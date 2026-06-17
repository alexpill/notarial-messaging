use crate::{en::registry, error::AppError, state::AppState};
use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use localpki_core::{
    cert::LocalPKICert,
    revocation::{RevocationRequest, validate_revocation_request},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// The LocalPKI certificate to revoke (JSON-serialized LocalPKICert).
    pub cert: serde_json::Value,
    /// Ed25519(sk_user_or_LRA, SHA256("Revoke" || SN || SI)). base64url.
    pub revocation_signature: String,
    /// Optional: SN of the LRA that countersigned the revocation. When set,
    /// the LRA's public key (looked up in the registry) is also accepted as a
    /// valid signer — enabling Algorithm 4 of the LocalPKI paper for the case
    /// where a user has lost their key and the LRA acts on their behalf.
    #[serde(default)]
    pub lra_sn: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub serial_number: String,
    pub revoked_at: i64,
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> Result<(StatusCode, Json<RevokeResponse>), AppError> {
    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    let sig_bytes: [u8; 64] = crate::utils::decode_b64(&req.revocation_signature, "revocation_signature")?;
    let revocation_signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let sn_hex = hex::encode(cert.tbs.serial_number.0);

    // The cert must already be in the registry (and not already revoked).
    registry::lookup_identity(&state.db, sn_hex.clone())
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found or already revoked".into()))?;

    // Optional LRA countersignature path: resolve LRA's verifying key from registry.
    let lra_key = if let Some(lra_sn) = &req.lra_sn {
        let lra = registry::lookup_identity(&state.db, lra_sn.clone())
            .await?
            .ok_or_else(|| AppError::BadRequest("LRA not found or revoked".into()))?;
        let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&lra.pk)
            .map_err(|_| AppError::Database("malformed LRA pk in registry".into()))?
            .try_into()
            .map_err(|_| AppError::Database("LRA pk must be 32 bytes".into()))?;
        Some(
            ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|_| AppError::Database("invalid LRA Ed25519 pk".into()))?,
        )
    } else {
        None
    };

    let request = RevocationRequest {
        cert: cert.clone(),
        revocation_signature,
    };
    validate_revocation_request(&request, lra_key.as_ref())
        .map_err(|_| AppError::BadRequest("invalid revocation signature".into()))?;

    let revoked_at = crate::utils::unix_now()?;
    registry::revoke_identity(&state.db, sn_hex.clone(), revoked_at).await?;

    Ok((
        StatusCode::OK,
        Json(RevokeResponse {
            serial_number: sn_hex,
            revoked_at,
        }),
    ))
}
