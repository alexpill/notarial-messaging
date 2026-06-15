use crate::{db::models::NewIdentity, en::registry, error::AppError, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Verifier;
use localpki_core::{cert::LocalPKICert, enrollment::verify_signature_id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// User's self-signed LocalPKI certificate (JSON-serialized).
    pub cert: serde_json::Value,
    /// LRA signature over SHA256(SN || SI || pk). base64url.
    pub lra_signature: String,
    /// SN of the LRA (must already be in the EN registry).
    pub lra_sn: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub serial_number: String,
    pub message: String,
}

pub async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> Result<(StatusCode, Json<EnrollResponse>), AppError> {
    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    verify_signature_id(&cert)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

    // The LRA's trustworthiness is established by its own presence in the EN registry.
    // No hardcoded LRA key — any enrolled and non-revoked identity can act as LRA.
    let lra = registry::lookup_identity(&state.db, req.lra_sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("LRA '{}' not found or revoked", req.lra_sn)))?;

    let pk_lra = ed25519_dalek::VerifyingKey::from_bytes(&decode_b64(&lra.pk, "LRA pk")?)
        .map_err(|_| AppError::BadRequest("LRA public key is not a valid Ed25519 key".into()))?;

    let lra_sig = ed25519_dalek::Signature::from_bytes(
        &decode_b64(&req.lra_signature, "lra_signature")?,
    );

    // Mirror the payload from prepare_lra_to_en_message: SHA256(SN || SI || pk).
    let mut payload = Vec::with_capacity(112);
    payload.extend_from_slice(&cert.tbs.serial_number.0);
    payload.extend_from_slice(&cert.signature_id.0.to_bytes());
    payload.extend_from_slice(cert.tbs.public_key.as_bytes());

    pk_lra
        .verify(&Sha256::digest(&payload), &lra_sig)
        .map_err(|_| AppError::BadRequest("LRA signature verification failed".into()))?;

    let sn_hex = hex::encode(cert.tbs.serial_number.0);
    let tbs_json = serde_json::to_string(&cert.tbs)
        .map_err(|e| AppError::BadRequest(format!("failed to serialize TBSCert: {e}")))?;

    registry::insert_identity(
        &state.db,
        NewIdentity {
            sn: &sn_hex,
            si: &URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes()),
            pk: &URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes()),
            tbs_cert: &tbs_json,
            lra_id: &req.lra_sn,
            registered_at: crate::utils::unix_now()?,
            revoked_at: None,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            serial_number: sn_hex,
            message: "enrolled successfully".to_string(),
        }),
    ))
}

pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(sn): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let identity = registry::lookup_identity(&state.db, sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("identity '{}' not found", sn)))?;

    Ok(Json(serde_json::json!({
        "sn": identity.sn,
        "pk": identity.pk,
        "tbs_cert": identity.tbs_cert,
        "registered_at": identity.registered_at,
    })))
}

fn decode_b64<const N: usize>(s: &str, label: &str) -> Result<[u8; N], AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AppError::BadRequest(format!("{label}: invalid base64url")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{label}: expected {N} bytes")))
}
