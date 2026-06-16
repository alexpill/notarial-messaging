use crate::{en, en::registry, error::AppError, state::AppState};
use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Verifier;
use localpki_core::{
    authentication::{AuthStatus, build_auth_request, verify_auth_response},
    cert::LocalPKICert,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AuthVerifyRequest {
    pub cert: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct AuthVerifyResponse {
    pub authenticated: bool,
    pub session_token: Option<String>,
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<Json<AuthVerifyResponse>, AppError> {
    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    // Verify SI against the EXACT DER bytes that were stored at enrollment —
    // not against a freshly re-serialized TBSCert. This keeps the auth path
    // independent of x509-cert encoder drift across library versions.
    let sn_hex = hex::encode(cert.tbs.serial_number.0);
    let stored = registry::lookup_identity(&state.db, sn_hex.clone())
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found or revoked".into()))?;

    let stored_pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&stored.pk)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AppError::Database("malformed pk in registry".into()))?;
    let stored_pk = ed25519_dalek::VerifyingKey::from_bytes(&stored_pk_bytes)
        .map_err(|_| AppError::Database("invalid Ed25519 pk in registry".into()))?;

    let tbs_der_stored = URL_SAFE_NO_PAD
        .decode(&stored.tbs_der)
        .map_err(|_| AppError::Database("malformed tbs_der in registry".into()))?;

    stored_pk
        .verify(&tbs_der_stored, &cert.signature_id.0)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

    // Defense in depth: also confirm the presented pk matches the registry's.
    // Otherwise the client could swap to a pk they control after enrollment.
    if cert.tbs.public_key.as_bytes() != &stored_pk_bytes {
        return Err(AppError::BadRequest(
            "presented public key does not match registry".into(),
        ));
    }

    // Reject expired or not-yet-valid certs at auth time — matches LocalPKI
    // Algorithm 2 (§3.3). The check is intentionally done before the EN
    // round-trip so an expired cert never reaches the registry lookup.
    cert.tbs
        .validity
        .check(crate::utils::unix_now()?)
        .map_err(|e| AppError::BadRequest(format!("certificate validity: {e}")))?;

    let auth_request = build_auth_request(&cert);

    // Clone before the await to avoid holding the Mutex across an await point.
    let signing_key = state
        .en_signing_key
        .lock()
        .map_err(|_| AppError::Database("en_signing_key lock poisoned".into()))?
        .clone();

    let response = en::auth::handle_auth_request(&state, &auth_request, &signing_key).await?;

    let status = verify_auth_response(&response, &state.en_verifying_key, &auth_request)
        .map_err(|_| AppError::BadRequest("EN signature verification failed".into()))?;

    if status != AuthStatus::Ok {
        return Ok(Json(AuthVerifyResponse {
            authenticated: false,
            session_token: None,
        }));
    }

    let token = uuid::Uuid::new_v4().to_string();
    let now = crate::utils::unix_now()?;

    registry::insert_session(&state.db, token.clone(), sn_hex, now, now + 86_400).await?;

    Ok(Json(AuthVerifyResponse {
        authenticated: true,
        session_token: Some(token),
    }))
}
