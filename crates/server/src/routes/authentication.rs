use crate::{en, en::registry, error::AppError, state::AppState};
use axum::{Json, extract::State};
use localpki_core::{
    authentication::{AuthStatus, build_auth_request, verify_auth_response},
    cert::LocalPKICert,
    enrollment::verify_signature_id,
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

    verify_signature_id(&cert)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

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
    let sn_hex = hex::encode(cert.tbs.serial_number.0);
    let now = crate::utils::unix_now()?;

    registry::insert_session(&state.db, token.clone(), sn_hex, now, now + 86_400).await?;

    Ok(Json(AuthVerifyResponse {
        authenticated: true,
        session_token: Some(token),
    }))
}
