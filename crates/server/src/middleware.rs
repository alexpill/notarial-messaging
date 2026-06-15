// Session token issued by POST /auth/verify after full LocalPKI verification.
// This is the only way to prove identity to the server — no SN accepted in request body.

use crate::{en::registry, error::AppError, state::AppState};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use std::sync::Arc;

/// Axum extractor that resolves a Bearer token to the authenticated SN.
pub struct AuthenticatedSn(pub String);

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedSn
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::<AppState>::from_ref(state);

        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?
            .to_owned();

        let session = registry::lookup_session(&state.db, token)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|_| AppError::Unauthorized)?;

        if session.expires_at < now {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthenticatedSn(session.sn))
    }
}
