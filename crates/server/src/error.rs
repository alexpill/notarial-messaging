use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("invalid LocalPKI certificate: {0}")]
    LocalPki(#[from] localpki_core::LocalPkiError),

    #[error("cryptographic error: {0}")]
    Crypto(#[from] messaging_crypto::CryptoError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),
}

impl From<diesel::result::Error> for AppError {
    fn from(e: diesel::result::Error) -> Self {
        use diesel::result::{DatabaseErrorKind, Error as DieselError};
        match e {
            DieselError::NotFound => AppError::NotFound("record not found".into()),
            // A unique-constraint violation is a 409, not a 500: duplicate SN at
            // enrollment, duplicate participant, or a byte-for-byte message replay
            // (the (acte_uuid, sender_sn, nonce) index — cf. ARCHITECTURE.md §8.5).
            DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                AppError::Conflict("resource already exists (duplicate key)".into())
            }
            _ => AppError::Database(e.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized          => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden(_)          => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound(_)           => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_)         => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Conflict(_)           => (StatusCode::CONFLICT, self.to_string()),
            AppError::LocalPki(_)
            | AppError::Crypto(_)           => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            _                               => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
