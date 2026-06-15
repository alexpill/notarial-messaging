use crate::error::AppError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub fn unix_now() -> Result<i64, AppError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| AppError::BadRequest("system clock error".into()))
}

pub fn decode_b64<const N: usize>(s: &str, label: &str) -> Result<[u8; N], AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AppError::BadRequest(format!("{label}: invalid base64url")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{label}: expected {N} bytes")))
}
