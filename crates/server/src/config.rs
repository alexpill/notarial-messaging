use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub frontend_origin: String,
    /// Bootstrap credential that lets a self-generated identity claim the
    /// `notaire` role at enrollment (POST /enroll/notaire). The private key
    /// never transits — only this token does. It is the EN's authority to
    /// designate a notaire (paper §2.1: "the LRA is registered by some EN").
    ///
    /// Dev: fixed via `NOTAIRE_ENROLLMENT_TOKEN` in `.env`, so the frontend can
    /// display it and a reviewer becomes notaire reliably. Prod: leave it unset
    /// and a random per-boot token is generated — printed once in the startup
    /// logs as the operator secret. Reusable on purpose: it can mint several
    /// notaires.
    pub notaire_enrollment_token: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://./notarial.db".to_string()),
            server_host: std::env::var("SERVER_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| AppError::Config("SERVER_PORT: invalid port number".to_string()))?,
            frontend_origin: std::env::var("FRONTEND_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            notaire_enrollment_token: std::env::var("NOTAIRE_ENROLLMENT_TOKEN")
                .unwrap_or_else(|_| random_token()),
        })
    }
}

/// 32-byte CSPRNG token, hex-encoded. Used when no fixed token is provided.
fn random_token() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}
