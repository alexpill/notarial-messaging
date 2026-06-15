use crate::{config::AppConfig, db::DbPool, error::AppError, hsm::HsmSimulator};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct AppState {
    pub db: DbPool,
    /// Mutex because derive_k_acte is rare and fast — no need for RwLock.
    pub hsm: Mutex<HsmSimulator>,
    pub config: AppConfig,
    /// Verifies AuthResponse signatures from the EN.
    pub en_verifying_key: ed25519_dalek::VerifyingKey,
    /// Signs AuthResponse and Merkle roots; Mutex for thread-safe Send.
    pub en_signing_key: Mutex<ed25519_dalek::SigningKey>,
    /// Per-acte broadcast channels — send_message notifies, ws_handler subscribes.
    pub ws_channels: Mutex<HashMap<String, tokio::sync::broadcast::Sender<String>>>,
}

impl AppState {
    pub fn new(db: DbPool, hsm: HsmSimulator, config: AppConfig) -> Result<Self, AppError> {
        let (signing_key, verifying_key) = load_en_keys(&config)?;
        Ok(Self {
            db,
            hsm: Mutex::new(hsm),
            config,
            en_verifying_key: verifying_key,
            en_signing_key: Mutex::new(signing_key),
            ws_channels: Mutex::new(HashMap::new()),
        })
    }
}

fn load_en_keys(
    _config: &AppConfig,
) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), AppError> {
    let hex = std::env::var("EN_SIGNING_KEY_HEX")
        .map_err(|_| AppError::Config("EN_SIGNING_KEY_HEX: missing".to_string()))?;

    let bytes = hex::decode(&hex)
        .map_err(|_| AppError::Config("EN_SIGNING_KEY_HEX: malformed hex".to_string()))?;

    if bytes.len() != 32 {
        return Err(AppError::Config("EN_SIGNING_KEY_HEX: must be exactly 32 bytes (64 hex chars)".to_string()));
    }

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        bytes.as_slice().try_into()
            .map_err(|_| AppError::Config("EN_SIGNING_KEY_HEX: must be exactly 32 bytes".to_string()))?,
    );
    let verifying_key = signing_key.verifying_key();

    Ok((signing_key, verifying_key))
}
