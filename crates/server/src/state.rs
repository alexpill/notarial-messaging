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
    /// Single-use short-lived tickets for WebSocket upgrades. Browsers can't set
    /// custom headers on WS handshakes, so we used to accept the session token
    /// as a query string — which leaks into access logs. The ticket flow has
    /// the client trade its session token (via Bearer on POST /ws/ticket) for a
    /// random 30-second single-use ticket; the ticket may safely appear in the
    /// WS URL because it's worthless after the handshake.
    pub ws_tickets: Mutex<HashMap<String, WsTicket>>,
    /// Single-use login challenges for proof of possession. Maps an opaque
    /// challenge (base64url of 32 random bytes) to its expiry. POST /auth/challenge
    /// inserts; POST /auth/verify consumes it (remove) and checks the client's
    /// signature over `tag || SN || nonce` with the registry pk. Same in-memory,
    /// single-process model as `ws_tickets`.
    pub auth_challenges: Mutex<HashMap<String, i64>>,
}

#[derive(Debug, Clone)]
pub struct WsTicket {
    pub sn: String,
    pub expires_at: i64,
}

impl AppState {
    pub fn new(
        db: DbPool,
        hsm: HsmSimulator,
        config: AppConfig,
    ) -> Result<Self, AppError> {
        let (signing_key, verifying_key) = load_en_keys(&config)?;
        Ok(Self {
            db,
            hsm: Mutex::new(hsm),
            config,
            en_verifying_key: verifying_key,
            en_signing_key: Mutex::new(signing_key),
            ws_channels: Mutex::new(HashMap::new()),
            ws_tickets: Mutex::new(HashMap::new()),
            auth_challenges: Mutex::new(HashMap::new()),
        })
    }

    /// Builds a test AppState with random EN keys and a fixed test config.
    /// Use `init_pool_for_test()` to create the DB pool.
    pub fn new_for_test(db: DbPool, hsm: HsmSimulator) -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let config = AppConfig {
            database_url: String::new(),
            server_host: "127.0.0.1".to_string(),
            server_port: 3000,
            frontend_origin: "http://localhost:5173".to_string(),
            notaire_enrollment_token: "test-notaire-token".to_string(),
            allow_self_enroll: true,
        };
        Self {
            db,
            hsm: Mutex::new(hsm),
            config,
            en_verifying_key: verifying_key,
            en_signing_key: Mutex::new(signing_key),
            ws_channels: Mutex::new(HashMap::new()),
            ws_tickets: Mutex::new(HashMap::new()),
            auth_challenges: Mutex::new(HashMap::new()),
        }
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
