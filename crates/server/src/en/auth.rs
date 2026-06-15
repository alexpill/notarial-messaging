use crate::{db::models::Identity, en::registry, error::AppError, state::AppState};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use localpki_core::{
    authentication::{AuthRequest, AuthResponse, EnDatabase, respond_to_auth_request},
    cert::{RegistrationEntry, SerialNumber, SignatureId},
};
use std::sync::Arc;

pub async fn handle_auth_request(
    state: &Arc<AppState>,
    request: &AuthRequest,
    en_signing_key: &ed25519_dalek::SigningKey,
) -> Result<AuthResponse, AppError> {
    let sn_hex = hex::encode(request.serial_number.0);
    let identity = registry::lookup_identity(&state.db, sn_hex)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found or revoked".into()))?;

    let entry = identity_to_registration_entry(&identity)?;
    Ok(respond_to_auth_request(request, &SingleEntryDb(entry), en_signing_key))
}

/// Adapts a single fetched identity for the synchronous EnDatabase trait.
struct SingleEntryDb(RegistrationEntry);

impl EnDatabase for SingleEntryDb {
    fn lookup(&self, sn: &SerialNumber) -> Option<RegistrationEntry> {
        (self.0.serial_number == *sn).then(|| self.0.clone())
    }
}

fn identity_to_registration_entry(identity: &Identity) -> Result<RegistrationEntry, AppError> {
    let sn_bytes: [u8; 16] = hex::decode(&identity.sn)
        .map_err(|_| AppError::Database("malformed SN in registry".into()))?
        .try_into()
        .map_err(|_| AppError::Database("SN must be 16 bytes".into()))?;

    let si_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&identity.si)
        .map_err(|_| AppError::Database("malformed SI in registry".into()))?
        .try_into()
        .map_err(|_| AppError::Database("SI must be 64 bytes".into()))?;

    let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&identity.pk)
        .map_err(|_| AppError::Database("malformed pk in registry".into()))?
        .try_into()
        .map_err(|_| AppError::Database("pk must be 32 bytes".into()))?;

    Ok(RegistrationEntry {
        serial_number: SerialNumber(sn_bytes),
        signature_id: SignatureId(ed25519_dalek::Signature::from_bytes(&si_bytes)),
        public_key: ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| AppError::Database("invalid Ed25519 key in registry".into()))?,
        lra_id: identity.lra_id.clone(),
        registered_at: identity.registered_at,
        revoked_at: identity.revoked_at,
    })
}
