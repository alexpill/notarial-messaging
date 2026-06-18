use crate::{
    db::models::NewActeParticipant,
    en::registry,
    error::AppError,
    middleware::AuthenticatedSn,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use diesel::prelude::*;
use ed25519_dalek::Verifier;
use localpki_core::crypto::verifying_key_to_x25519_public;
use messaging_crypto::keys::{EciesCiphertext, ecies_encrypt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct AddParticipantRequest {
    /// SN of the new participant (must be registered in the EN registry).
    pub participant_sn: String,
    /// Whether to grant access to the existing message history.
    /// false = participant can only see messages from this point forward.
    pub grant_history: bool,
    /// Notaire signature over SHA256(PARTICIPANT_DOMAIN_TAG || acte_uuid || participant_sn || grant_history). base64url.
    pub notaire_signature: String,
}

/// Domain-separation tag for the notaire's add-participant signature. Keeps it
/// from being reusable in another user-key context. Mirror in demo-cli
/// (`make_add_participant_signature`) and the frontend acte page.
const PARTICIPANT_DOMAIN_TAG: &[u8] = b"localpki-participant-v1\0";

#[derive(Debug, Serialize)]
pub struct AddParticipantResponse {
    pub acte_uuid: String,
    pub participant_sn: String,
    pub added_at: i64,
}

/// Adds a participant to an existing acte.
/// Flow: verify caller is the notaire → HSM decrypts C_acte_archive →
/// re-encrypts K_acte for the new participant → INSERT acte_participants.
///
/// Note: if grant_history = false, history_from is set to now() but K_acte is
/// technically decryptable from the start. This is a documented UI-level limitation.
pub async fn add_participant(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Json(req): Json<AddParticipantRequest>,
) -> Result<(StatusCode, Json<AddParticipantResponse>), AppError> {
    let acte = registry::get_acte(&state.db, acte_id.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("acte '{}' not found", acte_id)))?;

    if caller_sn != acte.notaire_sn {
        return Err(AppError::Unauthorized);
    }

    // Verify the notaire's signature over SHA256(tag || acte_uuid || participant_sn || grant_history).
    let notaire_identity = registry::lookup_identity(&state.db, acte.notaire_sn.clone())
        .await?
        .ok_or_else(|| AppError::Database("notaire identity not found".into()))?;

    let notaire_pk = ed25519_dalek::VerifyingKey::from_bytes(
        &crate::utils::decode_b64(&notaire_identity.pk, "notaire pk")?,
    )
    .map_err(|_| AppError::Database("invalid notaire Ed25519 key".into()))?;

    let sig = ed25519_dalek::Signature::from_bytes(
        &crate::utils::decode_b64(&req.notaire_signature, "notaire_signature")?,
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(PARTICIPANT_DOMAIN_TAG);
    payload.extend_from_slice(acte_id.as_bytes());
    payload.extend_from_slice(req.participant_sn.as_bytes());
    payload.push(req.grant_history as u8);

    notaire_pk
        .verify(&Sha256::digest(&payload), &sig)
        .map_err(|_| AppError::BadRequest("notaire signature verification failed".into()))?;

    // Decrypt K_acte from the HSM archive. The archive ciphertext binds K_acte
    // to the acte UUID (see HsmSimulator::decrypt_archive); we pass the UUID so
    // a swapped archive row would fail at the UUID check.
    let acte_uuid = uuid::Uuid::parse_str(&acte_id)
        .map_err(|_| AppError::BadRequest("invalid acte UUID".into()))?;
    let archive_ct: EciesCiphertext = serde_json::from_str(&acte.c_acte_archive)
        .map_err(|_| AppError::Database("malformed c_acte_archive".into()))?;
    let k_acte = Zeroizing::new(
        state
            .hsm
            .lock()
            .map_err(|_| AppError::Database("HSM lock poisoned".into()))?
            .decrypt_archive(&archive_ct, &acte_uuid)
            .map_err(AppError::Crypto)?,
    );

    // Encrypt K_acte for the new participant.
    let participant_pk_b64 = registry::get_public_key(&state.db, req.participant_sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("participant '{}' not found", req.participant_sn)))?;
    let participant_ed_pk = ed25519_dalek::VerifyingKey::from_bytes(
        &crate::utils::decode_b64(&participant_pk_b64, "participant pk")?,
    )
    .map_err(|_| AppError::Database(format!("invalid Ed25519 key for '{}'", req.participant_sn)))?;

    let x25519_pk = verifying_key_to_x25519_public(&participant_ed_pk);
    let ct = ecies_encrypt(&x25519_pk, k_acte.as_ref()).map_err(AppError::Crypto)?;
    let c_acte_key = serde_json::to_string(&ct)
        .map_err(|e| AppError::Database(format!("serialization error: {e}")))?;

    let now = crate::utils::unix_now()?;
    let history_from = if req.grant_history { None } else { Some(now) };
    let participant_sn = req.participant_sn.clone();
    let acte_id_db = acte_id.clone();
    let notaire_sn = acte.notaire_sn.clone();

    crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::acte_participants;
        diesel::insert_into(acte_participants::table)
            .values(NewActeParticipant {
                acte_uuid: &acte_id_db,
                participant_sn: &participant_sn,
                c_acte_key: &c_acte_key,
                added_at: now,
                added_by_sn: &notaire_sn,
                history_from,
            })
            .execute(conn)?;
        Ok(())
    })
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(AddParticipantResponse {
            acte_uuid: acte_id,
            participant_sn: req.participant_sn,
            added_at: now,
        }),
    ))
}
