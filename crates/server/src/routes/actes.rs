use crate::{
    db::models::{NewActe, NewActeParticipant},
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
use localpki_core::crypto::verifying_key_to_x25519_public;
use messaging_crypto::keys::ecies_encrypt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct CreateActeRequest {
    pub titre: String,
    /// SNs of the parties involved (buyer, seller, etc.) — notaire is added automatically.
    pub parties: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ActeResponse {
    pub uuid: String,
    pub titre: String,
    pub notaire_sn: String,
    pub parties: Vec<String>,
    pub created_at: i64,
}

struct ParticipantEntry {
    sn: String,
    c_acte_key: String,
}

/// Returns all actes where the authenticated user is a participant.
pub async fn list_actes(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ActeResponse>>, AppError> {
    let actes = registry::list_actes_for_participant(&state.db, caller_sn).await?;

    let mut responses = Vec::with_capacity(actes.len());
    for acte in actes {
        let parties = registry::list_participant_sns(&state.db, acte.uuid.clone()).await?;
        responses.push(ActeResponse {
            uuid: acte.uuid,
            titre: acte.titre,
            notaire_sn: acte.notaire_sn,
            parties,
            created_at: acte.created_at,
        });
    }
    Ok(Json(responses))
}

/// The only route that calls HsmSimulator::derive_k_acte().
/// Generates K_acte, encrypts it for each participant + HSM archive, stores in DB.
pub async fn create_acte(
    AuthenticatedSn(notaire_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateActeRequest>,
) -> Result<(StatusCode, Json<ActeResponse>), AppError> {
    // Only a notaire may open a dossier — the role is anchored in the EN registry.
    let caller = registry::lookup_identity(&state.db, notaire_sn.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if caller.role != crate::routes::enrollment::ROLE_NOTAIRE {
        return Err(AppError::Forbidden(
            "only a notaire may create an acte".into(),
        ));
    }

    // Deduplicate: notaire is always a participant too.
    let mut all_sns: Vec<String> = req.parties.clone();
    if !all_sns.contains(&notaire_sn) {
        all_sns.push(notaire_sn.clone());
    }

    // Fetch all public keys upfront (before touching the HSM).
    let mut participant_pks: Vec<(String, ed25519_dalek::VerifyingKey)> = Vec::new();
    for sn in &all_sns {
        let pk_b64 = registry::get_public_key(&state.db, sn.clone())
            .await?
            .ok_or_else(|| AppError::NotFound(format!("party '{}' not found", sn)))?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(
            &crate::utils::decode_b64(&pk_b64, "participant pk")?,
        )
        .map_err(|_| AppError::Database(format!("invalid Ed25519 key for '{sn}'")))?;
        participant_pks.push((sn.clone(), pk));
    }

    let acte_uuid = uuid::Uuid::new_v4();
    let uuid_str = acte_uuid.to_string();

    let (k_acte, hsm_x25519_pk) = {
        let hsm = state
            .hsm
            .lock()
            .map_err(|_| AppError::Database("HSM lock poisoned".into()))?;
        (Zeroizing::new(hsm.derive_k_acte(&acte_uuid)), hsm.x25519_public_key())
    };

    // Encrypt K_acte || acte_uuid for the HSM archive (used to re-derive K_acte
    // when adding a participant later). The trailing UUID binds the ciphertext to
    // a specific acte — see ARCHITECTURE.md §4.4 and `HsmSimulator::decrypt_archive`.
    let mut archive_plaintext = [0u8; 48];
    archive_plaintext[..32].copy_from_slice(k_acte.as_ref());
    archive_plaintext[32..].copy_from_slice(acte_uuid.as_bytes());
    let archive_ct = ecies_encrypt(&hsm_x25519_pk, &archive_plaintext).map_err(AppError::Crypto)?;
    let archive_json = serde_json::to_string(&archive_ct)
        .map_err(|e| AppError::Database(format!("serialization error: {e}")))?;

    // Encrypt K_acte for each participant via their Ed25519→X25519 public key.
    let mut participants: Vec<ParticipantEntry> = Vec::with_capacity(participant_pks.len());
    for (sn, ed_pk) in &participant_pks {
        let x25519_pk = verifying_key_to_x25519_public(ed_pk);
        let ct = ecies_encrypt(&x25519_pk, k_acte.as_ref()).map_err(AppError::Crypto)?;
        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AppError::Database(format!("serialization error: {e}")))?;
        participants.push(ParticipantEntry { sn: sn.clone(), c_acte_key: ct_json });
    }

    let now = crate::utils::unix_now()?;
    let titre = req.titre.clone();
    let notaire_sn_db = notaire_sn.clone();
    let uuid_str_db = uuid_str.clone();

    crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::{acte_participants, actes};

        diesel::insert_into(actes::table)
            .values(NewActe {
                uuid: &uuid_str_db,
                titre: &titre,
                notaire_sn: &notaire_sn_db,
                created_at: now,
                closed_at: None,
                c_acte_archive: &archive_json,
            })
            .execute(conn)?;

        for p in &participants {
            diesel::insert_into(acte_participants::table)
                .values(NewActeParticipant {
                    acte_uuid: &uuid_str_db,
                    participant_sn: &p.sn,
                    c_acte_key: &p.c_acte_key,
                    added_at: now,
                    added_by_sn: &notaire_sn_db,
                    history_from: None,
                })
                .execute(conn)?;
        }

        Ok(())
    })
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ActeResponse {
            uuid: uuid_str,
            titre: req.titre,
            notaire_sn,
            parties: all_sns,
            created_at: now,
        }),
    ))
}

pub async fn get_acte(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ActeResponse>, AppError> {
    // Only participants may read an acte's metadata (titre, parties…). The party
    // list of a notarial dossier is itself confidential — mirror the membership
    // check the sibling routes (/keys, /messages, /merkle) already enforce.
    registry::get_participant_key(&state.db, id.clone(), caller_sn)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let acte = registry::get_acte(&state.db, id.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("acte '{}' not found", id)))?;

    let parties = registry::list_participant_sns(&state.db, id).await?;

    Ok(Json(ActeResponse {
        uuid: acte.uuid,
        titre: acte.titre,
        notaire_sn: acte.notaire_sn,
        parties,
        created_at: acte.created_at,
    }))
}

/// Returns the caller's encrypted copy of K_acte (c_acte_key).
/// The client decrypts it locally with their private key to obtain K_acte.
pub async fn get_acte_key(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let c_acte_key =
        registry::get_participant_key(&state.db, id.clone(), caller_sn.clone())
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("no key for '{}' in acte '{}'", caller_sn, id))
            })?;

    Ok(Json(serde_json::json!({ "c_acte_key": c_acte_key })))
}
