use crate::{
    db::models::{NewMerkleEntry, NewMessage},
    en::registry,
    error::AppError,
    middleware::AuthenticatedSn,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use diesel::prelude::*;
use messaging_crypto::merkle::{MerkleLog, leaf_hash};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// AES-256-GCM(K_send_sender, plaintext). base64url.
    pub c_message: String,
    /// 96-bit AES-GCM nonce. base64url.
    pub nonce: String,
    /// Ed25519(sk_sender, SHA256(plaintext || acte_uuid || timestamp || SN)). base64url.
    /// Stored as-is — server does not verify (content is encrypted).
    pub signature: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: String,
    pub acte_uuid: String,
    pub sender_sn: String,
    pub c_message: String,
    pub nonce: String,
    pub signature: String,
    pub seq: i64,
    pub sent_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListMessagesQuery {
    /// Returns only messages with seq > after_seq (for incremental polling).
    pub after_seq: Option<i64>,
}

pub async fn send_message(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    registry::get_participant_key(&state.db, acte_id.clone(), caller_sn.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;

    let acte_uuid = uuid::Uuid::parse_str(&acte_id)
        .map_err(|_| AppError::BadRequest("invalid acte UUID".into()))?;

    let sig_bytes: [u8; 64] = crate::utils::decode_b64(&req.signature, "signature")?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = crate::utils::unix_now()?;

    // Move request fields into the closure; keep clones for the response.
    let c_message = req.c_message;
    let nonce = req.nonce;
    let sig_b64 = req.signature;
    let timestamp = req.timestamp;

    let msg_id_resp = msg_id.clone();
    let c_message_resp = c_message.clone();
    let nonce_resp = nonce.clone();
    let sig_resp = sig_b64.clone();
    let caller_resp = caller_sn.clone();
    let acte_id_resp = acte_id.clone();

    // Atomic: SELECT MAX(seq) + INSERT message + INSERT merkle_log in one transaction.
    let seq = crate::db::run_db(&state.db, move |conn| {
        conn.transaction(|conn| {
            use crate::db::schema::{merkle_log, messages};
            use diesel::dsl::max;

            let next_seq: i64 = messages::table
                .filter(messages::acte_uuid.eq(&acte_id))
                .select(max(messages::seq))
                .first::<Option<i64>>(conn)?
                .unwrap_or(-1) + 1;

            let leaf = leaf_hash(&signature, &acte_uuid, timestamp, next_seq as u64);

            diesel::insert_into(messages::table)
                .values(NewMessage {
                    id: &msg_id,
                    acte_uuid: &acte_id,
                    sender_sn: &caller_sn,
                    c_message: &c_message,
                    nonce: &nonce,
                    signature: &sig_b64,
                    seq: next_seq,
                    sent_at: now,
                })
                .execute(conn)?;

            diesel::insert_into(merkle_log::table)
                .values(NewMerkleEntry {
                    acte_uuid: &acte_id,
                    message_id: &msg_id,
                    leaf_hash: &hex::encode(leaf),
                    parent_hash: None,
                    en_signature: None,
                    logged_at: now,
                })
                .execute(conn)?;

            Ok(next_seq)
        })
    })
    .await?;

    // Notify WebSocket subscribers for this acte (fire-and-forget).
    if let Ok(channels) = state.ws_channels.lock() {
        if let Some(tx) = channels.get(&acte_id_resp) {
            let _ = tx.send(serde_json::json!({
                "event": "new_message",
                "message_id": msg_id_resp,
                "acte_uuid": acte_id_resp,
                "seq": seq,
            }).to_string());
        }
    }

    Ok(Json(MessageResponse {
        id: msg_id_resp,
        acte_uuid: acte_id_resp,
        sender_sn: caller_resp,
        c_message: c_message_resp,
        nonce: nonce_resp,
        signature: sig_resp,
        seq,
        sent_at: now,
    }))
}

/// Returns encrypted messages; clients decrypt locally with their K_acte.
pub async fn list_messages(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Query(params): Query<ListMessagesQuery>,
) -> Result<Json<Vec<MessageResponse>>, AppError> {
    registry::get_participant_key(&state.db, acte_id.clone(), caller_sn)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let after_seq = params.after_seq.unwrap_or(-1);

    let rows = crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::messages::dsl::*;
        messages
            .filter(acte_uuid.eq(&acte_id))
            .filter(seq.gt(after_seq))
            .order(seq.asc())
            .load::<crate::db::models::Message>(conn)
    })
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|m| MessageResponse {
                id: m.id,
                acte_uuid: m.acte_uuid,
                sender_sn: m.sender_sn,
                c_message: m.c_message,
                nonce: m.nonce,
                signature: m.signature,
                seq: m.seq,
                sent_at: m.sent_at,
            })
            .collect(),
    ))
}

pub async fn get_merkle_root(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    registry::get_participant_key(&state.db, acte_id.clone(), caller_sn)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let leaves_hex = crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::merkle_log::dsl::*;
        merkle_log
            .filter(acte_uuid.eq(&acte_id))
            .order(id.asc())
            .select(leaf_hash)
            .load::<String>(conn)
    })
    .await?;

    let leaves: Vec<[u8; 32]> = leaves_hex
        .iter()
        .map(|h| -> Result<[u8; 32], AppError> {
            hex::decode(h)
                .map_err(|_| AppError::Database("malformed leaf hash in merkle_log".into()))?
                .try_into()
                .map_err(|_| AppError::Database("leaf hash must be 32 bytes".into()))
        })
        .collect::<Result<_, _>>()?;

    let count = leaves.len();
    let root = MerkleLog::from_leaf_hashes(leaves)
        .root()
        .map(|r| hex::encode(r));

    Ok(Json(serde_json::json!({
        "root": root,
        "leaves_count": count,
        "en_signature": null,
    })))
}
