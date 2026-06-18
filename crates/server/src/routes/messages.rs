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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::prelude::*;
use localpki_core::cert::SerialNumber;
use ed25519_dalek::Signer;
use messaging_crypto::{
    merkle::{MerkleLog, leaf_hash, signed_root_payload},
    messages::verify_message_signature,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// AES-256-GCM(K_send_sender, plaintext). base64url.
    pub c_message: String,
    /// 96-bit AES-GCM nonce. base64url.
    pub nonce: String,
    /// Ed25519(sk_sender, SHA256("localpki-msg-v1\0" || c_message || nonce || acte_uuid || timestamp || SN)). base64url.
    /// Verified server-side against pk_sender before insert.
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

    // Bound clock drift on the client-supplied timestamp. Without this, a
    // malicious client could antedate/postdate its own signed messages within
    // arbitrary windows (the signature/AAD would still verify). 5 minutes is
    // generous enough to tolerate normal NTP drift while keeping the audit
    // window narrow.
    const MAX_TIMESTAMP_DRIFT_SECS: i64 = 300;
    let server_now = crate::utils::unix_now()?;
    if (req.timestamp - server_now).abs() > MAX_TIMESTAMP_DRIFT_SECS {
        return Err(AppError::BadRequest(format!(
            "timestamp drift > {MAX_TIMESTAMP_DRIFT_SECS}s vs server clock"
        )));
    }

    let sig_bytes: [u8; 64] = crate::utils::decode_b64(&req.signature, "signature")?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let nonce_bytes: [u8; 12] = crate::utils::decode_b64(&req.nonce, "nonce")?;
    let ciphertext_bytes = URL_SAFE_NO_PAD
        .decode(&req.c_message)
        .map_err(|_| AppError::BadRequest("c_message: invalid base64url".into()))?;

    // Verify SIG_sender with pk_sender (extracted from the LocalPKI registry).
    // The signature is over the ciphertext, so the server can reject forgeries without
    // ever reading the plaintext. See ARCHITECTURE.md §5.3.
    let sender_sn_bytes: [u8; 16] = hex::decode(&caller_sn)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AppError::BadRequest("sender SN: invalid hex".into()))?;
    let sender_sn = SerialNumber(sender_sn_bytes);

    let pk_b64 = registry::get_public_key(&state.db, caller_sn.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;
    let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&pk_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AppError::Database("malformed pk in registry".into()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| AppError::Database("invalid Ed25519 pk in registry".into()))?;

    verify_message_signature(
        &verifying_key,
        &ciphertext_bytes,
        &nonce_bytes,
        &acte_uuid,
        &sender_sn,
        req.timestamp,
        &signature,
    )?;

    let msg_id = uuid::Uuid::new_v4().to_string();
    let now = server_now;

    // Clone the EN signing key out of the mutex so the DB closure can sign without
    // holding the global lock across the transaction.
    let en_sk = state
        .en_signing_key
        .lock()
        .map_err(|_| AppError::Database("EN signing key mutex poisoned".into()))?
        .clone();

    // Move request fields into the closure; keep clones for the response.
    let client_timestamp = req.timestamp;
    let c_message = req.c_message;
    let nonce = req.nonce;
    let sig_b64 = req.signature;

    let msg_id_resp = msg_id.clone();
    let c_message_resp = c_message.clone();
    let nonce_resp = nonce.clone();
    let sig_resp = sig_b64.clone();
    let caller_resp = caller_sn.clone();
    let acte_id_resp = acte_id.clone();

    // Atomic: SELECT MAX(seq) + INSERT message + INSERT merkle_log in one transaction.
    // The new merkle_log row also carries the post-insert Merkle root and the EN
    // signature over that root — turning the append-only log into a proper
    // transparency log auditable end-to-end (cf. ARCHITECTURE.md §6).
    let seq = crate::db::run_db(&state.db, move |conn| {
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            use crate::db::schema::{merkle_log, messages};
            use diesel::dsl::max;

            let next_seq: i64 = messages::table
                .filter(messages::acte_uuid.eq(&acte_id))
                .select(max(messages::seq))
                .first::<Option<i64>>(conn)?
                .unwrap_or(-1) + 1;

            // Merkle leaf binds to the server's `now`, not the client-supplied timestamp:
            // a malicious client could otherwise backdate/forward-date its position in the
            // transparency log. Client `req.timestamp` remains covered by the signature/AAD
            // and is persisted as `sent_at`; server `now` is persisted in `merkle_log.logged_at`
            // for internal audit (not currently exposed via the API).
            let leaf = leaf_hash(&signature, &acte_uuid, now, next_seq as u64);

            // Rebuild the log from prior leaves + this one to compute the new root,
            // then sign it with the EN key. The signature in this row attests:
            //   "the EN saw a log whose root was R after appending message msg_id."
            let prior_leaves_hex: Vec<String> = merkle_log::table
                .filter(merkle_log::acte_uuid.eq(&acte_id))
                .order(merkle_log::id.asc())
                .select(merkle_log::leaf_hash)
                .load::<String>(conn)?;

            let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(prior_leaves_hex.len() + 1);
            for h in prior_leaves_hex {
                let bytes = hex::decode(&h).map_err(|_| {
                    diesel::result::Error::DeserializationError(
                        "malformed leaf hash in merkle_log".into(),
                    )
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    diesel::result::Error::DeserializationError(
                        "leaf hash must be 32 bytes".into(),
                    )
                })?;
                leaves.push(arr);
            }
            leaves.push(leaf);

            let log = MerkleLog::from_leaf_hashes(leaves);
            let root = log.root().ok_or_else(|| {
                diesel::result::Error::DeserializationError("empty merkle log after append".into())
            })?;
            // Sign tag || root || logged_at (le) so the EN signature binds both
            // the tree state and the moment it was attested. Matches
            // ARCHITECTURE.md §6.1 (signed_root = Sign(sk_EN, "localpki-merkle-v1\0" || root || logged_at)).
            let en_sig = en_sk.sign(&signed_root_payload(&root, now));

            // sent_at stores the client-supplied timestamp so decryption AAD is
            // consistent. The Merkle leaf uses server `now` separately for ordering integrity.
            diesel::insert_into(messages::table)
                .values(NewMessage {
                    id: &msg_id,
                    acte_uuid: &acte_id,
                    sender_sn: &caller_sn,
                    c_message: &c_message,
                    nonce: &nonce,
                    signature: &sig_b64,
                    seq: next_seq,
                    sent_at: client_timestamp,
                })
                .execute(conn)?;

            let root_hex = hex::encode(root);
            let en_sig_hex = hex::encode(en_sig.to_bytes());

            diesel::insert_into(merkle_log::table)
                .values(NewMerkleEntry {
                    acte_uuid: &acte_id,
                    message_id: &msg_id,
                    leaf_hash: &hex::encode(leaf),
                    parent_hash: Some(&root_hex),
                    en_signature: Some(&en_sig_hex),
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
        sent_at: client_timestamp,
    }))
}

/// Returns encrypted messages; clients decrypt locally with their K_acte.
pub async fn list_messages(
    AuthenticatedSn(caller_sn): AuthenticatedSn,
    State(state): State<Arc<AppState>>,
    Path(acte_id): Path<String>,
    Query(params): Query<ListMessagesQuery>,
) -> Result<Json<Vec<MessageResponse>>, AppError> {
    let participant = registry::get_participant_entry(&state.db, acte_id.clone(), caller_sn)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let after_seq = params.after_seq.unwrap_or(-1);
    let history_from = participant.history_from;

    let rows = crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::messages::dsl::*;
        let base = messages
            .filter(acte_uuid.eq(&acte_id))
            .filter(seq.gt(after_seq));

        if let Some(ts) = history_from {
            base.filter(sent_at.ge(ts))
                .order(seq.asc())
                .load::<crate::db::models::Message>(conn)
        } else {
            base.order(seq.asc())
                .load::<crate::db::models::Message>(conn)
        }
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

    let rows = crate::db::run_db(&state.db, move |conn| {
        use crate::db::schema::merkle_log::dsl::*;
        merkle_log
            .filter(acte_uuid.eq(&acte_id))
            .order(id.asc())
            .select((leaf_hash, parent_hash, en_signature, logged_at))
            .load::<(String, Option<String>, Option<String>, i64)>(conn)
    })
    .await?;

    let leaves: Vec<[u8; 32]> = rows
        .iter()
        .map(|(h, _, _, _)| -> Result<[u8; 32], AppError> {
            hex::decode(h)
                .map_err(|_| AppError::Database("malformed leaf hash in merkle_log".into()))?
                .try_into()
                .map_err(|_| AppError::Database("leaf hash must be 32 bytes".into()))
        })
        .collect::<Result<_, _>>()?;

    let count = leaves.len();
    let root = MerkleLog::from_leaf_hashes(leaves)
        .root()
        .map(hex::encode);

    // The EN signature on the most recent row attests to the current root at
    // its logged_at timestamp. Older rows keep their own (root, signature, ts)
    // tuple so any historical state is auditable end-to-end.
    let latest = rows.last();
    let latest_en_signature = latest.and_then(|(_, _, sig, _)| sig.clone());
    let latest_signed_root = latest.and_then(|(_, root_hex, _, _)| root_hex.clone());
    let latest_logged_at = latest.map(|(_, _, _, ts)| *ts);

    Ok(Json(serde_json::json!({
        "root": root,
        "leaves_count": count,
        "en_signature": latest_en_signature,
        "signed_root": latest_signed_root,
        "signed_at": latest_logged_at,
    })))
}
