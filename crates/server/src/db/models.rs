use super::schema::{acte_participants, actes, identities, merkle_log, messages, sessions};
use diesel::prelude::*;
use serde::Serialize;

// ─── identities ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = identities)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Identity {
    pub sn: String,
    pub si: String,
    pub pk: String,
    /// Exact DER bytes (base64url) that were signed at enrollment. Frozen here
    /// so SI verification is independent of x509-cert encoder drift.
    pub tbs_der: String,
    /// Display label, kept separate from the cryptographic core.
    pub subject_id: String,
    pub lra_id: String,
    pub registered_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = identities)]
pub struct NewIdentity<'a> {
    pub sn: &'a str,
    pub si: &'a str,
    pub pk: &'a str,
    pub tbs_der: &'a str,
    pub subject_id: &'a str,
    pub lra_id: &'a str,
    pub registered_at: i64,
    pub revoked_at: Option<i64>,
}

// ─── actes ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = actes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Acte {
    pub uuid: String,
    pub titre: String,
    pub notaire_sn: String,
    pub created_at: i64,
    pub closed_at: Option<i64>,
    pub c_acte_archive: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = actes)]
pub struct NewActe<'a> {
    pub uuid: &'a str,
    pub titre: &'a str,
    pub notaire_sn: &'a str,
    pub created_at: i64,
    pub closed_at: Option<i64>,
    pub c_acte_archive: &'a str,
}

// ─── acte_participants ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = acte_participants)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ActeParticipant {
    pub acte_uuid: String,
    pub participant_sn: String,
    pub c_acte_key: String,
    pub added_at: i64,
    pub added_by_sn: String,
    pub history_from: Option<i64>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = acte_participants)]
pub struct NewActeParticipant<'a> {
    pub acte_uuid: &'a str,
    pub participant_sn: &'a str,
    pub c_acte_key: &'a str,
    pub added_at: i64,
    pub added_by_sn: &'a str,
    pub history_from: Option<i64>,
}

// ─── messages ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = messages)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Message {
    pub id: String,
    pub acte_uuid: String,
    pub sender_sn: String,
    pub c_message: String,
    pub nonce: String,
    pub signature: String,
    pub seq: i64,
    pub sent_at: i64,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = messages)]
pub struct NewMessage<'a> {
    pub id: &'a str,
    pub acte_uuid: &'a str,
    pub sender_sn: &'a str,
    pub c_message: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
    pub seq: i64,
    pub sent_at: i64,
}

// ─── sessions ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Session {
    pub token: String,
    pub sn: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = sessions)]
pub struct NewSession<'a> {
    pub token: &'a str,
    pub sn: &'a str,
    pub created_at: i64,
    pub expires_at: i64,
}

// ─── merkle_log ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = merkle_log)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct MerkleEntry {
    pub id: i64,
    pub acte_uuid: String,
    pub message_id: String,
    pub leaf_hash: String,
    /// Merkle root *after* inserting this leaf (hex 32 bytes). The column name
    /// is historical — see ARCHITECTURE.md §11.
    pub parent_hash: Option<String>,
    pub en_signature: Option<String>,
    pub logged_at: i64,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = merkle_log)]
pub struct NewMerkleEntry<'a> {
    pub acte_uuid: &'a str,
    pub message_id: &'a str,
    pub leaf_hash: &'a str,
    /// Stores the Merkle root post-append, not a parent leaf. See MerkleEntry.
    pub parent_hash: Option<&'a str>,
    pub en_signature: Option<&'a str>,
    pub logged_at: i64,
}
