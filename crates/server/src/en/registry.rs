// LocalPKI registry — CRUD on the `identities` table via Diesel.
// Diesel's DSL is type-checked at compile time: a typo in a column name is a compile error.

use crate::{
    db::{
        models::{Acte, Identity, NewIdentity, Session},
        run_db, DbPool,
    },
    error::AppError,
};
use diesel::prelude::*;

// ─── identities ──────────────────────────────────────────────────────────────

pub async fn insert_identity(pool: &DbPool, entry: NewIdentity<'_>) -> Result<(), AppError> {
    // Strings must be 'static inside spawn_blocking, so we own them here.
    let sn         = entry.sn.to_owned();
    let si         = entry.si.to_owned();
    let pk         = entry.pk.to_owned();
    let tbs_der    = entry.tbs_der.to_owned();
    let subject_id = entry.subject_id.to_owned();
    let lra_id     = entry.lra_id.to_owned();
    let role       = entry.role.to_owned();
    let registered_at = entry.registered_at;

    run_db(pool, move |conn| {
        use crate::db::schema::identities;
        diesel::insert_into(identities::table)
            .values(NewIdentity {
                sn: &sn,
                si: &si,
                pk: &pk,
                tbs_der: &tbs_der,
                subject_id: &subject_id,
                lra_id: &lra_id,
                registered_at,
                revoked_at: None,
                role: &role,
            })
            .execute(conn)?;
        Ok(())
    })
    .await
}

/// Returns None if the identity is unknown or revoked.
pub async fn lookup_identity(
    pool: &DbPool,
    sn_value: String,
) -> Result<Option<Identity>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::identities::dsl::*;
        identities
            .filter(sn.eq(&sn_value))
            .filter(revoked_at.is_null())
            .first::<Identity>(conn)
            .optional()
    })
    .await
}

pub async fn get_public_key(
    pool: &DbPool,
    sn_value: String,
) -> Result<Option<String>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::identities::dsl::*;
        identities
            .filter(sn.eq(&sn_value))
            .select(pk)
            .first::<String>(conn)
            .optional()
    })
    .await
}

/// Soft-delete: sets revoked_at, preserving the identity history.
pub async fn revoke_identity(
    pool: &DbPool,
    sn_value: String,
    revoked_at_ts: i64,
) -> Result<(), AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::identities::dsl::*;
        diesel::update(identities.filter(sn.eq(&sn_value)))
            .set(revoked_at.eq(Some(revoked_at_ts)))
            .execute(conn)?;
        Ok(())
    })
    .await
}

// ─── sessions ────────────────────────────────────────────────────────────────

/// Stores only the SHA-256 of `token_clear`, never the clear token. A DB leak
/// then doesn't yield directly-usable session tokens — same idea as storing
/// password hashes rather than passwords. The clear token is returned only
/// once, by /auth/verify, to the client that just authenticated.
pub async fn insert_session(
    pool: &DbPool,
    token_clear: String,
    sn_val: String,
    created: i64,
    expires: i64,
) -> Result<(), AppError> {
    let token_hash = crate::utils::hash_session_token(&token_clear);
    run_db(pool, move |conn| {
        use crate::db::schema::sessions;
        diesel::insert_into(sessions::table)
            .values(crate::db::models::NewSession {
                token: &token_hash,
                sn: &sn_val,
                created_at: created,
                expires_at: expires,
            })
            .execute(conn)?;
        Ok(())
    })
    .await
}

/// Accepts the clear token as presented by the caller, hashes it, and looks up
/// the matching session row by hash. Symmetric with `insert_session`.
pub async fn lookup_session(
    pool: &DbPool,
    token_clear: String,
) -> Result<Option<Session>, AppError> {
    let token_hash = crate::utils::hash_session_token(&token_clear);
    run_db(pool, move |conn| {
        use crate::db::schema::sessions::dsl::*;
        sessions
            .filter(token.eq(&token_hash))
            .first::<Session>(conn)
            .optional()
    })
    .await
}

// ─── actes ───────────────────────────────────────────────────────────────────

/// Returns all actes where `sn_val` is listed as a participant.
pub async fn list_actes_for_participant(
    pool: &DbPool,
    sn_val: String,
) -> Result<Vec<Acte>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::{acte_participants, actes};
        acte_participants::table
            .filter(acte_participants::participant_sn.eq(&sn_val))
            .inner_join(actes::table.on(actes::uuid.eq(acte_participants::acte_uuid)))
            .select(actes::all_columns)
            .order(actes::created_at.desc())
            .load::<Acte>(conn)
    })
    .await
}

pub async fn get_acte(pool: &DbPool, uuid_val: String) -> Result<Option<Acte>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::actes::dsl::*;
        actes
            .filter(uuid.eq(&uuid_val))
            .first::<Acte>(conn)
            .optional()
    })
    .await
}

pub async fn list_participant_sns(
    pool: &DbPool,
    acte_uuid_val: String,
) -> Result<Vec<String>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::acte_participants::dsl::*;
        acte_participants
            .filter(acte_uuid.eq(&acte_uuid_val))
            .select(participant_sn)
            .load::<String>(conn)
    })
    .await
}

pub async fn get_participant_key(
    pool: &DbPool,
    acte_uuid_val: String,
    sn_val: String,
) -> Result<Option<String>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::acte_participants::dsl::*;
        acte_participants
            .filter(acte_uuid.eq(&acte_uuid_val))
            .filter(participant_sn.eq(&sn_val))
            .select(c_acte_key)
            .first::<String>(conn)
            .optional()
    })
    .await
}

pub async fn get_participant_entry(
    pool: &DbPool,
    acte_uuid_val: String,
    sn_val: String,
) -> Result<Option<crate::db::models::ActeParticipant>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::acte_participants::dsl::*;
        acte_participants
            .filter(acte_uuid.eq(&acte_uuid_val))
            .filter(participant_sn.eq(&sn_val))
            .first::<crate::db::models::ActeParticipant>(conn)
            .optional()
    })
    .await
}
