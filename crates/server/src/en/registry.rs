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
    let sn       = entry.sn.to_owned();
    let si       = entry.si.to_owned();
    let pk       = entry.pk.to_owned();
    let tbs_cert = entry.tbs_cert.to_owned();
    let lra_id   = entry.lra_id.to_owned();
    let registered_at = entry.registered_at;

    run_db(pool, move |conn| {
        use crate::db::schema::identities;
        diesel::insert_into(identities::table)
            .values(NewIdentity {
                sn: &sn,
                si: &si,
                pk: &pk,
                tbs_cert: &tbs_cert,
                lra_id: &lra_id,
                registered_at,
                revoked_at: None,
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

pub async fn insert_session(
    pool: &DbPool,
    token_val: String,
    sn_val: String,
    created: i64,
    expires: i64,
) -> Result<(), AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::sessions;
        diesel::insert_into(sessions::table)
            .values(crate::db::models::NewSession {
                token: &token_val,
                sn: &sn_val,
                created_at: created,
                expires_at: expires,
            })
            .execute(conn)?;
        Ok(())
    })
    .await
}

pub async fn lookup_session(
    pool: &DbPool,
    token_val: String,
) -> Result<Option<Session>, AppError> {
    run_db(pool, move |conn| {
        use crate::db::schema::sessions::dsl::*;
        sessions
            .filter(token.eq(&token_val))
            .first::<Session>(conn)
            .optional()
    })
    .await
}

// ─── actes ───────────────────────────────────────────────────────────────────

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
