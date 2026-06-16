// LocalPKI registry — CRUD on the `identities` table via Diesel.
// Diesel's DSL is type-checked at compile time: a typo in a column name is a compile error.

use crate::{
    db::{
        models::{Acte, Identity, NewIdentity, Session},
        run_db, DbPool,
    },
    error::AppError,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

/// Seeds a Root LRA in the DB at startup. Returns the keypair and its SN hex.
/// Each call inserts a fresh row with a new random SN — calling this multiple times
/// (e.g. on each restart) accumulates harmless LRA rows in the identities table.
/// The returned keypair is stored in AppState for the lifetime of the process.
pub async fn seed_root_lra(
    pool: &DbPool,
    en_url: &str,
) -> Result<(localpki_core::crypto::KeyPair, String), AppError> {
    let kp = localpki_core::crypto::KeyPair::generate()
        .map_err(|_| AppError::Config("root LRA key generation failed".into()))?;

    let sn_bytes: [u8; 16] = rand::random();
    let sn = localpki_core::cert::SerialNumber(sn_bytes);

    let challenge = localpki_core::enrollment::EnrollmentChallenge {
        serial_number: sn,
        en_url: en_url.to_string(),
        validity_days: 3650,
    };
    let cert = localpki_core::enrollment::create_self_signed_cert(&kp, "Root LRA", &challenge)
        .map_err(|_| AppError::Config("root LRA cert creation failed".into()))?;

    let sn_hex = hex::encode(sn.0);
    let si_b64 = URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes());
    let pk_b64 = URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes());
    let tbs_json = serde_json::to_string(&cert.tbs)
        .map_err(|e| AppError::Database(format!("tbs serialization: {e}")))?;
    let now = crate::utils::unix_now()?;
    let sn_hex_db = sn_hex.clone();

    run_db(pool, move |conn| {
        use crate::db::schema::identities;
        diesel::insert_into(identities::table)
            .values(NewIdentity {
                sn: &sn_hex_db,
                si: &si_b64,
                pk: &pk_b64,
                tbs_cert: &tbs_json,
                lra_id: &sn_hex_db,
                registered_at: now,
                revoked_at: None,
            })
            .execute(conn)?;
        Ok(())
    })
    .await?;

    Ok((kp, sn_hex))
}
