// Bootstrap notaire — seeded directly in SQLite with role=notaire. This is the
// EN designating its first notaire out-of-band (paper §2.1: "the LRA is
// registered by some EN"), the one privileged operation that can't go through
// the role-gated HTTP API. Every other operation in the demo uses the API.

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use localpki_core::{
    cert::{LocalPKICert, SerialNumber},
    crypto::KeyPair,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
};

use crate::identity::IdentityFile;

pub struct BootstrapNotaire {
    pub keypair: KeyPair,
    pub sn_hex: String,
    pub cert: LocalPKICert,
}

/// File next to the DB that persists the bootstrap notaire's keypair across runs.
/// Without this, every `demo-cli scenario` invocation would generate a fresh
/// notaire and leave the previous ones as orphaned rows in `identities`.
const BOOTSTRAP_NOTAIRE_FILE: &str = "bootstrap_notaire.json";

/// Seeds a notaire (role=notaire) into SQLite. Reuses the identity cached in
/// `bootstrap_notaire.json` across runs when present, and always (re)inserts the
/// row into `identities` via `INSERT OR IGNORE`. The DB insert runs on every
/// path so a wiped/recreated database stays in sync with the cached JSON —
/// otherwise the notaire would exist in the JSON but be missing server-side,
/// and `POST /auth/verify` would 404.
pub fn seed_bootstrap_notaire(db_path: &str, en_url: &str) -> anyhow::Result<BootstrapNotaire> {
    let (kp, sn_hex, cert) = if let Ok(existing) = IdentityFile::load(BOOTSTRAP_NOTAIRE_FILE) {
        let kp = existing.keypair()?;
        (kp, existing.sn_hex, existing.cert)
    } else {
        let kp = KeyPair::generate().map_err(|e| anyhow::anyhow!("KeyPair::generate: {e:?}"))?;
        let sn_bytes: [u8; 16] = rand::random();
        let sn = SerialNumber(sn_bytes);

        let challenge = EnrollmentChallenge {
            serial_number: sn,
            en_url: en_url.to_string(),
            validity_days: 365,
        };
        let cert = create_self_signed_cert(&kp, "Maître Dupont", &challenge)
            .map_err(|e| anyhow::anyhow!("create_self_signed_cert: {e:?}"))?;

        let identity = IdentityFile::from_keypair_and_cert("Maître Dupont", &kp, cert.clone());
        identity
            .save(BOOTSTRAP_NOTAIRE_FILE)
            .with_context(|| format!("failed to persist {BOOTSTRAP_NOTAIRE_FILE}"))?;

        (kp, hex::encode(sn.0), cert)
    };

    let si_b64 = URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes());
    let pk_b64 = URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes());
    let tbs_der_b64 = URL_SAFE_NO_PAD.encode(
        cert.tbs
            .to_der()
            .map_err(|e| anyhow::anyhow!("tbs DER encoding: {e:?}"))?,
    );
    let subject_id = cert.tbs.subject_id.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("failed to open SQLite DB at {db_path}"))?;

    // lra_id sentinel mirrors the server's /enroll/notaire path; role=notaire is
    // what lets this identity endorse clients and create actes. INSERT OR IGNORE
    // makes this idempotent: a no-op when the row already exists, a re-seed when
    // the DB was reset out from under the cached JSON.
    conn.execute(
        "INSERT OR IGNORE INTO identities \
         (sn, si, pk, tbs_der, subject_id, lra_id, registered_at, revoked_at, role) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, 'notaire')",
        rusqlite::params![sn_hex, si_b64, pk_b64, tbs_der_b64, subject_id, "en:notaire-token", now],
    )
    .context("INSERT bootstrap notaire into identities")?;

    Ok(BootstrapNotaire { keypair: kp, sn_hex, cert })
}

/// Extrait le chemin du fichier SQLite depuis DATABASE_URL.
/// Exemples : "sqlite://./notarial.db" → "./notarial.db"
///            "sqlite:///tmp/notarial.db" → "/tmp/notarial.db"
pub fn db_path_from_url(url: &str) -> anyhow::Result<String> {
    let path = url
        .strip_prefix("sqlite://")
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL must start with 'sqlite://', got: {url}"))?;
    Ok(path.to_string())
}
