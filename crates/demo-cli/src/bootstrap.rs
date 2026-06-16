// Bootstrap Root LRA — seeded directly in SQLite because the server's POST
// /enroll requires an existing LRA in the registry. Every other operation in
// the demo goes through the HTTP API. This is the only out-of-band path.

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use localpki_core::{
    cert::SerialNumber,
    crypto::KeyPair,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
};

use crate::identity::IdentityFile;

pub struct RootLra {
    pub keypair: KeyPair,
    pub sn_hex: String,
}

/// File next to the DB that persists the Root LRA's keypair across runs.
/// Without this, every `demo-cli scenario` invocation would generate a fresh
/// Root LRA and leave the previous ones as orphaned rows in `identities`.
const ROOT_LRA_FILE: &str = "root_lra.json";

/// Seeds a Root LRA into SQLite if none is recorded locally yet; otherwise
/// reloads the existing keypair so the same identity is reused across runs.
/// The file `root_lra.json` is the source of truth — if it disappears, a new
/// Root LRA is generated and inserted (the old DB row, if any, becomes
/// effectively orphaned — only the file-backed identity is reused).
pub fn seed_root_lra(db_path: &str, en_url: &str) -> anyhow::Result<RootLra> {
    if let Ok(existing) = IdentityFile::load(ROOT_LRA_FILE) {
        let kp = existing.keypair()?;
        return Ok(RootLra { keypair: kp, sn_hex: existing.sn_hex });
    }

    let kp = KeyPair::generate().map_err(|e| anyhow::anyhow!("KeyPair::generate: {e:?}"))?;
    let sn_bytes: [u8; 16] = rand::random();
    let sn = SerialNumber(sn_bytes);

    let challenge = EnrollmentChallenge {
        serial_number: sn,
        en_url: en_url.to_string(),
        validity_days: 365,
    };
    let cert = create_self_signed_cert(&kp, "Root LRA", &challenge)
        .map_err(|e| anyhow::anyhow!("create_self_signed_cert: {e:?}"))?;

    let sn_hex = hex::encode(sn.0);
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

    conn.execute(
        "INSERT OR IGNORE INTO identities \
         (sn, si, pk, tbs_der, subject_id, lra_id, registered_at, revoked_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        rusqlite::params![sn_hex, si_b64, pk_b64, tbs_der_b64, subject_id, sn_hex, now],
    )
    .context("INSERT root LRA into identities")?;

    let identity = IdentityFile::from_keypair_and_cert("Root LRA", &kp, cert);
    identity
        .save(ROOT_LRA_FILE)
        .with_context(|| format!("failed to persist {ROOT_LRA_FILE}"))?;

    Ok(RootLra { keypair: kp, sn_hex })
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
