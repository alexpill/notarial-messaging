// Seed direct du Root LRA en base SQLite pour le scénario de démo.
// Le serveur exige qu'un LRA soit déjà enregistré avant tout enrollment.
// Seule cette fonction contourne l'API — tout le reste passe par le serveur.

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use localpki_core::{
    cert::SerialNumber,
    crypto::KeyPair,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
};

pub struct RootLra {
    pub keypair: KeyPair,
    pub sn_hex: String,
}

/// Insère un Root LRA directement dans la DB SQLite et retourne ses clés.
/// Utilise `INSERT OR IGNORE` pour être idempotent si appelé plusieurs fois.
pub fn seed_root_lra(db_path: &str, en_url: &str) -> anyhow::Result<RootLra> {
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
