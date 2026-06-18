use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, ed25519::signature::Signer};
use localpki_core::{cert::{LocalPKICert, SerialNumber}, crypto::KeyPair};
use messaging_crypto::keys::{EciesCiphertext, ecies_decrypt};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// LRA signature requise par POST /enroll :
/// Ed25519(sk_lra, SHA256(SN(16) || SI(64) || pk(32))).
pub fn make_lra_signature(lra_sk: &SigningKey, cert: &LocalPKICert) -> String {
    let mut payload = Vec::with_capacity(112);
    payload.extend_from_slice(&cert.tbs.serial_number.0);
    payload.extend_from_slice(&cert.signature_id.0.to_bytes());
    payload.extend_from_slice(cert.tbs.public_key.as_bytes());
    let sig = lra_sk.sign(&Sha256::digest(&payload));
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

/// Signature notaire requise par POST /actes/:id/participants :
/// Ed25519(sk_notaire, SHA256(tag || acte_id_bytes || participant_sn_bytes || grant_history as u8)).
/// `tag` = PARTICIPANT_DOMAIN_TAG (cf. server::routes::participants).
#[allow(dead_code)]
pub fn make_add_participant_signature(
    notaire_sk: &SigningKey,
    acte_id: &str,
    participant_sn: &str,
    grant_history: bool,
) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"localpki-participant-v1\0");
    payload.extend_from_slice(acte_id.as_bytes());
    payload.extend_from_slice(participant_sn.as_bytes());
    payload.push(grant_history as u8);
    let sig = notaire_sk.sign(&Sha256::digest(&payload));
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

/// Déchiffre K_acte depuis le JSON `c_acte_key` retourné par GET /actes/:id/keys.
/// Utilise la conversion Ed25519→X25519 du KeyPair.
pub fn decrypt_k_acte(kp: &KeyPair, c_acte_key_json: &str) -> anyhow::Result<[u8; 32]> {
    let ct: EciesCiphertext = serde_json::from_str(c_acte_key_json)
        .context("c_acte_key: invalid JSON")?;
    let x25519_sk = Zeroizing::new(kp.to_x25519_static_secret());
    let k_acte_vec = ecies_decrypt(&x25519_sk, &ct)
        .map_err(|e| anyhow::anyhow!("ecies_decrypt failed: {e:?}"))?;
    k_acte_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("K_acte: unexpected length (expected 32 bytes)"))
}

/// Chiffre un plaintext et signe le message côté client.
/// Retourne (c_message_b64url, nonce_b64url, signature_b64url).
pub fn encrypt_and_sign(
    k_acte: &[u8; 32],
    plaintext: &[u8],
    acte_uuid: &Uuid,
    sender_sn: &SerialNumber,
    signing_key: &SigningKey,
    timestamp: i64,
) -> anyhow::Result<(String, String, String)> {
    let (ciphertext, nonce) =
        messaging_crypto::messages::encrypt_message(k_acte, plaintext, acte_uuid, sender_sn, timestamp)
            .map_err(|e| anyhow::anyhow!("encrypt_message failed: {e:?}"))?;

    let sig = messaging_crypto::messages::sign_message(signing_key, &ciphertext, &nonce, acte_uuid, sender_sn, timestamp);

    Ok((
        URL_SAFE_NO_PAD.encode(&ciphertext),
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    ))
}

/// Déchiffre un message chiffré reçu du serveur.
/// `sender_sn` est le SN de l'émetteur (pour dériver K_send_sender).
/// `timestamp` est le champ `sent_at` du message retourné par le serveur.
pub fn decrypt_msg(
    k_acte: &[u8; 32],
    sender_sn: &SerialNumber,
    c_message_b64: &str,
    nonce_b64: &str,
    acte_uuid: &Uuid,
    timestamp: i64,
) -> anyhow::Result<Vec<u8>> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(c_message_b64)
        .context("c_message: invalid base64url")?;
    let nonce_vec = URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .context("nonce: invalid base64url")?;
    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce: expected 12 bytes"))?;

    messaging_crypto::messages::decrypt_message(k_acte, sender_sn, &ciphertext, &nonce, acte_uuid, timestamp)
        .map_err(|e| anyhow::anyhow!("decrypt_message failed: {e:?}"))
}

/// Parse un SN hex en SerialNumber.
pub fn sn_from_hex(sn_hex: &str) -> anyhow::Result<SerialNumber> {
    let bytes: [u8; 16] = hex::decode(sn_hex)
        .context("sn_hex: invalid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("sn_hex: expected 16 bytes"))?;
    Ok(SerialNumber(bytes))
}
