// Message encryption and signing.
//
// Send (Alice): derive K_send → AES-256-GCM(K_send, M, AAD) + Ed25519.Sign(sk, H(C || context))
// Receive (Bob): verify signature on ciphertext → derive K_send_Alice → decrypt
//
// The signature is computed over the *ciphertext*, not the plaintext. This lets the server
// reject forgeries without ever reading the message. Non-repudiation on the cleartext is
// preserved because AES-GCM is AEAD: a given (ciphertext, nonce, AAD, key) tuple decrypts
// to exactly one plaintext or fails. See ARCHITECTURE.md §5.3.

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm};
use ed25519_dalek::{ed25519::signature::Signer, Verifier};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::{error::CryptoError, keys::derive_k_send};
use localpki_core::cert::SerialNumber;
use serde::{Deserialize, Serialize};

/// Encrypted message stored server-side. The server never sees plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    /// Ed25519(sk_sender, SHA256(MSG_DOMAIN_TAG || ciphertext || nonce || acte_uuid || timestamp || SN_sender))
    pub signature: ed25519_dalek::Signature,
    /// Monotonic sequence number within the acte, assigned by the server.
    pub seq: u64,
}

pub fn encrypt_message(
    k_acte: &[u8; 32],
    plaintext: &[u8],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let k_send = derive_k_send(k_acte, sender_sn);
    let aad = build_aad(acte_uuid, timestamp, sender_sn);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = Aes256Gcm::new_from_slice(&k_send)
        .map_err(|_| CryptoError::KeyDerivation)?
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: &aad },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_message(
    k_acte: &[u8; 32],
    sender_sn: &SerialNumber,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    acte_uuid: &uuid::Uuid,
    timestamp: i64,
) -> Result<Vec<u8>, CryptoError> {
    let k_send = derive_k_send(k_acte, sender_sn);
    let aad = build_aad(acte_uuid, timestamp, sender_sn);

    Aes256Gcm::new_from_slice(&k_send)
        .map_err(|_| CryptoError::KeyDerivation)?
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload { msg: ciphertext, aad: &aad },
        )
        .map_err(|_| CryptoError::Decryption)
}

pub fn sign_message(
    signing_key: &ed25519_dalek::SigningKey,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
) -> ed25519_dalek::Signature {
    signing_key.sign(&Sha256::digest(&signing_payload(ciphertext, nonce, acte_uuid, timestamp, sender_sn)))
}

pub fn verify_message_signature(
    verifying_key: &ed25519_dalek::VerifyingKey,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
    signature: &ed25519_dalek::Signature,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(&Sha256::digest(&signing_payload(ciphertext, nonce, acte_uuid, timestamp, sender_sn)), signature)
        .map_err(|_| CryptoError::InvalidMessageSignature)
}

/// AAD (Additional Authenticated Data): acte_uuid (16) || timestamp (8, LE) || SN (16) — binds ciphertext to its context.
fn build_aad(acte_uuid: &uuid::Uuid, timestamp: i64, sn: &SerialNumber) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(acte_uuid.as_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(&sn.0);
    aad
}

/// Domain-separation tag for client message signatures. Keeps a message
/// signature from being reusable in another user-key context (SI over the cert
/// DER, participant-add, revocation). Mirror in frontend/src/lib/crypto/messages.ts.
pub const MSG_DOMAIN_TAG: &[u8] = b"localpki-msg-v1\0";

/// Signing payload: tag || ciphertext || nonce (12) || acte_uuid (16) || timestamp (8, LE) || SN (16).
fn signing_payload(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    acte_uuid: &uuid::Uuid,
    timestamp: i64,
    sn: &SerialNumber,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MSG_DOMAIN_TAG.len() + ciphertext.len() + 52);
    payload.extend_from_slice(MSG_DOMAIN_TAG);
    payload.extend_from_slice(ciphertext);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(acte_uuid.as_bytes());
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload.extend_from_slice(&sn.0);
    payload
}
