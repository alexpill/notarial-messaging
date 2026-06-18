// Key derivation hierarchy: K_master (HSM) → K_acte (per dossier) → K_send (per participant).
// ECIES: manual implementation via X25519 DH + HKDF + AES-256-GCM.

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;

use crate::error::CryptoError;
use localpki_core::cert::SerialNumber;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Wire format: ephemeral_pk (32) || nonce (12) || ciphertext+tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesCiphertext {
    pub ephemeral_pk: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// K_acte = HKDF-Expand(K_master, "notariat-msg-v1" || acte_uuid, 32).
/// Deterministic — K_acte never needs to be stored, only K_master is.
pub fn derive_k_acte(k_master: &[u8; 32], acte_uuid: &uuid::Uuid) -> [u8; 32] {
    let mut info = Vec::with_capacity(15 + 16);
    info.extend_from_slice(b"notariat-msg-v1");
    info.extend_from_slice(acte_uuid.as_bytes());

    let mut output_key_material = [0u8; 32];
    Hkdf::<Sha256>::new(None, k_master)
        .expand(&info, &mut output_key_material)
        .expect("32 bytes is always a valid HKDF output length");
    output_key_material
}

/// K_send = HKDF-Expand(K_acte, "send" || SN, 32).
/// Each participant has a distinct K_send — any participant with K_acte can recompute it.
pub fn derive_k_send(k_acte: &[u8; 32], sn: &SerialNumber) -> [u8; 32] {
    let mut info = Vec::with_capacity(4 + 16);
    info.extend_from_slice(b"send");
    info.extend_from_slice(&sn.0);

    let mut output_key_material = [0u8; 32];
    Hkdf::<Sha256>::new(None, k_acte)
        .expand(&info, &mut output_key_material)
        .expect("32 bytes is always a valid HKDF output length");
    output_key_material
}

pub fn ecies_encrypt(
    recipient_x25519_pk: &x25519_dalek::PublicKey,
    plaintext: &[u8],
) -> Result<EciesCiphertext, CryptoError> {
    let ephemeral_sk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pk = x25519_dalek::PublicKey::from(&ephemeral_sk);

    let shared = ephemeral_sk.diffie_hellman(recipient_x25519_pk);

    let mut symmetric_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(ephemeral_pk.as_bytes()), shared.as_bytes())
        .expand(b"notariat-ecies-v1", symmetric_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = Aes256Gcm::new_from_slice(symmetric_key.as_ref())
        .map_err(|_| CryptoError::KeyDerivation)?
        .encrypt(aes_gcm::Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EciesCiphertext {
        ephemeral_pk: ephemeral_pk.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn ecies_decrypt(
    recipient_x25519_sk: &Zeroizing<x25519_dalek::StaticSecret>,
    ct: &EciesCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral_pk = x25519_dalek::PublicKey::from(ct.ephemeral_pk);
    let shared = recipient_x25519_sk.diffie_hellman(&ephemeral_pk);

    // Reject low-order ephemeral points: a non-contributory DH yields a known
    // all-zero shared secret, so an attacker who can write the ciphertext could
    // force a predictable symmetric key. Cheap hardening for an "état de l'art" claim.
    if !shared.was_contributory() {
        return Err(CryptoError::Decryption);
    }

    let mut symmetric_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(ephemeral_pk.as_bytes()), shared.as_bytes())
        .expand(b"notariat-ecies-v1", symmetric_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;

    Aes256Gcm::new_from_slice(symmetric_key.as_ref())
        .map_err(|_| CryptoError::KeyDerivation)?
        .decrypt(aes_gcm::Nonce::from_slice(&ct.nonce), ct.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption)
}
