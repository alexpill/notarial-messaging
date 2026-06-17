// LocalPKI enrollment — Algorithm 1 (Dumas et al. 2019).
//
// Message flow (see ARCHITECTURE.md §3.1):
//   1. Alice generates (sk, pk)
//   2. Alice → LRA: pk
//   3-4. LRA verifies identity, returns (SN, URL_EN, validity)
//   5. Alice builds TBSCert, computes SI = Sign(sk, H(TBSCert))
//   6. Alice → LRA: TBSCert || SI
//   7. LRA verifies SI (proof of possession of sk)
//   8-9. LRA → EN: {SN||SI||pk}_{pk_EN} || Sign(sk_LRA, H(SN||SI||pk))
//   11. EN decrypts, verifies LRA signature, stores (SN, SI)

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};
use ed25519_dalek::{ed25519::signature::Signer, Verifier};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    cert::{LocalPKICert, RegistrationEntry, SerialNumber, TBSCert},
    crypto::{self, KeyPair},
    error::LocalPkiError,
    SignatureId, Validity,
};

/// Step 2 — Sent by the user to the LRA to initiate enrollment.
pub struct EnrollmentRequest {
    pub public_key: ed25519_dalek::VerifyingKey,
}

/// Steps 3-4 — Sent by the LRA to the user after physical identity verification.
pub struct EnrollmentChallenge {
    /// Allocated by the EN and pre-distributed to the LRA.
    pub serial_number: SerialNumber,
    pub en_url: String,
    pub validity_days: u32,
}

/// Step 9 — Sent by the LRA to the EN.
pub struct LraToEnMessage {
    /// ECIES-encrypted payload: ephemeral_pk (32) || nonce (12) || ciphertext+tag.
    /// Plaintext is SN (16) || SI (64) || pk (32).
    pub encrypted_payload: Vec<u8>,
    /// Sign(sk_LRA, H(SN||SI||pk)) — faithful to Algorithm 1 of the paper.
    /// Trade-off: the EN must decrypt before verifying. Signing H(ciphertext)
    /// would allow verification without decryption but deviates from the paper.
    pub lra_signature: ed25519_dalek::Signature,
}

/// Step 5 — User side. Builds and self-signs the TBSCert to produce SI.
pub fn create_self_signed_cert(
    keypair: &KeyPair,
    subject_id: &str,
    challenge: &EnrollmentChallenge,
) -> Result<LocalPKICert, LocalPkiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalPkiError::SystemTime)?
        .as_secs() as i64;
    let duration_in_seconds = ((challenge.validity_days) * 24 * 60 * 60) as i64;

    let tbs = TBSCert {
        serial_number: challenge.serial_number,
        subject_id: subject_id.to_string(),
        validity: Validity {
            not_before: now,
            not_after: now + duration_in_seconds,
        },
        en_url: challenge.en_url.clone(),
        public_key: keypair.verifying_key,
    };

    let tbs_der = tbs.to_der()?;
    // Ed25519 hashes the message internally — no need to pre-hash.
    let signature_id = SignatureId(keypair.signing_key.sign(&tbs_der));

    Result::Ok(LocalPKICert { tbs, signature_id })
}

/// Step 7 — LRA side. Verifies SI as proof of possession of sk.
pub fn verify_signature_id(cert: &LocalPKICert) -> Result<(), LocalPkiError> {
    let tbs_der = cert.tbs.to_der()?;
    cert.tbs
        .public_key
        .verify(&tbs_der, &cert.signature_id.0)
        .map_err(|_| LocalPkiError::InvalidSignature)
}

/// Step 9 — LRA side. Encrypts (SN, SI, pk) for the EN and signs the plaintext hash.
/// See: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption
pub fn prepare_lra_to_en_message(
    cert: &LocalPKICert,
    en_verifying_key: &ed25519_dalek::VerifyingKey,
    lra_signing_key: &ed25519_dalek::SigningKey,
) -> Result<LraToEnMessage, LocalPkiError> {
    let en_x25519_pk = crypto::verifying_key_to_x25519_public(en_verifying_key);

    let ephemeral_sk = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let shared = ephemeral_sk.diffie_hellman(&en_x25519_pk);

    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pk.as_bytes()), shared.as_bytes());
    let mut symetric_key = [0u8; 32];
    hk.expand(b"localpki-enrollment-v1", &mut symetric_key)
        .map_err(|_| LocalPkiError::KeyGeneration)?;

    // SN (16) || SI (64) || pk (32) = 112 bytes
    // pk is included so the EN can populate RegistrationEntry (PoC extension).
    let mut plaintext = Vec::with_capacity(112);
    plaintext.extend_from_slice(&cert.tbs.serial_number.0);
    plaintext.extend_from_slice(&cert.signature_id.0.to_bytes());
    plaintext.extend_from_slice(cert.tbs.public_key.as_bytes());

    let cipher =
        Aes256Gcm::new_from_slice(&symetric_key).map_err(|_| LocalPkiError::KeyGeneration)?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| LocalPkiError::KeyGeneration)?;

    let mut encrypted_payload = Vec::with_capacity(32 + 12 + ciphertext.len());
    encrypted_payload.extend_from_slice(ephemeral_pk.as_bytes());
    encrypted_payload.extend_from_slice(&nonce_bytes);
    encrypted_payload.extend_from_slice(&ciphertext);

    let lra_signature = lra_signing_key.sign(&Sha256::digest(&plaintext));

    Ok(LraToEnMessage {
        encrypted_payload,
        lra_signature,
    })
}

/// Step 11 — EN side. Decrypts the LRA payload and registers (SN, SI) in the database.
pub fn register_from_lra_message(
    message: &LraToEnMessage,
    en_keypair: &KeyPair,
    lra_verifying_key: &ed25519_dalek::VerifyingKey,
    lra_id: &str,
) -> Result<RegistrationEntry, LocalPkiError> {
    let payload = &message.encrypted_payload;

    // ephemeral_pk (32) + nonce (12) + ciphertext+tag (112+16) = 172 bytes minimum
    if payload.len() < 172 {
        return Err(LocalPkiError::InvalidLraSignature);
    }

    let ephemeral_pk = PublicKey::from(
        <[u8; 32]>::try_from(&payload[0..32]).map_err(|_| LocalPkiError::InvalidLraSignature)?,
    );
    let nonce = aes_gcm::Nonce::from_slice(&payload[32..44]);
    let ciphertext = &payload[44..];

    let en_x25519_secret = en_keypair.to_x25519_static_secret();
    let shared = en_x25519_secret.diffie_hellman(&ephemeral_pk);

    // Salt = ephemeral_pk, matching the derivation in prepare_lra_to_en_message.
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pk.as_bytes()), shared.as_bytes());
    let mut symmetric_key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"localpki-enrollment-v1", symmetric_key.as_mut())
        .map_err(|_| LocalPkiError::KeyGeneration)?;

    // GCM decryption also authenticates the ciphertext.
    let cipher = Aes256Gcm::new_from_slice(symmetric_key.as_ref())
        .map_err(|_| LocalPkiError::KeyGeneration)?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LocalPkiError::InvalidLraSignature)?;

    // Verify before acting on the decrypted content.
    lra_verifying_key
        .verify(&Sha256::digest(&plaintext), &message.lra_signature)
        .map_err(|_| LocalPkiError::InvalidLraSignature)?;

    // SN (16) || SI (64) || pk (32)
    if plaintext.len() != 112 {
        return Err(LocalPkiError::InvalidLraSignature);
    }
    let serial_number = SerialNumber(
        <[u8; 16]>::try_from(&plaintext[0..16]).map_err(|_| LocalPkiError::InvalidLraSignature)?,
    );
    let signature_id = SignatureId(ed25519_dalek::Signature::from_bytes(
        <&[u8; 64]>::try_from(&plaintext[16..80]).map_err(|_| LocalPkiError::InvalidLraSignature)?,
    ));
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(
        <&[u8; 32]>::try_from(&plaintext[80..112]).map_err(|_| LocalPkiError::InvalidLraSignature)?,
    )
    .map_err(|_| LocalPkiError::InvalidLraSignature)?;

    let registered_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalPkiError::SystemTime)?
        .as_secs() as i64;

    Ok(RegistrationEntry {
        serial_number,
        signature_id,
        public_key,
        lra_id: lra_id.to_string(),
        registered_at,
        revoked_at: None,
    })
}
