#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AES-GCM decryption failed (corrupted data or wrong key)")]
    Decryption,

    #[error("AES-GCM encryption failed")]
    Encryption,

    #[error("invalid message signature")]
    InvalidMessageSignature,

    #[error("invalid nonce (expected 12 bytes)")]
    InvalidNonce,

    #[error("malformed ECIES ciphertext")]
    MalformedEciesCiphertext,

    #[error("HKDF key derivation error")]
    KeyDerivation,
}
