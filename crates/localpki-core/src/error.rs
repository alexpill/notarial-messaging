#[derive(Debug, thiserror::Error)]
pub enum LocalPkiError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("certificate expired")]
    ExpiredCertificate,

    #[error("certificate not yet valid")]
    CertNotYetValid,

    #[error("unknown serial number")]
    UnknownSerialNumber,

    #[error("serial number already registered")]
    DuplicateSerialNumber,

    #[error("invalid LRA signature")]
    InvalidLraSignature,

    #[error("certificate encoding error: {0}")]
    CertEncoding(#[from] x509_cert::der::Error),

    #[error("key generation error")]
    KeyGeneration,

    #[error("invalid system clock")]
    SystemTime,

    #[error("EN response nonce does not match the original request")]
    InvalidNonce,
}
