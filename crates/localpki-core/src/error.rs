// Erreurs de la crate localpki-core.
// Chaque variant correspond à un échec protocolaire précis du papier LocalPKI.

#[derive(Debug, thiserror::Error)]
pub enum LocalPkiError {
    #[error("signature invalide")]
    InvalidSignature,

    #[error("certificat expiré")]
    ExpiredCertificate,

    #[error("SN inconnu dans la base EN")]
    UnknownSerialNumber,

    #[error("SN déjà enregistré")]
    DuplicateSerialNumber,

    #[error("signature LRA invalide")]
    InvalidLraSignature,

    #[error("erreur de sérialisation du certificat : {0}")]
    CertEncoding(#[from] x509_cert::der::Error),

    #[error("erreur de génération de clé")]
    KeyGeneration,

    #[error("horloge système invalide")]
    SystemTime,

    #[error("nonce de la réponse EN ne correspond pas à la requête")]
    InvalidNonce,
}
