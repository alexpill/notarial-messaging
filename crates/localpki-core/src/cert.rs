// LocalPKI certificate structures.

use serde::{Deserialize, Serialize};

/// 16-byte serial number assigned by the EN to the LRA during enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialNumber(pub [u8; 16]);

/// SI = Ed25519.Sign(sk_user, SHA256(TBSCert_DER))
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureId(pub ed25519_dalek::Signature);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: i64, // Unix timestamp
    pub not_after: i64,  // Unix timestamp
}

/// Certificate body before self-signature. Maps to X.509v3 fields (see ARCHITECTURE.md §8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBSCert {
    pub subject_id: String,
    pub public_key: ed25519_dalek::VerifyingKey,
    pub serial_number: SerialNumber,
    pub validity: Validity,
    /// Stored in a custom X.509 extension OID 1.3.6.1.4.1.99999.1
    pub en_url: String,
}

/// Full LocalPKI certificate presented during authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalPKICert {
    pub tbs: TBSCert,
    pub signature_id: SignatureId,
}

/// EN registry entry for a single LRA. The EN never stores the full TBSCert, only (SN, SI).
#[derive(Debug, Clone)]
pub struct RegistrationEntry {
    pub serial_number: SerialNumber,
    pub signature_id: SignatureId,
    /// Kept for message signature verification
    pub public_key: ed25519_dalek::VerifyingKey,
    pub lra_id: String,
    pub registered_at: i64,
    pub revoked_at: Option<i64>,
}
