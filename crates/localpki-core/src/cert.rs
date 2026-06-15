// LocalPKI certificate structures.

use serde::{Deserialize, Serialize};
use x509_cert::der::{asn1::Ia5StringRef, Encode};

use crate::error::LocalPkiError;

/// 16-byte serial number assigned by the EN to the LRA during enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
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

impl TBSCert {
    /// Encodes this structure as a DER `TBSCertificate` (X.509v3, RFC 5280).
    ///
    /// The returned bytes are the canonical input for computing SI:
    /// `SI = Ed25519.Sign(sk_user, tbs_der)`.
    /// The full certificate is then assembled as `TBSCertificate || AlgorithmId || SI`.
    pub fn to_der(&self) -> Result<Vec<u8>, LocalPkiError> {
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::der::asn1::{GeneralizedTime, ObjectIdentifier, OctetString};
        use x509_cert::{
            ext::Extension,
            name::Name,
            serial_number::SerialNumber as X509SerialNumber,
            spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
            time::{Time, Validity as X509Validity},
            TbsCertificate, Version,
        };

        // Subject == Issuer for a self-signed cert
        let name = Name::from_str(&format!("CN={}", self.subject_id))?;

        // Validity — timestamps are always positive for future dates
        let not_before_secs = u64::try_from(self.validity.not_before)
            .map_err(|_| LocalPkiError::SystemTime)?;
        let not_after_secs = u64::try_from(self.validity.not_after)
            .map_err(|_| LocalPkiError::SystemTime)?;
        let validity = X509Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_unix_duration(
                Duration::from_secs(not_before_secs),
            )?),
            not_after: Time::GeneralTime(GeneralizedTime::from_unix_duration(
                Duration::from_secs(not_after_secs),
            )?),
        };

        // SN → X.509 serialNumber
        let serial = X509SerialNumber::new(&self.serial_number.0)?;

        // SPKI built from the public key (ed25519-dalek implements EncodePublicKey)
        let spki = SubjectPublicKeyInfoOwned::from_key(self.public_key)
            .map_err(|e| LocalPkiError::CertEncoding(match e {
                x509_cert::spki::Error::Asn1(der_err) => der_err,
                _ => x509_cert::der::ErrorKind::Failed.into(),
            }))?;

        // Algorithm OID for Ed25519 (RFC 8410 §3) — no parameters
        let alg = AlgorithmIdentifierOwned {
            oid: ed25519_dalek::ed25519::pkcs8::ALGORITHM_OID,
            parameters: None,
        };

        // Extension OID 1.3.6.1.4.1.99999.1 — EN URL encoded as DER IA5String
        let url_der = Ia5StringRef::new(self.en_url.as_str())?.to_der()?;
        let ext = Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            critical: false,
            extn_value: OctetString::new(url_der)?,
        };

        TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: alg,
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![ext]),
        }
        .to_der()
        .map_err(LocalPkiError::CertEncoding)
    }
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
