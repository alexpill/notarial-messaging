// LocalPKI revocation — Algorithm 4.
// After revocation, any authentication attempt for this (SN, SI) will fail.
// Re-enrollment requires a new key pair and a new physical identity check.

use ed25519_dalek::{ed25519::signature::Signer, Verifier};
use sha2::{Digest, Sha256};

use crate::{cert::LocalPKICert, error::LocalPkiError};

#[derive(Debug, Clone)]
pub struct RevocationRequest {
    pub cert: LocalPKICert,
    /// Sign(sk_user_or_LRA, SHA256(REVOKE_DOMAIN_TAG || SN || SI))
    pub revocation_signature: ed25519_dalek::Signature,
}

/// User or LRA side — build a signed RevocationRequest.
pub fn build_revocation_request(
    cert: &LocalPKICert,
    signing_key: &ed25519_dalek::SigningKey,
) -> RevocationRequest {
    let signature = signing_key.sign(&Sha256::digest(&revocation_payload(cert)));
    RevocationRequest {
        cert: cert.clone(),
        revocation_signature: signature,
    }
}

/// EN side — verify the revocation signature before removing (SN, SI) from the registry.
/// Accepts a signature from the user's own key or from a known LRA key.
pub fn validate_revocation_request(
    request: &RevocationRequest,
    lra_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<(), LocalPkiError> {
    let digest = Sha256::digest(&revocation_payload(&request.cert));
    let sig = &request.revocation_signature;

    let user_ok = request.cert.tbs.public_key.verify(&digest, sig).is_ok();
    let lra_ok = lra_verifying_key.is_some_and(|k| k.verify(&digest, sig).is_ok());

    if user_ok || lra_ok {
        Ok(())
    } else {
        Err(LocalPkiError::InvalidSignature)
    }
}

/// Domain-separation tag for revocation signatures. Replaces the ad-hoc
/// `"Revoke"` ASCII prefix with a versioned tag, consistent with the message,
/// participant, EN-auth and Merkle signing contexts.
pub const REVOKE_DOMAIN_TAG: &[u8] = b"localpki-revoke-v1\0";

/// Canonical payload: REVOKE_DOMAIN_TAG || SN (16) || SI (64).
fn revocation_payload(cert: &LocalPKICert) -> Vec<u8> {
    let mut payload = Vec::with_capacity(REVOKE_DOMAIN_TAG.len() + 80);
    payload.extend_from_slice(REVOKE_DOMAIN_TAG);
    payload.extend_from_slice(&cert.tbs.serial_number.0);
    payload.extend_from_slice(&cert.signature_id.0.to_bytes());
    payload
}
