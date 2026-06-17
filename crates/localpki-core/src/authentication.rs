// LocalPKI authentication — Algorithms 2 and 3 (private mode).
// Verified once per connection, not on every message.

use ed25519_dalek::{ed25519::signature::Signer, Verifier};
use sha2::{Digest, Sha256};

use crate::{cert::LocalPKICert, error::LocalPkiError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStatus {
    Ok,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub serial_number: crate::cert::SerialNumber,
    pub signature_id: crate::cert::SignatureId,
    /// Random nonce — bound into the EN signature to prevent replay attacks.
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: AuthStatus,
    pub request_echo: AuthRequest,
    /// Sign(sk_EN, SHA256(status || SN || SI || nonce))
    pub en_signature: ed25519_dalek::Signature,
}

/// Abstracts the EN database — allows testing without SQLite.
pub trait EnDatabase: Send + Sync {
    fn lookup(&self, sn: &crate::cert::SerialNumber) -> Option<crate::cert::RegistrationEntry>;
}

/// Server side — build an AuthRequest from Alice's certificate.
pub fn build_auth_request(cert: &LocalPKICert) -> AuthRequest {
    AuthRequest {
        serial_number: cert.tbs.serial_number,
        signature_id: cert.signature_id.clone(),
        nonce: rand::random(),
    }
}

/// EN side — look up (SN, SI) and return a signed AuthResponse.
pub fn respond_to_auth_request(
    request: &AuthRequest,
    database: &dyn EnDatabase,
    en_signing_key: &ed25519_dalek::SigningKey,
) -> AuthResponse {
    let status = match database.lookup(&request.serial_number) {
        Some(entry) if entry.revoked_at.is_none()
            && entry.signature_id.0.to_bytes() == request.signature_id.0.to_bytes() =>
        {
            AuthStatus::Ok
        }
        _ => AuthStatus::Unknown,
    };

    let en_signature = en_signing_key.sign(&Sha256::digest(&auth_payload(&status, request)));

    AuthResponse {
        status,
        request_echo: request.clone(),
        en_signature,
    }
}

/// Server side — verify the EN signature and nonce echo, return AuthStatus.
pub fn verify_auth_response(
    response: &AuthResponse,
    en_verifying_key: &ed25519_dalek::VerifyingKey,
    original_request: &AuthRequest,
) -> Result<AuthStatus, LocalPkiError> {
    if response.request_echo.nonce != original_request.nonce {
        return Err(LocalPkiError::InvalidNonce);
    }

    let payload = auth_payload(&response.status, &response.request_echo);
    en_verifying_key
        .verify(&Sha256::digest(&payload), &response.en_signature)
        .map_err(|_| LocalPkiError::InvalidSignature)?;

    Ok(response.status.clone())
}

/// Domain-separation tag for EN AuthResponse signatures. Distinguishes this
/// payload from anything else the EN key signs (e.g. Merkle roots).
const AUTH_DOMAIN_TAG: &[u8] = b"localpki-auth-v1\0";

/// Canonical payload signed by the EN: tag || status (1) || SN (16) || SI (64) || nonce (32).
fn auth_payload(status: &AuthStatus, request: &AuthRequest) -> Vec<u8> {
    let status_byte: u8 = match status {
        AuthStatus::Ok => 0,
        AuthStatus::Unknown => 1,
    };
    let mut payload = Vec::with_capacity(AUTH_DOMAIN_TAG.len() + 113);
    payload.extend_from_slice(AUTH_DOMAIN_TAG);
    payload.push(status_byte);
    payload.extend_from_slice(&request.serial_number.0);
    payload.extend_from_slice(&request.signature_id.0.to_bytes());
    payload.extend_from_slice(&request.nonce);
    payload
}

// ─── Login proof of possession ─────────────────────────────────────────────────
//
// At login the client must prove it holds sk (not merely that it knows the static,
// non-secret SI). The server issues a fresh single-use nonce; the client signs
// `tag || SN || nonce` with sk; the server verifies with the registry pk. Signed
// directly with Ed25519 (internal SHA-512), no explicit SHA-256 — same convention
// as SI over the cert DER.

/// Domain-separation tag for the client's login proof-of-possession signature.
/// Keeps the user key from producing a login signature reusable in another context.
pub const AUTH_POP_DOMAIN_TAG: &[u8] = b"localpki-auth-pop-v1\0";

/// Canonical payload the client signs at login: tag || SN (16) || challenge nonce (32).
pub fn auth_pop_payload(sn: &crate::cert::SerialNumber, nonce: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(AUTH_POP_DOMAIN_TAG.len() + 16 + 32);
    payload.extend_from_slice(AUTH_POP_DOMAIN_TAG);
    payload.extend_from_slice(&sn.0);
    payload.extend_from_slice(nonce);
    payload
}

#[cfg(test)]
mod pop_tests {
    use super::*;
    use crate::{cert::SerialNumber, crypto::KeyPair};

    #[test]
    fn auth_pop_roundtrip_and_rejects_wrong_nonce() {
        let kp = KeyPair::generate().unwrap();
        let sn = SerialNumber([7u8; 16]);
        let nonce = [9u8; 32];

        let sig = kp.signing_key.sign(&auth_pop_payload(&sn, &nonce));
        assert!(kp
            .verifying_key
            .verify(&auth_pop_payload(&sn, &nonce), &sig)
            .is_ok());

        // A different nonce must not verify against the same signature.
        let other_nonce = [10u8; 32];
        assert!(kp
            .verifying_key
            .verify(&auth_pop_payload(&sn, &other_nonce), &sig)
            .is_err());
    }
}
