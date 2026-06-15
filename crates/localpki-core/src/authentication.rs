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

/// Canonical payload signed by the EN: status (1) || SN (16) || SI (64) || nonce (32).
fn auth_payload(status: &AuthStatus, request: &AuthRequest) -> Vec<u8> {
    let status_byte: u8 = match status {
        AuthStatus::Ok => 0,
        AuthStatus::Unknown => 1,
    };
    let mut payload = Vec::with_capacity(113);
    payload.push(status_byte);
    payload.extend_from_slice(&request.serial_number.0);
    payload.extend_from_slice(&request.signature_id.0.to_bytes());
    payload.extend_from_slice(&request.nonce);
    payload
}
