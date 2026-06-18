use crate::{db::models::NewIdentity, en::registry, error::AppError, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Verifier;
use localpki_core::{cert::LocalPKICert, enrollment::verify_signature_id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Trust roles stored on identities in the EN registry. The role anchors the
/// EN → notaire → client hierarchy and gates endorsement + acte creation.
pub const ROLE_NOTAIRE: &str = "notaire";
pub const ROLE_CLIENT: &str = "client";

/// Sentinel `lra_id` values for identities not endorsed by a named notaire.
/// `lra_id` is a plain label column (no FK), so these are safe.
const LRA_ID_NOTAIRE_TOKEN: &str = "en:notaire-token";
const LRA_ID_SELF_ENROLL: &str = "en:self-enroll-demo";

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// User's self-signed LocalPKI certificate (JSON-serialized).
    pub cert: serde_json::Value,
    /// LRA signature over SHA256(SN || SI || pk). base64url.
    pub lra_signature: String,
    /// SN of the LRA (must already be in the EN registry).
    pub lra_sn: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub serial_number: String,
    pub message: String,
}

pub async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> Result<(StatusCode, Json<EnrollResponse>), AppError> {
    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    verify_signature_id(&cert)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

    // Reject certs whose validity window does not cover "now" — refuse to enroll
    // an already-expired or not-yet-valid certificate. Matches paper §3.3.
    cert.tbs
        .validity
        .check(crate::utils::unix_now()?)
        .map_err(|e| AppError::BadRequest(format!("certificate validity: {e}")))?;

    // The endorser must be a registered, non-revoked identity carrying the
    // `notaire` role. This is the LocalPKI trust anchor: per the paper (§2.1)
    // the EN designates its LRAs — here, an identity is a notaire only if the EN
    // registry says so (set via /enroll/notaire or an operator), never by a
    // self-declared cert. Establishes the chain EN → notaire → client.
    let lra = registry::lookup_identity(&state.db, req.lra_sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("LRA '{}' not found or revoked", req.lra_sn)))?;

    if lra.role != ROLE_NOTAIRE {
        return Err(AppError::Forbidden(
            "endorser is not a notaire — only a notaire may endorse a client".into(),
        ));
    }

    let pk_lra = ed25519_dalek::VerifyingKey::from_bytes(&decode_b64(&lra.pk, "LRA pk")?)
        .map_err(|_| AppError::BadRequest("LRA public key is not a valid Ed25519 key".into()))?;

    let lra_sig = ed25519_dalek::Signature::from_bytes(
        &decode_b64(&req.lra_signature, "lra_signature")?,
    );

    // Mirror the payload from prepare_lra_to_en_message: SHA256(SN || SI || pk).
    let mut payload = Vec::with_capacity(112);
    payload.extend_from_slice(&cert.tbs.serial_number.0);
    payload.extend_from_slice(&cert.signature_id.0.to_bytes());
    payload.extend_from_slice(cert.tbs.public_key.as_bytes());

    pk_lra
        .verify(&Sha256::digest(&payload), &lra_sig)
        .map_err(|_| AppError::BadRequest("LRA signature verification failed".into()))?;

    let sn_hex = hex::encode(cert.tbs.serial_number.0);

    // Freeze the exact DER bytes that the client signed. Re-serializing the
    // TBSCert at verification time would tie correctness to x509-cert's
    // encoder being byte-stable across versions — we don't want that coupling.
    let tbs_der = cert
        .tbs
        .to_der()
        .map_err(|e| AppError::BadRequest(format!("DER encoding failed: {e}")))?;

    registry::insert_identity(
        &state.db,
        NewIdentity {
            sn: &sn_hex,
            si: &URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes()),
            pk: &URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes()),
            tbs_der: &URL_SAFE_NO_PAD.encode(&tbs_der),
            subject_id: &cert.tbs.subject_id,
            lra_id: &req.lra_sn,
            registered_at: crate::utils::unix_now()?,
            revoked_at: None,
            role: ROLE_CLIENT,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            serial_number: sn_hex,
            message: "enrolled successfully".to_string(),
        }),
    ))
}

pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(sn): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let identity = registry::lookup_identity(&state.db, sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("identity '{}' not found", sn)))?;

    Ok(Json(serde_json::json!({
        "sn": identity.sn,
        "pk": identity.pk,
        "display_name": identity.subject_id,
        "registered_at": identity.registered_at,
    })))
}

fn decode_b64<const N: usize>(s: &str, label: &str) -> Result<[u8; N], AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AppError::BadRequest(format!("{label}: invalid base64url")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{label}: expected {N} bytes")))
}

// ─── Frontend-assisted enrollment endpoints ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PrepareTbsRequest {
    pub subject_id: String,
    /// Ed25519 public key as array of 32 numbers (Rust serde format).
    pub public_key: [u8; 32],
}

#[derive(Debug, Serialize)]
pub struct PrepareTbsResponse {
    /// Canonical source of truth for the SN. Use this — not tbs_json.serial_number —
    /// to build sn_hex on the frontend. tbs_json.serial_number contains the same bytes
    /// but its JSON representation depends on serde's serialization of [u8; 16].
    pub sn_bytes: [u8; 16],
    /// TBSCert as JSON — client reconstructs the LocalPKICert with this + SI.
    pub tbs_json: serde_json::Value,
    /// DER-encoded TBSCert bytes, base64url. Client signs these to produce SI.
    pub tbs_der_b64url: String,
}

/// Generates a SN + TBSCert DER for the client to self-sign.
/// The client signs the DER with its Ed25519 key to produce SI.
pub async fn prepare_tbs(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PrepareTbsRequest>,
) -> Result<Json<PrepareTbsResponse>, AppError> {
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&req.public_key)
        .map_err(|_| AppError::BadRequest("invalid Ed25519 public key".into()))?;

    let sn_bytes: [u8; 16] = rand::random();
    let sn = localpki_core::cert::SerialNumber(sn_bytes);

    let now = crate::utils::unix_now()?;
    let tbs = localpki_core::cert::TBSCert {
        serial_number: sn,
        subject_id: req.subject_id,
        public_key: pk,
        validity: localpki_core::cert::Validity {
            not_before: now,
            not_after: now + 365 * 24 * 3600,
        },
        en_url: format!("http://{}:{}", state.config.server_host, state.config.server_port),
    };

    let tbs_der = tbs.to_der().map_err(|_| AppError::Config("DER encoding failed".into()))?;
    let tbs_json = serde_json::to_value(&tbs)
        .map_err(|e| AppError::Database(format!("tbs json: {e}")))?;

    Ok(Json(PrepareTbsResponse {
        sn_bytes,
        tbs_json,
        tbs_der_b64url: URL_SAFE_NO_PAD.encode(&tbs_der),
    }))
}

// ─── Self-enrollment (demo/bootstrap) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EnrollSelfRequest {
    pub cert: serde_json::Value,
}

/// One-shot **client** self-enrollment — a demo shortcut. The client presents
/// its self-signed cert and the server registers it immediately as a `client`
/// (no endorsement, no physical identity check). This exists solely so a
/// reviewer can enroll a client in one click; it can never mint a notaire (that
/// requires the enrollment token via /enroll/notaire). The trust anchor is not
/// bypassed for privileged roles.
pub async fn enroll_self(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollSelfRequest>,
) -> Result<(StatusCode, Json<EnrollResponse>), AppError> {
    // Demo shortcut — gated off unless explicitly enabled. In a production-like
    // config the only way in is the endorsed flow (POST /enroll), enforcing the
    // face-to-face LRA check that LocalPKI's trust model assumes.
    if !state.config.allow_self_enroll {
        return Err(AppError::Forbidden(
            "self-enrollment is disabled — a notaire must endorse this client (POST /enroll)".into(),
        ));
    }

    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    verify_signature_id(&cert)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

    cert.tbs
        .validity
        .check(crate::utils::unix_now()?)
        .map_err(|e| AppError::BadRequest(format!("certificate validity: {e}")))?;

    let sn_hex = hex::encode(cert.tbs.serial_number.0);

    let tbs_der = cert
        .tbs
        .to_der()
        .map_err(|e| AppError::BadRequest(format!("DER encoding failed: {e}")))?;

    registry::insert_identity(
        &state.db,
        NewIdentity {
            sn: &sn_hex,
            si: &URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes()),
            pk: &URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes()),
            tbs_der: &URL_SAFE_NO_PAD.encode(&tbs_der),
            subject_id: &cert.tbs.subject_id,
            lra_id: LRA_ID_SELF_ENROLL,
            registered_at: crate::utils::unix_now()?,
            revoked_at: None,
            role: ROLE_CLIENT,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            serial_number: sn_hex,
            message: "enrolled as client (self-enroll demo)".to_string(),
        }),
    ))
}

// ─── Notaire enrollment (token-gated bootstrap) ──────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EnrollNotaireRequest {
    /// Self-signed LocalPKI certificate, keys generated client-side.
    pub cert: serde_json::Value,
    /// Notaire enrollment token (the EN's bootstrap authority). The private key
    /// never transits — only this token does.
    pub token: String,
}

/// Enrolls a `notaire` after verifying the EN's notaire enrollment token. The
/// client generates its keys in the browser and self-signs the cert (exactly
/// like a client); presenting the valid token is what makes the EN grant the
/// `notaire` role. Reusable: the token can designate several notaires.
pub async fn enroll_notaire(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollNotaireRequest>,
) -> Result<(StatusCode, Json<EnrollResponse>), AppError> {
    let cert: LocalPKICert = serde_json::from_value(req.cert)
        .map_err(|e| AppError::BadRequest(format!("invalid certificate: {e}")))?;

    verify_signature_id(&cert)
        .map_err(|_| AppError::BadRequest("invalid signature ID (SI)".into()))?;

    cert.tbs
        .validity
        .check(crate::utils::unix_now()?)
        .map_err(|e| AppError::BadRequest(format!("certificate validity: {e}")))?;

    // Constant-time token check — avoids a timing oracle on the bootstrap secret.
    if !ct_eq(
        req.token.as_bytes(),
        state.config.notaire_enrollment_token.as_bytes(),
    ) {
        return Err(AppError::Forbidden("invalid notaire enrollment token".into()));
    }

    let sn_hex = hex::encode(cert.tbs.serial_number.0);

    let tbs_der = cert
        .tbs
        .to_der()
        .map_err(|e| AppError::BadRequest(format!("DER encoding failed: {e}")))?;

    registry::insert_identity(
        &state.db,
        NewIdentity {
            sn: &sn_hex,
            si: &URL_SAFE_NO_PAD.encode(cert.signature_id.0.to_bytes()),
            pk: &URL_SAFE_NO_PAD.encode(cert.tbs.public_key.as_bytes()),
            tbs_der: &URL_SAFE_NO_PAD.encode(&tbs_der),
            subject_id: &cert.tbs.subject_id,
            lra_id: LRA_ID_NOTAIRE_TOKEN,
            registered_at: crate::utils::unix_now()?,
            revoked_at: None,
            role: ROLE_NOTAIRE,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            serial_number: sn_hex,
            message: "enrolled as notaire (token)".to_string(),
        }),
    ))
}

/// Length-checked constant-time byte comparison. The length check leaks length
/// (acceptable for a fixed-length-ish token); the byte loop does not short-circuit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
