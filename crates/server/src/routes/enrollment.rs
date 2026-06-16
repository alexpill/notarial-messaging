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

    // The LRA's trustworthiness is established by its own presence in the EN registry.
    // No hardcoded LRA key — any enrolled and non-revoked identity can act as LRA.
    let lra = registry::lookup_identity(&state.db, req.lra_sn.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("LRA '{}' not found or revoked", req.lra_sn)))?;

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

// `lra_sign` endpoint deliberately removed. Endorsements must be produced by an
// authenticated LRA (notaire) signing the cert with their own private key on
// the client side — see frontend `/notaire/enroller` and demo-cli `enroller`.
// The EN now exposes only `POST /enroll`, which validates the LRA's Ed25519
// signature against the pk recorded in the registry. This keeps the EN minimal
// (it never holds an LRA key) and matches Dumas et al. §1.2, §2.1.
