use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use localpki_core::{
    cert::{LocalPKICert, SerialNumber},
    crypto::KeyPair,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

// ─── Test harness ─────────────────────────────────────────────────────────────

struct TestApp {
    router: Router,
    root_lra_sn: String,
    root_lra_sk: ed25519_dalek::SigningKey,
    /// SN(hex) → signing key, populated by `enroll_user`, so `authenticate` can
    /// sign the login challenge (proof of possession) without changing call sites.
    keys: std::sync::Mutex<std::collections::HashMap<String, ed25519_dalek::SigningKey>>,
}

impl TestApp {
    async fn new() -> Self {
        let pool = crate::db::init_pool_for_test().unwrap();
        let hsm = crate::hsm::HsmSimulator::new([0x42u8; 32]);
        let (root_lra_kp, root_lra_sn) =
            crate::en::registry::seed_root_lra(&pool, "http://localhost:3000")
                .await
                .unwrap();
        let root_lra_sk = root_lra_kp.signing_key.clone();
        let state = Arc::new(crate::state::AppState::new_for_test(pool, hsm));
        TestApp {
            router: crate::routes::build_router(state),
            root_lra_sn,
            root_lra_sk,
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn post_json(&self, uri: &str, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post_json_authed(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn get_authed(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// Enrolls a new user via `POST /enroll` using the root LRA key.
    async fn enroll_user(&self, name: &str) -> (KeyPair, String, LocalPKICert) {
        let kp = KeyPair::generate().unwrap();
        let sn_bytes: [u8; 16] = rand::random();
        let sn = SerialNumber(sn_bytes);
        let challenge = EnrollmentChallenge {
            serial_number: sn,
            en_url: "http://localhost:3000".to_string(),
            validity_days: 365,
        };
        let cert = create_self_signed_cert(&kp, name, &challenge).unwrap();
        let lra_sig = lra_signature(&self.root_lra_sk, &cert);
        let cert_json = serde_json::to_value(&cert).unwrap();

        let (status, resp) = self
            .post_json(
                "/enroll",
                &json!({
                    "cert": cert_json,
                    "lra_signature": lra_sig,
                    "lra_sn": self.root_lra_sn,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "enroll failed: {resp}");

        let sn_hex = hex::encode(sn_bytes);
        self.keys
            .lock()
            .unwrap()
            .insert(sn_hex.clone(), kp.signing_key.clone());
        (kp, sn_hex, cert)
    }

    /// Authenticates via `POST /auth/verify`. Returns the session token.
    async fn authenticate(&self, cert: &LocalPKICert) -> String {
        use ed25519_dalek::ed25519::signature::Signer;
        let cert_json = serde_json::to_value(cert).unwrap();

        // Fetch a fresh challenge and sign it with the cert's sk (proof of possession).
        let (_, ch) = self.post_json("/auth/challenge", &json!({})).await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let nonce: [u8; 32] = URL_SAFE_NO_PAD.decode(&challenge).unwrap().try_into().unwrap();
        let sn_hex = hex::encode(cert.tbs.serial_number.0);
        let sk = self
            .keys
            .lock()
            .unwrap()
            .get(&sn_hex)
            .cloned()
            .expect("signing key for cert not in test keystore");
        let payload =
            localpki_core::authentication::auth_pop_payload(&cert.tbs.serial_number, &nonce);
        let pop_signature = URL_SAFE_NO_PAD.encode(sk.sign(&payload).to_bytes());

        let (status, resp) = self
            .post_json(
                "/auth/verify",
                &json!({ "cert": cert_json, "challenge": challenge, "pop_signature": pop_signature }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "auth failed: {resp}");
        assert!(resp["authenticated"].as_bool().unwrap_or(false));
        resp["session_token"].as_str().unwrap().to_string()
    }
}

fn lra_signature(lra_sk: &ed25519_dalek::SigningKey, cert: &LocalPKICert) -> String {
    use ed25519_dalek::ed25519::signature::Signer;
    let mut payload = Vec::with_capacity(112);
    payload.extend_from_slice(&cert.tbs.serial_number.0);
    payload.extend_from_slice(&cert.signature_id.0.to_bytes());
    payload.extend_from_slice(cert.tbs.public_key.as_bytes());
    let sig = lra_sk.sign(&Sha256::digest(&payload));
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

fn fake_message_body(seq_hint: u8) -> (String, String, String) {
    let c_message = URL_SAFE_NO_PAD.encode(&[seq_hint; 48]);
    let nonce = URL_SAFE_NO_PAD.encode(&[seq_hint; 12]);
    let signature = URL_SAFE_NO_PAD.encode(&[seq_hint; 64]);
    (c_message, nonce, signature)
}

/// Builds a message body with a *valid* signature over the ciphertext, as the
/// server now verifies before insert.
fn signed_message_body(
    seq_hint: u8,
    signing_key: &ed25519_dalek::SigningKey,
    sender_sn_hex: &str,
    acte_uuid_str: &str,
    timestamp: i64,
) -> (String, String, String) {
    let ciphertext = vec![seq_hint; 48];
    let nonce: [u8; 12] = [seq_hint; 12];
    let sn_bytes: [u8; 16] = hex::decode(sender_sn_hex).unwrap().try_into().unwrap();
    let sender_sn = SerialNumber(sn_bytes);
    let uuid = uuid::Uuid::parse_str(acte_uuid_str).unwrap();
    let sig = messaging_crypto::messages::sign_message(
        signing_key, &ciphertext, &nonce, &uuid, &sender_sn, timestamp,
    );
    (
        URL_SAFE_NO_PAD.encode(&ciphertext),
        URL_SAFE_NO_PAD.encode(&nonce),
        URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    )
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ─── Tests — enrollment & identity ───────────────────────────────────────────

#[tokio::test]
async fn test_enroll_and_get_identity() {
    let app = TestApp::new().await;
    let (_kp, sn_hex, _cert) = app.enroll_user("Alice").await;

    let (status, resp) = app.get(&format!("/identity/{sn_hex}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["sn"].as_str().unwrap(), sn_hex);

    // pk must be 32-byte base64url
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(resp["pk"].as_str().unwrap())
        .unwrap();
    assert_eq!(pk_bytes.len(), 32);
}

#[tokio::test]
async fn test_get_identity_not_found() {
    let app = TestApp::new().await;
    let (status, _) = app.get("/identity/deadbeefdeadbeefdeadbeefdeadbeef").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_enroll_duplicate_sn_rejected() {
    let app = TestApp::new().await;
    // First enrollment: creates a cert
    let kp = KeyPair::generate().unwrap();
    let sn_bytes: [u8; 16] = rand::random();
    let sn = SerialNumber(sn_bytes);
    let challenge = EnrollmentChallenge {
        serial_number: sn,
        en_url: "http://localhost:3000".to_string(),
        validity_days: 365,
    };
    let cert = create_self_signed_cert(&kp, "Alice", &challenge).unwrap();
    let lra_sig = lra_signature(&app.root_lra_sk, &cert);
    let cert_json = serde_json::to_value(&cert).unwrap();
    let body = json!({ "cert": cert_json, "lra_signature": lra_sig, "lra_sn": app.root_lra_sn });

    let (s1, _) = app.post_json("/enroll", &body).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Second enrollment with the same cert (same SN) must be rejected
    let (s2, _) = app.post_json("/enroll", &body).await;
    assert_eq!(s2, StatusCode::INTERNAL_SERVER_ERROR); // unique constraint → DB error
}

// ─── Tests — authentication ───────────────────────────────────────────────────

#[tokio::test]
async fn test_authenticate_returns_token() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Bob").await;
    let token = app.authenticate(&cert).await;
    assert!(!token.is_empty());
    // Tokens are UUID v4 — 36 chars
    assert_eq!(token.len(), 36);
}

#[tokio::test]
async fn test_unauthorized_without_token() {
    let app = TestApp::new().await;
    let (status, _) = app.get("/actes").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_unknown_identity_fails() {
    let app = TestApp::new().await;
    // Build a cert for a key that is NOT enrolled
    let kp = KeyPair::generate().unwrap();
    let challenge = EnrollmentChallenge {
        serial_number: SerialNumber(rand::random()),
        en_url: "http://localhost:3000".to_string(),
        validity_days: 365,
    };
    let cert = create_self_signed_cert(&kp, "Ghost", &challenge).unwrap();
    let cert_json = serde_json::to_value(&cert).unwrap();

    // Provide a well-formed challenge + PoP so the request deserializes; the
    // identity is still unknown to the EN, so the lookup fails with 404.
    use ed25519_dalek::ed25519::signature::Signer;
    let (_, ch) = app.post_json("/auth/challenge", &json!({})).await;
    let ch_str = ch["challenge"].as_str().unwrap().to_string();
    let nonce: [u8; 32] = URL_SAFE_NO_PAD.decode(&ch_str).unwrap().try_into().unwrap();
    let payload =
        localpki_core::authentication::auth_pop_payload(&cert.tbs.serial_number, &nonce);
    let pop_signature = URL_SAFE_NO_PAD.encode(kp.signing_key.sign(&payload).to_bytes());

    let (status, resp) = app
        .post_json(
            "/auth/verify",
            &json!({ "cert": cert_json, "challenge": ch_str, "pop_signature": pop_signature }),
        )
        .await;
    // Identity not in EN → 404
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404, got {status}: {resp}");
}

#[tokio::test]
async fn test_auth_challenge_is_single_use() {
    use ed25519_dalek::ed25519::signature::Signer;
    let app = TestApp::new().await;
    let (kp, _sn, cert) = app.enroll_user("Bob").await;
    let cert_json = serde_json::to_value(&cert).unwrap();

    let (_, ch) = app.post_json("/auth/challenge", &json!({})).await;
    let challenge = ch["challenge"].as_str().unwrap().to_string();
    let nonce: [u8; 32] = URL_SAFE_NO_PAD.decode(&challenge).unwrap().try_into().unwrap();
    let payload =
        localpki_core::authentication::auth_pop_payload(&cert.tbs.serial_number, &nonce);
    let pop_signature = URL_SAFE_NO_PAD.encode(kp.signing_key.sign(&payload).to_bytes());
    let body = json!({ "cert": cert_json, "challenge": challenge, "pop_signature": pop_signature });

    // First use succeeds.
    let (status1, _) = app.post_json("/auth/verify", &body).await;
    assert_eq!(status1, StatusCode::OK);

    // Replaying the exact same challenge + signature fails — it was consumed.
    let (status2, _) = app.post_json("/auth/verify", &body).await;
    assert_eq!(
        status2,
        StatusCode::UNAUTHORIZED,
        "replayed login challenge must be rejected (A1)"
    );
}

// ─── Tests — actes ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_acte_includes_all_parties() {
    let app = TestApp::new().await;
    let (_kp_n, sn_notaire, cert_notaire) = app.enroll_user("Notaire").await;
    let (_kp_a, sn_alice, _cert_a) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert_notaire).await;

    let (status, resp) = app
        .post_json_authed(
            "/actes",
            &token,
            &json!({ "titre": "Vente test", "parties": [sn_alice] }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create_acte failed: {resp}");

    let uuid = resp["uuid"].as_str().expect("uuid must be present");
    assert!(!uuid.is_empty());
    assert_eq!(resp["titre"], "Vente test");

    let parties: Vec<&str> = resp["parties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(parties.contains(&sn_notaire.as_str()), "notaire auto-added");
    assert!(parties.contains(&sn_alice.as_str()));
}

#[tokio::test]
async fn test_get_acte_after_creation() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Notaire").await;
    let (_kp2, sn2, _cert2) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert).await;

    let (_, acte) = app
        .post_json_authed("/actes", &token, &json!({ "titre": "Acte X", "parties": [sn2] }))
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    let (status, fetched) = app.get_authed(&format!("/actes/{acte_id}"), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["uuid"], acte_id.as_str());
    assert_eq!(fetched["titre"], "Acte X");
}

#[tokio::test]
async fn test_list_actes_for_participant() {
    let app = TestApp::new().await;
    let (_kp, sn_notaire, cert_notaire) = app.enroll_user("Notaire").await;
    let (_kp2, sn_alice, cert2) = app.enroll_user("Alice").await;
    let token_notaire = app.authenticate(&cert_notaire).await;
    let token_alice = app.authenticate(&cert2).await;

    // Create two actes where Alice is a party
    for title in ["Acte A", "Acte B"] {
        app.post_json_authed(
            "/actes",
            &token_notaire,
            &json!({ "titre": title, "parties": [sn_alice] }),
        )
        .await;
    }

    // Notaire can list their own actes
    let (status, list) = app.get_authed("/actes", &token_notaire).await;
    assert_eq!(status, StatusCode::OK);
    let actes = list.as_array().unwrap();
    // Notaire is automatically added to both actes
    assert!(actes.len() >= 2);

    // Alice can also list hers
    let (status, _) = app.get_authed("/actes", &token_alice).await;
    assert_eq!(status, StatusCode::OK);

    let _ = sn_notaire; // suppress unused warning
}

// ─── Tests — messages ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_send_and_list_messages() {
    let app = TestApp::new().await;
    let (_kp, _sn_n, cert_notaire) = app.enroll_user("Notaire").await;
    let (kp_alice, sn_alice, cert_alice) = app.enroll_user("Alice").await;
    let token_notaire = app.authenticate(&cert_notaire).await;
    let token_alice = app.authenticate(&cert_alice).await;

    let (_, acte) = app
        .post_json_authed(
            "/actes",
            &token_notaire,
            &json!({ "titre": "Msgs test", "parties": [sn_alice] }),
        )
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    let now = now_ts();
    let (c_msg, nonce, sig) = signed_message_body(0, &kp_alice.signing_key, &sn_alice, &acte_id, now);

    let (status, msg) = app
        .post_json_authed(
            &format!("/actes/{acte_id}/messages"),
            &token_alice,
            &json!({ "c_message": c_msg, "nonce": nonce, "signature": sig, "timestamp": now }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "send_message failed: {msg}");
    assert_eq!(msg["seq"], 0);
    assert_eq!(msg["sender_sn"].as_str().unwrap(), sn_alice);

    // List — Alice reads her message back
    let (status, list) = app
        .get_authed(&format!("/actes/{acte_id}/messages"), &token_alice)
        .await;
    assert_eq!(status, StatusCode::OK);
    let msgs = list.as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["seq"], 0);
    assert_eq!(msgs[0]["c_message"].as_str().unwrap(), c_msg);
}

#[tokio::test]
async fn test_seq_is_monotone() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Notaire").await;
    let (kp2, sn2, cert2) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert).await;
    let token2 = app.authenticate(&cert2).await;

    let (_, acte) = app
        .post_json_authed("/actes", &token, &json!({ "titre": "Seq", "parties": [sn2] }))
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    for i in 0u8..3 {
        let ts = now_ts() + i as i64;
        let (c, n, s) = signed_message_body(i, &kp2.signing_key, &sn2, &acte_id, ts);
        let (status, msg) = app
            .post_json_authed(
                &format!("/actes/{acte_id}/messages"),
                &token2,
                &json!({ "c_message": c, "nonce": n, "signature": s, "timestamp": ts }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "msg {i} failed: {msg}");
        assert_eq!(msg["seq"], i as i64, "seq must be monotone");
    }
}

#[tokio::test]
async fn test_after_seq_filtering() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Notaire").await;
    let (kp2, sn2, cert2) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert).await;
    let token2 = app.authenticate(&cert2).await;

    let (_, acte) = app
        .post_json_authed("/actes", &token, &json!({ "titre": "Filter", "parties": [sn2] }))
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    // Send 3 messages
    for i in 0u8..3 {
        let ts = now_ts();
        let (c, n, s) = signed_message_body(i, &kp2.signing_key, &sn2, &acte_id, ts);
        app.post_json_authed(
            &format!("/actes/{acte_id}/messages"),
            &token2,
            &json!({ "c_message": c, "nonce": n, "signature": s, "timestamp": ts }),
        )
        .await;
    }

    // GET ?after_seq=0 should return only seq=1 and seq=2
    let (status, list) = app
        .get_authed(&format!("/actes/{acte_id}/messages?after_seq=0"), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    let msgs = list.as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["seq"], 1);
    assert_eq!(msgs[1]["seq"], 2);
}

#[tokio::test]
async fn test_non_participant_cannot_send_message() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert_notaire) = app.enroll_user("Notaire").await;
    let (_kp2, sn_alice, _cert_alice) = app.enroll_user("Alice").await;
    let (_kp3, _sn_eve, cert_eve) = app.enroll_user("Eve").await;
    let token_notaire = app.authenticate(&cert_notaire).await;
    let token_eve = app.authenticate(&cert_eve).await;

    let (_, acte) = app
        .post_json_authed(
            "/actes",
            &token_notaire,
            &json!({ "titre": "Private", "parties": [sn_alice] }),
        )
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    let (c, n, s) = fake_message_body(0);
    // Eve is not a participant — should be refused
    let (status, _) = app
        .post_json_authed(
            &format!("/actes/{acte_id}/messages"),
            &token_eve,
            &json!({ "c_message": c, "nonce": n, "signature": s, "timestamp": now_ts() }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Tests — merkle log ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_merkle_root_empty() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Notaire").await;
    let (_kp2, sn2, _cert2) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert).await;

    let (_, acte) = app
        .post_json_authed("/actes", &token, &json!({ "titre": "Merkle", "parties": [sn2] }))
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    let (status, merkle) = app.get_authed(&format!("/actes/{acte_id}/merkle"), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(merkle["root"].is_null(), "empty log has no root");
    assert_eq!(merkle["leaves_count"], 0);
}

#[tokio::test]
async fn test_merkle_root_after_messages() {
    let app = TestApp::new().await;
    let (_kp, _sn, cert) = app.enroll_user("Notaire").await;
    let (kp2, sn2, cert2) = app.enroll_user("Alice").await;
    let token = app.authenticate(&cert).await;
    let token2 = app.authenticate(&cert2).await;

    let (_, acte) = app
        .post_json_authed("/actes", &token, &json!({ "titre": "Merkle2", "parties": [sn2] }))
        .await;
    let acte_id = acte["uuid"].as_str().unwrap().to_owned();

    for i in 0u8..2 {
        let ts = now_ts();
        let (c, n, s) = signed_message_body(i, &kp2.signing_key, &sn2, &acte_id, ts);
        app.post_json_authed(
            &format!("/actes/{acte_id}/messages"),
            &token2,
            &json!({ "c_message": c, "nonce": n, "signature": s, "timestamp": ts }),
        )
        .await;
    }

    let (status, merkle) = app.get_authed(&format!("/actes/{acte_id}/merkle"), &token).await;
    assert_eq!(status, StatusCode::OK);
    let root = merkle["root"].as_str().expect("root must be present after messages");
    assert_eq!(root.len(), 64, "root is a 32-byte value hex-encoded");
    assert_eq!(merkle["leaves_count"], 2);
}
