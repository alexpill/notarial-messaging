use anyhow::Context;
use localpki_core::cert::LocalPKICert;
use reqwest::StatusCode;
use serde_json::{Value, json};

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// POST /enroll — retourne le serial_number hex attribué.
    pub async fn enroll(
        &self,
        cert: &LocalPKICert,
        lra_sn: &str,
        lra_signature_b64: &str,
    ) -> anyhow::Result<String> {
        let body = json!({
            "cert": serde_json::to_value(cert)?,
            "lra_sn": lra_sn,
            "lra_signature": lra_signature_b64,
        });
        let resp = self
            .client
            .post(format!("{}/enroll", self.base_url))
            .json(&body)
            .send()
            .await
            .context("POST /enroll")?;

        let resp = ensure_ok(resp, "POST /enroll").await?;
        let v: Value = resp.json().await?;
        v["serial_number"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("enroll: missing serial_number in response"))
    }

    /// POST /auth/verify — retourne le session token.
    pub async fn authenticate(&self, cert: &LocalPKICert) -> anyhow::Result<String> {
        let body = json!({ "cert": serde_json::to_value(cert)? });
        let resp = self
            .client
            .post(format!("{}/auth/verify", self.base_url))
            .json(&body)
            .send()
            .await
            .context("POST /auth/verify")?;

        let resp = ensure_ok(resp, "POST /auth/verify").await?;
        let v: Value = resp.json().await?;
        if !v["authenticated"].as_bool().unwrap_or(false) {
            return Err(anyhow::anyhow!("authenticate: server returned authenticated=false"));
        }
        v["session_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("authenticate: missing session_token"))
    }

    /// POST /actes — retourne le JSON de l'acte créé.
    pub async fn create_acte(
        &self,
        token: &str,
        titre: &str,
        parties: Vec<String>,
    ) -> anyhow::Result<Value> {
        let body = json!({ "titre": titre, "parties": parties });
        let resp = self
            .client
            .post(format!("{}/actes", self.base_url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .context("POST /actes")?;

        let resp = ensure_ok(resp, "POST /actes").await?;
        Ok(resp.json().await?)
    }

    /// GET /actes/:id/keys — retourne le JSON encodé de `c_acte_key` (EciesCiphertext).
    pub async fn get_acte_key(&self, token: &str, acte_id: &str) -> anyhow::Result<String> {
        let resp = self
            .client
            .get(format!("{}/actes/{}/keys", self.base_url, acte_id))
            .bearer_auth(token)
            .send()
            .await
            .context("GET /actes/:id/keys")?;

        let resp = ensure_ok(resp, "GET /actes/:id/keys").await?;
        let v: Value = resp.json().await?;
        v["c_acte_key"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("get_acte_key: missing c_acte_key"))
    }

    /// POST /actes/:id/messages — envoie un message chiffré.
    pub async fn send_message(
        &self,
        token: &str,
        acte_id: &str,
        c_message_b64: &str,
        nonce_b64: &str,
        signature_b64: &str,
        timestamp: i64,
    ) -> anyhow::Result<Value> {
        let body = json!({
            "c_message": c_message_b64,
            "nonce": nonce_b64,
            "signature": signature_b64,
            "timestamp": timestamp,
        });
        let resp = self
            .client
            .post(format!("{}/actes/{}/messages", self.base_url, acte_id))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .context("POST /actes/:id/messages")?;

        let resp = ensure_ok(resp, "POST /actes/:id/messages").await?;
        Ok(resp.json().await?)
    }

    /// GET /actes/:id/messages — liste les messages chiffrés.
    pub async fn list_messages(&self, token: &str, acte_id: &str) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .client
            .get(format!("{}/actes/{}/messages", self.base_url, acte_id))
            .bearer_auth(token)
            .send()
            .await
            .context("GET /actes/:id/messages")?;

        let resp = ensure_ok(resp, "GET /actes/:id/messages").await?;
        Ok(resp.json().await?)
    }

    /// GET /actes/:id/merkle — retourne la racine Merkle et le nombre de feuilles.
    pub async fn get_merkle(&self, token: &str, acte_id: &str) -> anyhow::Result<Value> {
        let resp = self
            .client
            .get(format!("{}/actes/{}/merkle", self.base_url, acte_id))
            .bearer_auth(token)
            .send()
            .await
            .context("GET /actes/:id/merkle")?;

        let resp = ensure_ok(resp, "GET /actes/:id/merkle").await?;
        Ok(resp.json().await?)
    }

    /// POST /actes/:id/participants — ajoute un participant (notaire seulement).
    #[allow(dead_code)]
    pub async fn add_participant(
        &self,
        token: &str,
        acte_id: &str,
        participant_sn: &str,
        grant_history: bool,
        notaire_signature_b64: &str,
    ) -> anyhow::Result<Value> {
        let body = json!({
            "participant_sn": participant_sn,
            "grant_history": grant_history,
            "notaire_signature": notaire_signature_b64,
        });
        let resp = self
            .client
            .post(format!("{}/actes/{}/participants", self.base_url, acte_id))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .context("POST /actes/:id/participants")?;

        let resp = ensure_ok(resp, "POST /actes/:id/participants").await?;
        Ok(resp.json().await?)
    }
}

async fn ensure_ok(resp: reqwest::Response, label: &str) -> anyhow::Result<reqwest::Response> {
    let status = resp.status();
    if status == StatusCode::OK || status == StatusCode::CREATED {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_else(|_| "(no body)".to_string());
    Err(anyhow::anyhow!("{label}: status {status} — {body}"))
}
