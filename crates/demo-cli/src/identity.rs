use anyhow::Context;
use localpki_core::{
    cert::{LocalPKICert, SerialNumber},
    crypto::KeyPair,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityFile {
    pub name: String,
    /// hex(SN[16]) — identifiant public enregistré en DB
    pub sn_hex: String,
    /// hex(sk[32]) — clé privée, jamais transmise au serveur
    pub signing_key_hex: String,
    pub cert: LocalPKICert,
    pub session_token: Option<String>,
}

impl IdentityFile {
    pub fn from_keypair_and_cert(name: &str, kp: &KeyPair, cert: LocalPKICert) -> Self {
        Self {
            name: name.to_string(),
            sn_hex: hex::encode(cert.tbs.serial_number.0),
            signing_key_hex: hex::encode(kp.signing_key.to_bytes()),
            cert,
            session_token: None,
        }
    }

    pub fn signing_key(&self) -> anyhow::Result<ed25519_dalek::SigningKey> {
        let bytes: [u8; 32] = hex::decode(&self.signing_key_hex)
            .context("signing_key_hex: invalid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing_key_hex: expected 32 bytes"))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
    }

    pub fn keypair(&self) -> anyhow::Result<KeyPair> {
        let signing_key = self.signing_key()?;
        let verifying_key = signing_key.verifying_key();
        Ok(KeyPair { signing_key, verifying_key })
    }

    pub fn serial_number(&self) -> anyhow::Result<SerialNumber> {
        let bytes: [u8; 16] = hex::decode(&self.sn_hex)
            .context("sn_hex: invalid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("sn_hex: expected 16 bytes"))?;
        Ok(SerialNumber(bytes))
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write identity file: {path}"))?;
        Ok(())
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read identity file: {path}"))?;
        serde_json::from_str(&json).with_context(|| format!("failed to parse identity file: {path}"))
    }
}
