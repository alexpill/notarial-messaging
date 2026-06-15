// In production, replace with a PKCS#11 client for a real HSM.
// For this PoC, K_master is loaded from HSM_MASTER_KEY_HEX at startup and never leaves this struct.

use crate::error::AppError;
use hkdf::Hkdf;
use messaging_crypto::{keys::EciesCiphertext, keys::ecies_decrypt, CryptoError};
use sha2::Sha256;
use zeroize::Zeroizing;

pub struct HsmSimulator {
    master_key: Zeroizing<[u8; 32]>,
}

impl HsmSimulator {
    pub fn from_env() -> Result<Self, AppError> {
        let hex = std::env::var("HSM_MASTER_KEY_HEX")
            .map_err(|_| AppError::Config("HSM_MASTER_KEY_HEX: missing".to_string()))?;

        if hex.len() != 64 {
            return Err(AppError::Config(
                "HSM_MASTER_KEY_HEX: must be exactly 64 hex chars".to_string(),
            ));
        }

        let bytes = hex::decode(&hex)
            .map_err(|_| AppError::Config("HSM_MASTER_KEY_HEX: malformed hex".to_string()))?;

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);

        tracing::info!("HSM simulator initialized");
        Ok(Self { master_key: key })
    }

    /// Only invoked at acte creation (POST /actes).
    pub fn derive_k_acte(&self, acte_uuid: &uuid::Uuid) -> [u8; 32] {
        messaging_crypto::keys::derive_k_acte(&self.master_key, acte_uuid)
    }

    /// Returns the HSM's X25519 public key — used by POST /actes to encrypt C_archive.
    pub fn x25519_public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(&*self.derive_hsm_x25519_sk())
    }

    /// Decrypts C_acte_archive → K_acte.
    /// Only needed when adding a participant (POST /actes/:id/participants) or for legal recovery.
    pub fn decrypt_archive(&self, ciphertext: &EciesCiphertext) -> Result<[u8; 32], CryptoError> {
        let sk = self.derive_hsm_x25519_sk();
        let plaintext = ecies_decrypt(&sk, ciphertext)?;
        plaintext
            .try_into()
            .map_err(|_| CryptoError::Decryption)
    }

    /// Derives a stable X25519 static secret from K_master.
    /// Kept separate from K_master so the HSM signing key is domain-separated.
    fn derive_hsm_x25519_sk(&self) -> Zeroizing<x25519_dalek::StaticSecret> {
        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, self.master_key.as_ref())
            .expand(b"notariat-hsm-x25519-v1", sk_bytes.as_mut())
            .expect("32 bytes is always a valid HKDF output length");
        Zeroizing::new(x25519_dalek::StaticSecret::from(*sk_bytes))
    }
}
