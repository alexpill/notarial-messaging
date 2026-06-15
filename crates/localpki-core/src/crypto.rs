// ED25519/X25519 key pair generation
// We chose to use the same key pair for both signing and encryption.
// This is a bad idea in general, but it is fine for our PoC.
// See ARCHITECTURE.md §8.1 for more details.

use crate::error::LocalPkiError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

/// LocalPKI user's Ed25519 key pair.
/// The private key is wrapped in Zeroizing thanks to the "zeroize" feature and then will be zeroed on drop.
pub struct KeyPair {
    /// Private key
    pub signing_key: SigningKey,
    /// Public key
    pub verifying_key: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, LocalPkiError> {
        let mut os_rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut os_rng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// ED25519 to X25519 conversion using montgomery form for public key.
    pub fn to_x25519_public(&self) -> PublicKey {
        PublicKey::from(self.verifying_key.to_montgomery().to_bytes())
    }

    /// ED25519 to X25519 conversion using scalar form for private key.
    pub fn to_x25519_static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.signing_key.to_scalar_bytes())
    }
}

pub fn verifying_key_to_x25519_public(verifying_key: &VerifyingKey) -> PublicKey {
    PublicKey::from(verifying_key.to_montgomery().to_bytes())
}
