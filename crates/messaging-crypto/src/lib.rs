// messaging-crypto — notarial messaging cryptography.
// Pure library: no I/O. Depends only on localpki-core for key types.

pub mod error;
pub mod keys;
pub mod messages;
pub mod merkle;

pub use error::CryptoError;
pub use keys::{EciesCiphertext, derive_k_acte, derive_k_send, ecies_decrypt, ecies_encrypt};
pub use messages::{
    EncryptedMessage, decrypt_message, encrypt_message, sign_message, verify_message_signature,
};
pub use merkle::{MerkleLog, MerkleProof};
