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

#[cfg(test)]
mod tests {
    use localpki_core::{KeyPair, SerialNumber};
    use uuid::Uuid;

    use super::*;

    fn sn(b: u8) -> SerialNumber {
        SerialNumber([b; 16])
    }

    fn keypair() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    // --- Key derivation ---

    #[test]
    fn derive_k_acte_is_deterministic() {
        let master = [1u8; 32];
        let uuid = Uuid::new_v4();
        assert_eq!(derive_k_acte(&master, &uuid), derive_k_acte(&master, &uuid));
    }

    #[test]
    fn derive_k_acte_differs_per_uuid() {
        let master = [1u8; 32];
        assert_ne!(
            derive_k_acte(&master, &Uuid::new_v4()),
            derive_k_acte(&master, &Uuid::new_v4()),
        );
    }

    #[test]
    fn derive_k_send_differs_per_sn() {
        let k_acte = [2u8; 32];
        assert_ne!(derive_k_send(&k_acte, &sn(1)), derive_k_send(&k_acte, &sn(2)));
    }

    // --- ECIES ---

    #[test]
    fn ecies_round_trip() {
        let kp = keypair();
        let x25519_pk = kp.to_x25519_public();
        let x25519_sk = zeroize::Zeroizing::new(kp.to_x25519_static_secret());

        let plaintext = b"K_acte secret";
        let ct = ecies_encrypt(&x25519_pk, plaintext).unwrap();
        let recovered = ecies_decrypt(&x25519_sk, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn ecies_wrong_key_fails() {
        let kp = keypair();
        let other = keypair();
        let x25519_pk = kp.to_x25519_public();
        let wrong_sk = zeroize::Zeroizing::new(other.to_x25519_static_secret());

        let ct = ecies_encrypt(&x25519_pk, b"secret").unwrap();
        assert!(ecies_decrypt(&wrong_sk, &ct).is_err());
    }

    // --- Messages ---

    #[test]
    fn message_encrypt_decrypt_round_trip() {
        let k_acte = [3u8; 32];
        let sender = sn(10);
        let uuid = Uuid::new_v4();
        let timestamp = 1_700_000_000i64;
        let plaintext = b"Bonjour maitre";

        let (ciphertext, nonce) =
            encrypt_message(&k_acte, plaintext, &uuid, &sender, timestamp).unwrap();
        let recovered =
            decrypt_message(&k_acte, &sender, &ciphertext, &nonce, &uuid, timestamp).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn message_wrong_aad_fails_decryption() {
        let k_acte = [3u8; 32];
        let sender = sn(10);
        let uuid = Uuid::new_v4();
        let plaintext = b"secret";

        let (ciphertext, nonce) =
            encrypt_message(&k_acte, plaintext, &uuid, &sender, 1000).unwrap();
        // Different timestamp → different AAD → GCM authentication fails.
        assert!(decrypt_message(&k_acte, &sender, &ciphertext, &nonce, &uuid, 9999).is_err());
    }

    #[test]
    fn sign_and_verify_message() {
        let kp = keypair();
        let sender = sn(20);
        let uuid = Uuid::new_v4();
        let timestamp = 1_700_000_000i64;
        let plaintext = b"acte notarial";

        let sig = sign_message(&kp.signing_key, plaintext, &uuid, &sender, timestamp);
        assert!(
            verify_message_signature(&kp.verifying_key, plaintext, &uuid, &sender, timestamp, &sig)
                .is_ok()
        );
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = keypair();
        let sender = sn(20);
        let uuid = Uuid::new_v4();
        let timestamp = 1_700_000_000i64;

        let sig = sign_message(&kp.signing_key, b"original", &uuid, &sender, timestamp);
        assert!(
            verify_message_signature(&kp.verifying_key, b"tampered", &uuid, &sender, timestamp, &sig)
                .is_err()
        );
    }

    // --- Merkle ---

    #[test]
    fn merkle_empty_root_is_none() {
        assert!(MerkleLog::new().root().is_none());
    }

    #[test]
    fn merkle_single_leaf_root_equals_leaf() {
        let kp = keypair();
        let uuid = Uuid::new_v4();
        let mut log = MerkleLog::new();
        let sig = sign_message(&kp.signing_key, b"msg", &uuid, &sn(1), 1000);

        let leaf = log.add_leaf(&sig, &uuid, 1000, 0);
        assert_eq!(log.root().unwrap(), leaf);
    }

    #[test]
    fn merkle_proof_verifies() {
        let kp = keypair();
        let uuid = Uuid::new_v4();
        let mut log = MerkleLog::new();

        for (i, msg) in [b"msg0" as &[u8], b"msg1", b"msg2", b"msg3"].iter().enumerate() {
            let sig = sign_message(&kp.signing_key, msg, &uuid, &sn(1), i as i64);
            log.add_leaf(&sig, &uuid, i as i64, i as u64);
        }

        let root = log.root().unwrap();
        for i in 0..4 {
            let proof = log.proof(i).unwrap();
            let _leaf = log.proof(i).unwrap().leaf_index;
            // Recompute leaf hash to pass to verify_proof.
            let sig = sign_message(&kp.signing_key, [b"msg0", b"msg1", b"msg2", b"msg3"][i], &uuid, &sn(1), i as i64);
            let mut fresh_log = MerkleLog::new();
            let leaf_hash = fresh_log.add_leaf(&sig, &uuid, i as i64, i as u64);
            assert!(MerkleLog::verify_proof(&root, &leaf_hash, &proof), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn merkle_proof_verifies_odd_tree() {
        let kp = keypair();
        let uuid = Uuid::new_v4();
        let messages: &[&[u8]] = &[b"msg0", b"msg1", b"msg2"];
        let mut log = MerkleLog::new();
        let mut leaves = Vec::new();

        for (i, msg) in messages.iter().enumerate() {
            let sig = sign_message(&kp.signing_key, msg, &uuid, &sn(1), i as i64);
            leaves.push(log.add_leaf(&sig, &uuid, i as i64, i as u64));
        }

        let root = log.root().unwrap();
        for i in 0..3 {
            let proof = log.proof(i).unwrap();
            assert!(MerkleLog::verify_proof(&root, &leaves[i], &proof), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn merkle_wrong_root_fails_verification() {
        let kp = keypair();
        let uuid = Uuid::new_v4();
        let mut log = MerkleLog::new();
        let sig = sign_message(&kp.signing_key, b"msg", &uuid, &sn(1), 0);
        let leaf = log.add_leaf(&sig, &uuid, 0, 0);
        let proof = log.proof(0).unwrap();
        let wrong_root = [0u8; 32];
        assert!(!MerkleLog::verify_proof(&wrong_root, &leaf, &proof));
    }
}
