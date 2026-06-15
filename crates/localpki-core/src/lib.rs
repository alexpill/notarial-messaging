// localpki-core — LocalPKI protocols (Dumas et al. 2019).
// Pure library: no network, no I/O.

pub mod cert;
pub mod crypto;
pub mod enrollment;
pub mod authentication;
pub mod revocation;
pub mod error;

pub use cert::{LocalPKICert, SerialNumber, SignatureId, TBSCert, Validity};
pub use crypto::KeyPair;
pub use error::LocalPkiError;

#[cfg(test)]
mod tests {
    use super::*;
    use authentication::{
        build_auth_request, respond_to_auth_request, verify_auth_response, AuthStatus, EnDatabase,
    };
    use cert::RegistrationEntry;
    use enrollment::{
        create_self_signed_cert, prepare_lra_to_en_message, register_from_lra_message,
        verify_signature_id, EnrollmentChallenge,
    };
    use revocation::{build_revocation_request, validate_revocation_request};

    fn make_keypair() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    fn make_challenge(sn: SerialNumber) -> EnrollmentChallenge {
        EnrollmentChallenge {
            serial_number: sn,
            en_url: "https://en.example.com".to_string(),
            validity_days: 365,
        }
    }

    fn make_cert(keypair: &KeyPair, sn: SerialNumber) -> LocalPKICert {
        create_self_signed_cert(keypair, "Alice", &make_challenge(sn)).unwrap()
    }

    // Minimal EnDatabase backed by a single entry.
    struct MockDb(Option<RegistrationEntry>);
    impl EnDatabase for MockDb {
        fn lookup(&self, _sn: &SerialNumber) -> Option<RegistrationEntry> {
            self.0.clone()
        }
    }

    // --- Enrollment ---

    #[test]
    fn enrollment_self_signed_cert_is_valid() {
        let kp = make_keypair();
        let sn = SerialNumber([1u8; 16]);
        let cert = make_cert(&kp, sn);
        assert!(verify_signature_id(&cert).is_ok());
    }

    #[test]
    fn enrollment_wrong_key_fails_verify() {
        let kp = make_keypair();
        let other = make_keypair();
        let sn = SerialNumber([2u8; 16]);
        let mut cert = make_cert(&kp, sn);
        // Swap in a different public key — SI no longer matches.
        cert.tbs.public_key = other.verifying_key;
        assert!(verify_signature_id(&cert).is_err());
    }

    #[test]
    fn enrollment_lra_to_en_round_trip() {
        let user_kp = make_keypair();
        let lra_kp = make_keypair();
        let en_kp = make_keypair();
        let sn = SerialNumber([3u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let msg = prepare_lra_to_en_message(&cert, &en_kp.verifying_key, &lra_kp.signing_key)
            .unwrap();
        let entry = register_from_lra_message(&msg, &en_kp, &lra_kp.verifying_key, "lra-1")
            .unwrap();

        assert_eq!(entry.serial_number.0, sn.0);
        assert_eq!(
            entry.signature_id.0.to_bytes(),
            cert.signature_id.0.to_bytes()
        );
        assert!(entry.revoked_at.is_none());
    }

    // --- Authentication ---

    #[test]
    fn auth_valid_cert_returns_ok() {
        let user_kp = make_keypair();
        let en_kp = make_keypair();
        let sn = SerialNumber([4u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let entry = RegistrationEntry {
            serial_number: sn,
            signature_id: cert.signature_id.clone(),
            public_key: user_kp.verifying_key,
            lra_id: "lra-1".to_string(),
            registered_at: 0,
            revoked_at: None,
        };
        let db = MockDb(Some(entry));

        let request = build_auth_request(&cert);
        let response = respond_to_auth_request(&request, &db, &en_kp.signing_key);
        let status = verify_auth_response(&response, &en_kp.verifying_key, &request).unwrap();

        assert_eq!(status, AuthStatus::Ok);
    }

    #[test]
    fn auth_unknown_sn_returns_unknown() {
        let user_kp = make_keypair();
        let en_kp = make_keypair();
        let sn = SerialNumber([5u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let db = MockDb(None);
        let request = build_auth_request(&cert);
        let response = respond_to_auth_request(&request, &db, &en_kp.signing_key);
        let status = verify_auth_response(&response, &en_kp.verifying_key, &request).unwrap();

        assert_eq!(status, AuthStatus::Unknown);
    }

    #[test]
    fn auth_revoked_cert_returns_unknown() {
        let user_kp = make_keypair();
        let en_kp = make_keypair();
        let sn = SerialNumber([6u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let entry = RegistrationEntry {
            serial_number: sn,
            signature_id: cert.signature_id.clone(),
            public_key: user_kp.verifying_key,
            lra_id: "lra-1".to_string(),
            registered_at: 0,
            revoked_at: Some(1_000_000),
        };
        let db = MockDb(Some(entry));

        let request = build_auth_request(&cert);
        let response = respond_to_auth_request(&request, &db, &en_kp.signing_key);
        let status = verify_auth_response(&response, &en_kp.verifying_key, &request).unwrap();

        assert_eq!(status, AuthStatus::Unknown);
    }

    #[test]
    fn auth_tampered_nonce_is_rejected() {
        let user_kp = make_keypair();
        let en_kp = make_keypair();
        let sn = SerialNumber([7u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let entry = RegistrationEntry {
            serial_number: sn,
            signature_id: cert.signature_id.clone(),
            public_key: user_kp.verifying_key,
            lra_id: "lra-1".to_string(),
            registered_at: 0,
            revoked_at: None,
        };
        let db = MockDb(Some(entry));

        let request = build_auth_request(&cert);
        let response = respond_to_auth_request(&request, &db, &en_kp.signing_key);

        let mut other_request = request.clone();
        other_request.nonce = [0u8; 32];

        assert!(verify_auth_response(&response, &en_kp.verifying_key, &other_request).is_err());
    }

    // --- Revocation ---

    #[test]
    fn revocation_user_signature_is_valid() {
        let kp = make_keypair();
        let sn = SerialNumber([8u8; 16]);
        let cert = make_cert(&kp, sn);

        let req = build_revocation_request(&cert, &kp.signing_key);
        assert!(validate_revocation_request(&req, None).is_ok());
    }

    #[test]
    fn revocation_lra_signature_is_valid() {
        let user_kp = make_keypair();
        let lra_kp = make_keypair();
        let sn = SerialNumber([9u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let req = build_revocation_request(&cert, &lra_kp.signing_key);
        assert!(validate_revocation_request(&req, Some(&lra_kp.verifying_key)).is_ok());
    }

    #[test]
    fn revocation_unknown_key_is_rejected() {
        let user_kp = make_keypair();
        let attacker_kp = make_keypair();
        let sn = SerialNumber([10u8; 16]);
        let cert = make_cert(&user_kp, sn);

        let req = build_revocation_request(&cert, &attacker_kp.signing_key);
        assert!(validate_revocation_request(&req, None).is_err());
    }
}
