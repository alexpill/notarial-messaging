-- Enforce AES-256-GCM nonce uniqueness per (acte, sender).
-- K_send = HKDF(K_acte, "send" || sender_sn) is fixed for the lifetime of an
-- acte, so every message from a given sender MUST use a fresh nonce — reusing a
-- nonce under the same key is catastrophic for GCM (cf. ARCHITECTURE.md §8.5).
-- As a direct side effect, this rejects byte-for-byte message replay: an
-- identical re-POST reuses the nonce and is refused (409) instead of producing a
-- duplicate leaf in the transparency log (cf. CRYPTO_REVIEW.md §B).
CREATE UNIQUE INDEX messages_acte_sender_nonce ON messages(acte_uuid, sender_sn, nonce);
