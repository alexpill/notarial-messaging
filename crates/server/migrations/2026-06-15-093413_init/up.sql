-- LocalPKI EN registry. Paper §2: notaries store the signed hash of the
-- certificate and its serial number — we extend this with `pk` (needed to
-- verify message signatures), `subject_id` (display label, kept out of the
-- cryptographic core), and `tbs_der` (the exact bytes that were signed at
-- enrollment time, so SI verification is robust to x509-cert version drift —
-- the encoding is frozen at enrollment, never recomputed).
CREATE TABLE identities (
    sn            TEXT   NOT NULL PRIMARY KEY,
    si            TEXT   NOT NULL,
    pk            TEXT   NOT NULL,
    tbs_der       TEXT   NOT NULL,
    subject_id    TEXT   NOT NULL,
    lra_id        TEXT   NOT NULL,
    registered_at BIGINT NOT NULL,
    revoked_at    BIGINT
);

CREATE TABLE actes (
    uuid            TEXT    NOT NULL PRIMARY KEY,
    titre           TEXT    NOT NULL,
    notaire_sn      TEXT    NOT NULL REFERENCES identities(sn),
    created_at      BIGINT  NOT NULL,
    closed_at       BIGINT,
    c_acte_archive  TEXT    NOT NULL
);

CREATE TABLE acte_participants (
    acte_uuid       TEXT    NOT NULL REFERENCES actes(uuid),
    participant_sn  TEXT    NOT NULL REFERENCES identities(sn),
    c_acte_key      TEXT    NOT NULL,
    added_at        BIGINT  NOT NULL,
    added_by_sn     TEXT    NOT NULL,
    history_from    BIGINT,
    PRIMARY KEY (acte_uuid, participant_sn)
);

CREATE TABLE messages (
    id          TEXT    NOT NULL PRIMARY KEY,
    acte_uuid   TEXT    NOT NULL REFERENCES actes(uuid),
    sender_sn   TEXT    NOT NULL REFERENCES identities(sn),
    c_message   TEXT    NOT NULL,
    nonce       TEXT    NOT NULL,
    signature   TEXT    NOT NULL,
    seq         BIGINT  NOT NULL,
    sent_at     BIGINT  NOT NULL
);

CREATE UNIQUE INDEX messages_acte_seq ON messages(acte_uuid, seq);

CREATE TABLE merkle_log (
    id          INTEGER PRIMARY KEY,
    acte_uuid   TEXT    NOT NULL REFERENCES actes(uuid),
    message_id  TEXT    NOT NULL REFERENCES messages(id),
    leaf_hash   TEXT    NOT NULL,
    -- `parent_hash` historically suggested the previous leaf hash, but in fact
    -- it stores the Merkle root *after* inserting this leaf (hex 32 bytes).
    -- The column name is kept to avoid a migration; semantics are documented
    -- in ARCHITECTURE.md §11.
    parent_hash TEXT,
    en_signature TEXT,
    logged_at   BIGINT  NOT NULL
);
