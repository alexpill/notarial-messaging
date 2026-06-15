CREATE TABLE sessions (
    token       TEXT    NOT NULL PRIMARY KEY,
    sn          TEXT    NOT NULL REFERENCES identities(sn),
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL
);
