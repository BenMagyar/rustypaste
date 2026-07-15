CREATE TABLE principals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('oidc', 'service', 'legacy')),
    issuer TEXT,
    subject TEXT,
    stable_name TEXT,
    email TEXT,
    display_name TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    can_delete_all INTEGER NOT NULL DEFAULT 0 CHECK (can_delete_all IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    CHECK (
        (kind = 'oidc' AND issuer IS NOT NULL AND subject IS NOT NULL AND stable_name IS NULL)
        OR (kind IN ('service', 'legacy') AND issuer IS NULL AND subject IS NULL AND stable_name IS NOT NULL)
    )
);

CREATE UNIQUE INDEX principals_oidc_identity
    ON principals (issuer, subject)
    WHERE kind = 'oidc';

CREATE UNIQUE INDEX principals_named_identity
    ON principals (kind, stable_name)
    WHERE kind IN ('service', 'legacy');

CREATE TABLE browser_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX browser_sessions_principal ON browser_sessions (principal_id);
CREATE INDEX browser_sessions_expiry ON browser_sessions (expires_at);

CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    label TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX api_tokens_principal ON api_tokens (principal_id);
CREATE INDEX api_tokens_expiry ON api_tokens (expires_at);

CREATE TABLE oauth_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_hash BLOB NOT NULL UNIQUE,
    code_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX oauth_flows_expiry ON oauth_flows (expires_at);

CREATE TABLE cli_device_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_code_hash BLOB NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    client_name TEXT NOT NULL,
    approved_principal_id INTEGER REFERENCES principals(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    poll_interval_seconds INTEGER NOT NULL,
    last_polled_at INTEGER,
    approved_at INTEGER,
    delivered_at INTEGER
);

CREATE INDEX cli_device_flows_expiry ON cli_device_flows (expires_at);

CREATE TABLE pastes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_principal_id INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    public_filename TEXT NOT NULL,
    storage_path TEXT NOT NULL UNIQUE,
    paste_type TEXT NOT NULL CHECK (
        paste_type IN ('file', 'remote_file', 'oneshot', 'url', 'oneshot_url', 'protected_file')
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    expires_at INTEGER,
    content_hash TEXT NOT NULL,
    dedup_key TEXT
);

CREATE INDEX pastes_owner_created ON pastes (owner_principal_id, created_at DESC);
CREATE INDEX pastes_public_filename ON pastes (public_filename);
CREATE INDEX pastes_expiry ON pastes (expires_at);
CREATE INDEX pastes_owner_hash ON pastes (owner_principal_id, content_hash);
CREATE UNIQUE INDEX pastes_owner_dedup
    ON pastes (owner_principal_id, dedup_key)
    WHERE owner_principal_id IS NOT NULL AND dedup_key IS NOT NULL;
