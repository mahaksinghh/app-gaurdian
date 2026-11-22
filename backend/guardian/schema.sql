CREATE TABLE IF NOT EXISTS guardian_accounts (
    id uuid PRIMARY KEY,
    login_hash bytea UNIQUE NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS guardian_devices (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES guardian_accounts(id) ON DELETE CASCADE,
    secret_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (id, account_id)
);

CREATE INDEX IF NOT EXISTS guardian_devices_account_idx ON guardian_devices(account_id);

CREATE TABLE IF NOT EXISTS guardian_sessions (
    token_hash bytea PRIMARY KEY,
    device_id uuid NOT NULL,
    account_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (device_id, account_id) REFERENCES guardian_devices(id, account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS guardian_sessions_device_idx ON guardian_sessions(device_id);
CREATE INDEX IF NOT EXISTS guardian_sessions_expiry_idx ON guardian_sessions(expires_at);

CREATE TABLE IF NOT EXISTS guardian_scans (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL,
    account_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    sealed_report bytea NOT NULL,
    shared_with_account boolean NOT NULL DEFAULT false,
    FOREIGN KEY (device_id, account_id) REFERENCES guardian_devices(id, account_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS guardian_scan_device_created_idx ON guardian_scans(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS guardian_scan_expiry_idx ON guardian_scans(expires_at);

ALTER TABLE guardian_scans ADD COLUMN IF NOT EXISTS shared_with_account boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS guardian_scan_shared_idx ON guardian_scans(account_id, created_at DESC)
    WHERE shared_with_account;
