CREATE TABLE IF NOT EXISTS peer_sessions (
    torrent_hash TEXT NOT NULL,
    peer_key TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    client_name TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    baseline_progress REAL NOT NULL,
    latest_progress REAL NOT NULL,
    rolling_avg_up_rate_bps INTEGER NOT NULL,
    observed_seconds INTEGER NOT NULL,
    bad_seconds INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    last_torrent_seeder_count INTEGER NOT NULL,
    last_exemption_reason TEXT,
    policy_version TEXT NOT NULL,
    PRIMARY KEY (torrent_hash, peer_key)
);

CREATE TABLE IF NOT EXISTS peer_offences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    torrent_hash TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    offence_number INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    observed_seconds INTEGER NOT NULL,
    bad_seconds INTEGER NOT NULL,
    progress_delta REAL NOT NULL,
    avg_up_rate_bps INTEGER NOT NULL,
    banned_at TEXT NOT NULL,
    ban_expires_at TEXT NOT NULL,
    ban_revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS active_bans (
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    scope TEXT NOT NULL,
    offence_number INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    reconciled_at TEXT,
    PRIMARY KEY (peer_ip, peer_port, scope)
);

CREATE TABLE IF NOT EXISTS service_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    service_version TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
