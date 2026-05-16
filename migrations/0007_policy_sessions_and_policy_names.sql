ALTER TABLE peer_offences ADD COLUMN policy_name TEXT NOT NULL DEFAULT 'score';

CREATE TABLE IF NOT EXISTS peer_policy_sessions (
    policy_name TEXT NOT NULL,
    torrent_hash TEXT NOT NULL,
    peer_key TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    observed_seconds INTEGER NOT NULL,
    bad_seconds INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    last_uploaded_bytes INTEGER,
    last_upload_rate_bps INTEGER NOT NULL,
    last_exemption_reason TEXT,
    state_json TEXT NOT NULL DEFAULT '{}',
    policy_version TEXT NOT NULL,
    bannable_since TEXT,
    last_ban_decision_at TEXT,
    PRIMARY KEY (policy_name, torrent_hash, peer_key)
);

CREATE TABLE pending_ban_intents_new (
    torrent_hash TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    policy_name TEXT NOT NULL,
    offence_number INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ban_expires_at TEXT NOT NULL,
    bad_seconds INTEGER NOT NULL,
    progress_delta REAL NOT NULL,
    avg_up_rate_bps INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    PRIMARY KEY (torrent_hash, peer_ip, peer_port, policy_name, offence_number)
);

INSERT INTO pending_ban_intents_new (
    torrent_hash,
    peer_ip,
    peer_port,
    policy_name,
    offence_number,
    reason_code,
    observed_at,
    ban_expires_at,
    bad_seconds,
    progress_delta,
    avg_up_rate_bps,
    last_error
)
SELECT
    torrent_hash,
    peer_ip,
    peer_port,
    'score',
    offence_number,
    reason_code,
    observed_at,
    ban_expires_at,
    bad_seconds,
    progress_delta,
    avg_up_rate_bps,
    last_error
FROM pending_ban_intents;

DROP TABLE pending_ban_intents;
ALTER TABLE pending_ban_intents_new RENAME TO pending_ban_intents;
