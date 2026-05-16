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
    PRIMARY KEY (torrent_hash, peer_ip, policy_name, offence_number)
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
    policy_name,
    offence_number,
    reason_code,
    observed_at,
    ban_expires_at,
    bad_seconds,
    progress_delta,
    avg_up_rate_bps,
    last_error
FROM (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY torrent_hash, peer_ip, policy_name, offence_number
            ORDER BY ban_expires_at DESC, observed_at DESC, peer_port DESC
        ) AS rank
    FROM pending_ban_intents
)
WHERE rank = 1;

DROP TABLE pending_ban_intents;
ALTER TABLE pending_ban_intents_new RENAME TO pending_ban_intents;
