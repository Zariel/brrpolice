CREATE TABLE IF NOT EXISTS pending_ban_intents (
    torrent_hash TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    offence_number INTEGER NOT NULL,
    reason_code TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ban_expires_at TEXT NOT NULL,
    bad_seconds INTEGER NOT NULL,
    progress_delta REAL NOT NULL,
    avg_up_rate_bps INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    PRIMARY KEY (torrent_hash, peer_ip, peer_port, offence_number)
);
