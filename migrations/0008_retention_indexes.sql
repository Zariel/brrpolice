CREATE INDEX idx_peer_sessions_last_seen
    ON peer_sessions (last_seen_at);

CREATE INDEX idx_peer_policy_sessions_last_seen
    ON peer_policy_sessions (last_seen_at);

-- SQLite appends rowid to this index, including the latest-offence tie breaker.
CREATE INDEX idx_peer_offences_identity_time
    ON peer_offences (torrent_hash, peer_ip, policy_name, banned_at);

CREATE INDEX idx_peer_offences_banned_at
    ON peer_offences (banned_at);

-- Enforcement protects history across peer ports and policies.
CREATE INDEX idx_active_bans_unreconciled_scope_ip
    ON active_bans (scope, peer_ip) WHERE reconciled_at IS NULL;

CREATE INDEX idx_active_bans_reconciled_at
    ON active_bans (reconciled_at) WHERE reconciled_at IS NOT NULL;

CREATE INDEX idx_pending_ban_intents_expires_at
    ON pending_ban_intents (ban_expires_at);
