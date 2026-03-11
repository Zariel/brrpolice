ALTER TABLE peer_sessions ADD COLUMN bannable_since TEXT;
ALTER TABLE peer_sessions ADD COLUMN last_ban_decision_at TEXT;
