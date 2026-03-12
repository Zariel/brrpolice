ALTER TABLE peer_sessions ADD COLUMN ban_score REAL NOT NULL DEFAULT 0;
ALTER TABLE peer_sessions ADD COLUMN ban_score_above_seconds INTEGER NOT NULL DEFAULT 0;
