ALTER TABLE peer_sessions ADD COLUMN churn_reconnect_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE peer_sessions ADD COLUMN churn_penalty REAL NOT NULL DEFAULT 0;
ALTER TABLE peer_sessions ADD COLUMN churn_window_started_at TEXT;
