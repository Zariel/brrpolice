ALTER TABLE peer_sessions ADD COLUMN churn_amplifier REAL NOT NULL DEFAULT 0;
UPDATE peer_sessions SET churn_amplifier = churn_penalty WHERE churn_penalty IS NOT NULL;
