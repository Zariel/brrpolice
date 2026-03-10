use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use sqlx::{
    Row, SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqliteJournalMode,
    sqlite::SqlitePoolOptions,
};
use tracing::info;

use crate::config::DatabaseConfig;

const CURRENT_SCHEMA_VERSION: i64 = 1;

#[derive(Clone)]
pub struct Persistence {
    pool: SqlitePool,
    migrations_succeeded: Arc<AtomicBool>,
}

impl Persistence {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        if config.path != Path::new(":memory:") {
            if let Some(parent) = config.path.parent() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!("failed to create database directory `{}`", parent.display())
                })?;
            }
        }

        let connect_options = if config.path == Path::new(":memory:") {
            SqliteConnectOptions::new()
                .filename(":memory:")
                .create_if_missing(true)
        } else {
            SqliteConnectOptions::new()
                .filename(&config.path)
                .create_if_missing(true)
        }
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(config.busy_timeout);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options)
            .await?;

        Ok(Self {
            pool,
            migrations_succeeded: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        self.migrations_succeeded.store(false, Ordering::Relaxed);

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&mut *tx)
        .await?;

        let max_version =
            sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM schema_migrations")
                .fetch_one(&mut *tx)
                .await?
                .unwrap_or(0);

        if max_version > CURRENT_SCHEMA_VERSION {
            bail!(
                "database schema version {} is newer than supported version {}",
                max_version,
                CURRENT_SCHEMA_VERSION
            );
        }

        if max_version < 1 {
            apply_migration_1(&mut tx).await?;
            sqlx::query(
                r#"
                INSERT INTO schema_migrations (version, description)
                VALUES (1, 'initial schema')
                "#,
            )
            .execute(&mut *tx)
            .await?;
        }

        upsert_service_meta(&mut tx).await?;
        tx.commit().await?;

        self.migrations_succeeded.store(true, Ordering::Relaxed);
        info!(
            schema_version = CURRENT_SCHEMA_VERSION,
            "migration complete"
        );
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        if !self.migrations_succeeded.load(Ordering::Relaxed) {
            return false;
        }

        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}

async fn apply_migration_1(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
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
        )
        "#,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
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
        )
        "#,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
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
        )
        "#,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS service_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            schema_version INTEGER NOT NULL,
            service_version TEXT NOT NULL,
            config_hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn upsert_service_meta(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    let existing_version = sqlx::query("SELECT schema_version FROM service_meta WHERE id = 1")
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| row.get::<i64, _>("schema_version"));

    if let Some(version) = existing_version {
        if version > CURRENT_SCHEMA_VERSION {
            bail!(
                "service_meta schema version {} is newer than supported version {}",
                version,
                CURRENT_SCHEMA_VERSION
            );
        }
    }

    sqlx::query(
        r#"
        INSERT INTO service_meta (id, schema_version, service_version, config_hash, updated_at)
        VALUES (1, ?, '0.1.0', 'bootstrap', datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            schema_version = excluded.schema_version,
            service_version = excluded.service_version,
            config_hash = excluded.config_hash,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(CURRENT_SCHEMA_VERSION)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use super::{CURRENT_SCHEMA_VERSION, Persistence};
    use crate::config::DatabaseConfig;

    #[tokio::test]
    async fn migrations_create_expected_tables_and_readiness() {
        let persistence = test_persistence().await;

        persistence.run_migrations().await.unwrap();

        assert!(persistence.is_ready().await);

        for table in [
            "schema_migrations",
            "peer_sessions",
            "peer_offences",
            "active_bans",
            "service_meta",
        ] {
            let exists = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(&persistence.pool)
            .await
            .unwrap();
            assert_eq!(exists, 1, "expected table `{table}` to exist");
        }
    }

    #[tokio::test]
    async fn migrations_fail_on_newer_schema_version() {
        let persistence = test_persistence().await;

        sqlx::query(
            r#"
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&persistence.pool)
        .await
        .unwrap();

        sqlx::query("INSERT INTO schema_migrations (version, description) VALUES (?, 'future')")
            .bind(CURRENT_SCHEMA_VERSION + 1)
            .execute(&persistence.pool)
            .await
            .unwrap();

        let error = persistence.run_migrations().await.unwrap_err();
        assert!(error.to_string().contains("newer than supported version"));
        assert!(!persistence.is_ready().await);
    }

    async fn test_persistence() -> Persistence {
        Persistence::connect(&DatabaseConfig {
            path: PathBuf::from(":memory:"),
            busy_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap()
    }
}
