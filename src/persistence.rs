use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tracing::info;

use crate::config::DatabaseConfig;

#[derive(Clone)]
pub struct Persistence {
    pool: SqlitePool,
}

impl Persistence {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        let url = if config.path == std::path::Path::new(":memory:") {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite://{}", config.path.display())
        };
        let pool = SqlitePoolOptions::new().connect(&url).await?;
        sqlx::query("PRAGMA journal_mode = WAL;")
            .execute(&pool)
            .await?;
        sqlx::query(&format!(
            "PRAGMA busy_timeout = {};",
            config.busy_timeout.as_millis()
        ))
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
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
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO service_meta (id, schema_version, service_version, config_hash, updated_at)
            VALUES (1, 1, '0.1.0', 'bootstrap', datetime('now'))
            ON CONFLICT(id) DO UPDATE SET
                schema_version = excluded.schema_version,
                service_version = excluded.service_version,
                config_hash = excluded.config_hash,
                updated_at = excluded.updated_at
            "#,
        )
        .execute(&self.pool)
        .await?;

        info!("sqlite bootstrap migration applied");
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}
