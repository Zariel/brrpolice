use std::{
    net::IpAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use humantime::{format_rfc3339_seconds, parse_rfc3339_weak};
use sqlx::{
    Row, SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqliteJournalMode,
    sqlite::SqlitePoolOptions,
};
use tracing::info;

use crate::{
    config::DatabaseConfig,
    types::{
        BanDecision, ExemptionReason, OffenceIdentity, PeerEvaluation, PeerObservationId,
        PeerSessionState,
    },
};

const CURRENT_SCHEMA_VERSION: i64 = 2;
const DEFAULT_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG_HASH: &str = "bootstrap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMetaRecord {
    pub schema_version: i64,
    pub service_version: String,
    pub config_hash: String,
    pub updated_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveBanRecord {
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub scope: String,
    pub offence_number: u32,
    pub reason: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub reconciled_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOffenceRecord {
    pub id: Option<i64>,
    pub torrent_hash: String,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub offence_number: u32,
    pub reason_code: String,
    pub observed_duration: Duration,
    pub bad_duration: Duration,
    pub progress_delta_per_mille: u32,
    pub avg_up_rate_bps: u64,
    pub banned_at: SystemTime,
    pub ban_expires_at: SystemTime,
    pub ban_revoked_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementWriteResult {
    pub duplicate_suppressed: bool,
    pub offence_id: Option<i64>,
    pub active_ban: Option<ActiveBanRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecoverySnapshot {
    pub service_meta: ServiceMetaRecord,
    pub peer_sessions: Vec<PeerSessionState>,
    pub active_bans: Vec<ActiveBanRecord>,
}

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

        if max_version < 2 {
            apply_migration_2(&mut tx).await?;
            sqlx::query(
                r#"
                INSERT INTO schema_migrations (version, description)
                VALUES (2, 'persist bannable timestamps for peer sessions')
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

    pub async fn load_peer_sessions(&self) -> Result<Vec<PeerSessionState>> {
        let rows = sqlx::query(
            r#"
            SELECT
                torrent_hash,
                peer_key,
                peer_ip,
                peer_port,
                first_seen_at,
                last_seen_at,
                baseline_progress,
                latest_progress,
                rolling_avg_up_rate_bps,
                observed_seconds,
                bad_seconds,
                sample_count,
                last_torrent_seeder_count,
                last_exemption_reason,
                bannable_since,
                last_ban_decision_at
            FROM peer_sessions
            ORDER BY torrent_hash, peer_key
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(decode_peer_session).collect()
    }

    pub async fn get_peer_session(
        &self,
        observation_id: &PeerObservationId,
    ) -> Result<Option<PeerSessionState>> {
        let row = sqlx::query(
            r#"
            SELECT
                torrent_hash,
                peer_key,
                peer_ip,
                peer_port,
                first_seen_at,
                last_seen_at,
                baseline_progress,
                latest_progress,
                rolling_avg_up_rate_bps,
                observed_seconds,
                bad_seconds,
                sample_count,
                last_torrent_seeder_count,
                last_exemption_reason,
                bannable_since,
                last_ban_decision_at
            FROM peer_sessions
            WHERE torrent_hash = ? AND peer_key = ?
            "#,
        )
        .bind(&observation_id.torrent_hash)
        .bind(peer_key(observation_id.peer_ip, observation_id.peer_port))
        .fetch_optional(&self.pool)
        .await?;

        row.map(decode_peer_session).transpose()
    }

    pub async fn upsert_peer_session(
        &self,
        session: &PeerSessionState,
        policy_version: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO peer_sessions (
                torrent_hash,
                peer_key,
                peer_ip,
                peer_port,
                client_name,
                first_seen_at,
                last_seen_at,
                baseline_progress,
                latest_progress,
                rolling_avg_up_rate_bps,
                observed_seconds,
                bad_seconds,
                sample_count,
                last_torrent_seeder_count,
                last_exemption_reason,
                policy_version,
                bannable_since,
                last_ban_decision_at
            )
            VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(torrent_hash, peer_key) DO UPDATE SET
                peer_ip = excluded.peer_ip,
                peer_port = excluded.peer_port,
                first_seen_at = excluded.first_seen_at,
                last_seen_at = excluded.last_seen_at,
                baseline_progress = excluded.baseline_progress,
                latest_progress = excluded.latest_progress,
                rolling_avg_up_rate_bps = excluded.rolling_avg_up_rate_bps,
                observed_seconds = excluded.observed_seconds,
                bad_seconds = excluded.bad_seconds,
                sample_count = excluded.sample_count,
                last_torrent_seeder_count = excluded.last_torrent_seeder_count,
                last_exemption_reason = excluded.last_exemption_reason,
                policy_version = excluded.policy_version,
                bannable_since = excluded.bannable_since,
                last_ban_decision_at = excluded.last_ban_decision_at
            "#,
        )
        .bind(&session.observation_id.torrent_hash)
        .bind(peer_key(
            session.observation_id.peer_ip,
            session.observation_id.peer_port,
        ))
        .bind(session.observation_id.peer_ip.to_string())
        .bind(i64::from(session.observation_id.peer_port))
        .bind(format_system_time(session.first_seen_at))
        .bind(format_system_time(session.last_seen_at))
        .bind(session.baseline_progress)
        .bind(session.latest_progress)
        .bind(i64::try_from(session.rolling_avg_up_rate_bps)?)
        .bind(i64::try_from(session.observed_duration.as_secs())?)
        .bind(i64::try_from(session.bad_duration.as_secs())?)
        .bind(i64::from(session.sample_count))
        .bind(i64::from(session.last_torrent_seeder_count))
        .bind(
            session
                .last_exemption_reason
                .as_ref()
                .map(encode_exemption_reason),
        )
        .bind(policy_version)
        .bind(session.bannable_since.map(format_system_time))
        .bind(session.last_ban_decision_at.map(format_system_time))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_peer_session(&self, observation_id: &PeerObservationId) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM peer_sessions WHERE torrent_hash = ? AND peer_key = ?")
                .bind(&observation_id.torrent_hash)
                .bind(peer_key(observation_id.peer_ip, observation_id.peer_port))
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn get_service_meta(&self) -> Result<Option<ServiceMetaRecord>> {
        let row = sqlx::query(
            r#"
            SELECT schema_version, service_version, config_hash, updated_at
            FROM service_meta
            WHERE id = 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(decode_service_meta).transpose()
    }

    pub async fn update_service_meta(
        &self,
        service_version: &str,
        config_hash: &str,
    ) -> Result<ServiceMetaRecord> {
        let updated_at = SystemTime::now();
        sqlx::query(
            r#"
            INSERT INTO service_meta (id, schema_version, service_version, config_hash, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                schema_version = excluded.schema_version,
                service_version = excluded.service_version,
                config_hash = excluded.config_hash,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(CURRENT_SCHEMA_VERSION)
        .bind(service_version)
        .bind(config_hash)
        .bind(format_system_time(updated_at))
        .execute(&self.pool)
        .await?;

        Ok(ServiceMetaRecord {
            schema_version: CURRENT_SCHEMA_VERSION,
            service_version: service_version.to_string(),
            config_hash: config_hash.to_string(),
            updated_at,
        })
    }

    pub async fn upsert_active_ban(&self, ban: &ActiveBanRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO active_bans (
                peer_ip,
                peer_port,
                scope,
                offence_number,
                reason,
                created_at,
                expires_at,
                reconciled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(peer_ip, peer_port, scope) DO UPDATE SET
                offence_number = excluded.offence_number,
                reason = excluded.reason,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                reconciled_at = excluded.reconciled_at
            "#,
        )
        .bind(ban.peer_ip.to_string())
        .bind(i64::from(ban.peer_port))
        .bind(&ban.scope)
        .bind(i64::from(ban.offence_number))
        .bind(&ban.reason)
        .bind(format_system_time(ban.created_at))
        .bind(format_system_time(ban.expires_at))
        .bind(ban.reconciled_at.map(format_system_time))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn load_active_bans(&self) -> Result<Vec<ActiveBanRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT
                peer_ip,
                peer_port,
                scope,
                offence_number,
                reason,
                created_at,
                expires_at,
                reconciled_at
            FROM active_bans
            ORDER BY expires_at, peer_ip, peer_port, scope
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(decode_active_ban).collect()
    }

    pub async fn list_expired_active_bans(
        &self,
        as_of: SystemTime,
    ) -> Result<Vec<ActiveBanRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT
                peer_ip,
                peer_port,
                scope,
                offence_number,
                reason,
                created_at,
                expires_at,
                reconciled_at
            FROM active_bans
            WHERE expires_at <= ? AND reconciled_at IS NULL
            ORDER BY expires_at, peer_ip, peer_port, scope
            "#,
        )
        .bind(format_system_time(as_of))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(decode_active_ban).collect()
    }

    pub async fn mark_active_ban_reconciled(
        &self,
        peer_ip: IpAddr,
        peer_port: u16,
        scope: &str,
        reconciled_at: SystemTime,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE active_bans
            SET reconciled_at = ?
            WHERE peer_ip = ? AND peer_port = ? AND scope = ?
            "#,
        )
        .bind(format_system_time(reconciled_at))
        .bind(peer_ip.to_string())
        .bind(i64::from(peer_port))
        .bind(scope)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_active_ban(
        &self,
        peer_ip: IpAddr,
        peer_port: u16,
        scope: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM active_bans WHERE peer_ip = ? AND peer_port = ? AND scope = ?",
        )
        .bind(peer_ip.to_string())
        .bind(i64::from(peer_port))
        .bind(scope)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn record_ban_enforcement(
        &self,
        evaluation: &PeerEvaluation,
        decision: &BanDecision,
        enforced_at: SystemTime,
    ) -> Result<EnforcementWriteResult> {
        let mut tx = self.pool.begin().await?;
        let existing = sqlx::query(
            r#"
            SELECT
                torrent_hash,
                peer_key,
                peer_ip,
                peer_port,
                first_seen_at,
                last_seen_at,
                baseline_progress,
                latest_progress,
                rolling_avg_up_rate_bps,
                observed_seconds,
                bad_seconds,
                sample_count,
                last_torrent_seeder_count,
                last_exemption_reason,
                policy_version,
                bannable_since,
                last_ban_decision_at
            FROM peer_sessions
            WHERE torrent_hash = ? AND peer_key = ?
            "#,
        )
        .bind(&evaluation.session.observation_id.torrent_hash)
        .bind(peer_key(
            evaluation.session.observation_id.peer_ip,
            evaluation.session.observation_id.peer_port,
        ))
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            let session = decode_peer_session(row)?;
            if session.last_ban_decision_at.is_some() {
                tx.commit().await?;
                return Ok(EnforcementWriteResult {
                    duplicate_suppressed: true,
                    offence_id: None,
                    active_ban: None,
                });
            }
        }

        let mut updated_session = evaluation.session.clone();
        updated_session.last_ban_decision_at = Some(enforced_at);
        upsert_peer_session_tx(&mut tx, &updated_session, "policy-v1").await?;

        let offence = PeerOffenceRecord {
            id: None,
            torrent_hash: updated_session.observation_id.torrent_hash.clone(),
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            offence_number: decision.offence_number,
            reason_code: decision.reason.clone(),
            observed_duration: updated_session.observed_duration,
            bad_duration: updated_session.bad_duration,
            progress_delta_per_mille: progress_delta_per_mille(evaluation.progress_delta),
            avg_up_rate_bps: updated_session.rolling_avg_up_rate_bps,
            banned_at: enforced_at,
            ban_expires_at: enforced_at + decision.ttl,
            ban_revoked_at: None,
        };
        let offence_id = insert_peer_offence_tx(&mut tx, &offence).await?;

        let active_ban = ActiveBanRecord {
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            scope: format!("torrent:{}", updated_session.observation_id.torrent_hash),
            offence_number: decision.offence_number,
            reason: decision.reason.clone(),
            created_at: enforced_at,
            expires_at: enforced_at + decision.ttl,
            reconciled_at: None,
        };
        upsert_active_ban_tx(&mut tx, &active_ban).await?;

        tx.commit().await?;

        Ok(EnforcementWriteResult {
            duplicate_suppressed: false,
            offence_id: Some(offence_id),
            active_ban: Some(active_ban),
        })
    }

    pub async fn load_recovery_snapshot(&self) -> Result<RecoverySnapshot> {
        let mut tx = self.pool.begin().await?;
        let service_meta = sqlx::query(
            r#"
            SELECT
                schema_version,
                service_version,
                config_hash,
                updated_at
            FROM service_meta
            LIMIT 1
            "#,
        )
        .fetch_one(&mut *tx)
        .await
        .map(decode_service_meta)??;

        let peer_sessions = sqlx::query(
            r#"
            SELECT
                torrent_hash,
                peer_key,
                peer_ip,
                peer_port,
                first_seen_at,
                last_seen_at,
                baseline_progress,
                latest_progress,
                rolling_avg_up_rate_bps,
                observed_seconds,
                bad_seconds,
                sample_count,
                last_torrent_seeder_count,
                last_exemption_reason,
                policy_version,
                bannable_since,
                last_ban_decision_at
            FROM peer_sessions
            ORDER BY torrent_hash, peer_key
            "#,
        )
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(decode_peer_session)
        .collect::<Result<Vec<_>>>()?;

        let active_bans = sqlx::query(
            r#"
            SELECT
                peer_ip,
                peer_port,
                scope,
                offence_number,
                reason,
                created_at,
                expires_at,
                reconciled_at
            FROM active_bans
            ORDER BY expires_at, peer_ip, peer_port, scope
            "#,
        )
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(decode_active_ban)
        .collect::<Result<Vec<_>>>()?;

        tx.commit().await?;

        Ok(RecoverySnapshot {
            service_meta,
            peer_sessions,
            active_bans,
        })
    }

    pub async fn insert_peer_offence(&self, offence: &PeerOffenceRecord) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO peer_offences (
                torrent_hash,
                peer_ip,
                peer_port,
                offence_number,
                reason_code,
                observed_seconds,
                bad_seconds,
                progress_delta,
                avg_up_rate_bps,
                banned_at,
                ban_expires_at,
                ban_revoked_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&offence.torrent_hash)
        .bind(offence.peer_ip.to_string())
        .bind(i64::from(offence.peer_port))
        .bind(i64::from(offence.offence_number))
        .bind(&offence.reason_code)
        .bind(i64::try_from(offence.observed_duration.as_secs())?)
        .bind(i64::try_from(offence.bad_duration.as_secs())?)
        .bind(f64::from(offence.progress_delta_per_mille) / 1000.0)
        .bind(i64::try_from(offence.avg_up_rate_bps)?)
        .bind(format_system_time(offence.banned_at))
        .bind(format_system_time(offence.ban_expires_at))
        .bind(offence.ban_revoked_at.map(format_system_time))
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn load_peer_offences_by_ip(
        &self,
        peer_ip: IpAddr,
    ) -> Result<Vec<PeerOffenceRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                torrent_hash,
                peer_ip,
                peer_port,
                offence_number,
                reason_code,
                observed_seconds,
                bad_seconds,
                progress_delta,
                avg_up_rate_bps,
                banned_at,
                ban_expires_at,
                ban_revoked_at
            FROM peer_offences
            WHERE peer_ip = ?
            ORDER BY offence_number, banned_at
            "#,
        )
        .bind(peer_ip.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(decode_peer_offence).collect()
    }

    pub async fn load_offence_history(
        &self,
        identity: &OffenceIdentity,
    ) -> Result<crate::types::OffenceHistory> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) AS offence_count,
                MAX(ban_expires_at) AS last_ban_expires_at
            FROM peer_offences
            WHERE peer_ip = ?
            "#,
        )
        .bind(identity.peer_ip.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(crate::types::OffenceHistory {
            offence_count: u32::try_from(row.get::<i64, _>("offence_count"))?,
            last_ban_expires_at: row
                .get::<Option<String>, _>("last_ban_expires_at")
                .map(|value| parse_system_time(&value))
                .transpose()?,
        })
    }

    pub async fn revoke_peer_offence(
        &self,
        offence_id: i64,
        revoked_at: SystemTime,
    ) -> Result<bool> {
        let result = sqlx::query("UPDATE peer_offences SET ban_revoked_at = ? WHERE id = ?")
            .bind(format_system_time(revoked_at))
            .bind(offence_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
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

async fn apply_migration_2(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    sqlx::query("ALTER TABLE peer_sessions ADD COLUMN bannable_since TEXT")
        .execute(&mut **tx)
        .await?;
    sqlx::query("ALTER TABLE peer_sessions ADD COLUMN last_ban_decision_at TEXT")
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
        VALUES (1, ?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            schema_version = excluded.schema_version,
            service_version = excluded.service_version,
            config_hash = excluded.config_hash,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(CURRENT_SCHEMA_VERSION)
    .bind(DEFAULT_SERVICE_VERSION)
    .bind(DEFAULT_CONFIG_HASH)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

fn peer_key(peer_ip: IpAddr, peer_port: u16) -> String {
    format!("{peer_ip}:{peer_port}")
}

fn format_system_time(value: SystemTime) -> String {
    format_rfc3339_seconds(value).to_string()
}

fn parse_system_time(value: &str) -> Result<SystemTime> {
    Ok(parse_rfc3339_weak(value)?)
}

fn encode_exemption_reason(reason: &ExemptionReason) -> String {
    match reason {
        ExemptionReason::TorrentExcluded => "torrent_excluded".to_string(),
        ExemptionReason::InsufficientSeeders {
            total_seeders,
            required_seeders,
        } => format!("insufficient_seeders:{total_seeders}:{required_seeders}"),
        ExemptionReason::AllowlistedPeer => "allowlisted_peer".to_string(),
        ExemptionReason::NearComplete {
            progress,
            threshold,
        } => format!("near_complete:{progress}:{threshold}"),
        ExemptionReason::NewPeerGracePeriod { age, grace_period } => format!(
            "new_peer_grace_period:{}:{}",
            age.as_secs(),
            grace_period.as_secs()
        ),
        ExemptionReason::AlreadyBanned => "already_banned".to_string(),
    }
}

fn decode_exemption_reason(value: &str) -> Result<ExemptionReason> {
    let parts: Vec<_> = value.split(':').collect();
    match parts.as_slice() {
        ["torrent_excluded"] => Ok(ExemptionReason::TorrentExcluded),
        ["insufficient_seeders", total_seeders, required_seeders] => {
            Ok(ExemptionReason::InsufficientSeeders {
                total_seeders: total_seeders.parse()?,
                required_seeders: required_seeders.parse()?,
            })
        }
        ["allowlisted_peer"] => Ok(ExemptionReason::AllowlistedPeer),
        ["near_complete", progress, threshold] => Ok(ExemptionReason::NearComplete {
            progress: progress.parse()?,
            threshold: threshold.parse()?,
        }),
        ["new_peer_grace_period", age, grace_period] => Ok(ExemptionReason::NewPeerGracePeriod {
            age: Duration::from_secs(age.parse()?),
            grace_period: Duration::from_secs(grace_period.parse()?),
        }),
        ["already_banned"] => Ok(ExemptionReason::AlreadyBanned),
        _ => bail!("unsupported exemption reason encoding `{value}`"),
    }
}

fn decode_peer_session(row: sqlx::sqlite::SqliteRow) -> Result<PeerSessionState> {
    let torrent_hash = row.get::<String, _>("torrent_hash");
    let peer_ip = row.get::<String, _>("peer_ip").parse::<IpAddr>()?;
    let peer_port = u16::try_from(row.get::<i64, _>("peer_port"))?;
    Ok(PeerSessionState {
        observation_id: PeerObservationId {
            torrent_hash,
            peer_ip,
            peer_port,
        },
        offence_identity: OffenceIdentity { peer_ip },
        first_seen_at: parse_system_time(&row.get::<String, _>("first_seen_at"))?,
        last_seen_at: parse_system_time(&row.get::<String, _>("last_seen_at"))?,
        baseline_progress: row.get("baseline_progress"),
        latest_progress: row.get("latest_progress"),
        rolling_avg_up_rate_bps: u64::try_from(row.get::<i64, _>("rolling_avg_up_rate_bps"))?,
        observed_duration: Duration::from_secs(u64::try_from(
            row.get::<i64, _>("observed_seconds"),
        )?),
        bad_duration: Duration::from_secs(u64::try_from(row.get::<i64, _>("bad_seconds"))?),
        sample_count: u32::try_from(row.get::<i64, _>("sample_count"))?,
        last_torrent_seeder_count: u32::try_from(row.get::<i64, _>("last_torrent_seeder_count"))?,
        last_exemption_reason: row
            .get::<Option<String>, _>("last_exemption_reason")
            .map(|value| decode_exemption_reason(&value))
            .transpose()?,
        bannable_since: row
            .get::<Option<String>, _>("bannable_since")
            .map(|value| parse_system_time(&value))
            .transpose()?,
        last_ban_decision_at: row
            .get::<Option<String>, _>("last_ban_decision_at")
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

fn decode_service_meta(row: sqlx::sqlite::SqliteRow) -> Result<ServiceMetaRecord> {
    Ok(ServiceMetaRecord {
        schema_version: row.get("schema_version"),
        service_version: row.get("service_version"),
        config_hash: row.get("config_hash"),
        updated_at: parse_system_time(&row.get::<String, _>("updated_at"))?,
    })
}

async fn upsert_peer_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    session: &PeerSessionState,
    policy_version: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO peer_sessions (
            torrent_hash,
            peer_key,
            peer_ip,
            peer_port,
            client_name,
            first_seen_at,
            last_seen_at,
            baseline_progress,
            latest_progress,
            rolling_avg_up_rate_bps,
            observed_seconds,
            bad_seconds,
            sample_count,
            last_torrent_seeder_count,
            last_exemption_reason,
            policy_version,
            bannable_since,
            last_ban_decision_at
        ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(torrent_hash, peer_key) DO UPDATE SET
            peer_ip = excluded.peer_ip,
            peer_port = excluded.peer_port,
            first_seen_at = excluded.first_seen_at,
            last_seen_at = excluded.last_seen_at,
            baseline_progress = excluded.baseline_progress,
            latest_progress = excluded.latest_progress,
            rolling_avg_up_rate_bps = excluded.rolling_avg_up_rate_bps,
            observed_seconds = excluded.observed_seconds,
            bad_seconds = excluded.bad_seconds,
            sample_count = excluded.sample_count,
            last_torrent_seeder_count = excluded.last_torrent_seeder_count,
            last_exemption_reason = excluded.last_exemption_reason,
            policy_version = excluded.policy_version,
            bannable_since = excluded.bannable_since,
            last_ban_decision_at = excluded.last_ban_decision_at
        "#,
    )
    .bind(&session.observation_id.torrent_hash)
    .bind(peer_key(
        session.observation_id.peer_ip,
        session.observation_id.peer_port,
    ))
    .bind(session.observation_id.peer_ip.to_string())
    .bind(i64::from(session.observation_id.peer_port))
    .bind(format_system_time(session.first_seen_at))
    .bind(format_system_time(session.last_seen_at))
    .bind(session.baseline_progress)
    .bind(session.latest_progress)
    .bind(
        i64::try_from(session.rolling_avg_up_rate_bps)
            .context("rolling avg up rate exceeds sqlite integer range")?,
    )
    .bind(
        i64::try_from(session.observed_duration.as_secs())
            .context("observed duration exceeds sqlite integer range")?,
    )
    .bind(
        i64::try_from(session.bad_duration.as_secs())
            .context("bad duration exceeds sqlite integer range")?,
    )
    .bind(i64::from(session.sample_count))
    .bind(i64::from(session.last_torrent_seeder_count))
    .bind(
        session
            .last_exemption_reason
            .as_ref()
            .map(encode_exemption_reason),
    )
    .bind(policy_version)
    .bind(session.bannable_since.map(format_system_time))
    .bind(session.last_ban_decision_at.map(format_system_time))
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn upsert_active_ban_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ban: &ActiveBanRecord,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO active_bans (
            peer_ip,
            peer_port,
            scope,
            offence_number,
            reason,
            created_at,
            expires_at,
            reconciled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(peer_ip, peer_port, scope) DO UPDATE SET
            offence_number = excluded.offence_number,
            reason = excluded.reason,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            reconciled_at = excluded.reconciled_at
        "#,
    )
    .bind(ban.peer_ip.to_string())
    .bind(i64::from(ban.peer_port))
    .bind(&ban.scope)
    .bind(i64::from(ban.offence_number))
    .bind(&ban.reason)
    .bind(format_system_time(ban.created_at))
    .bind(format_system_time(ban.expires_at))
    .bind(ban.reconciled_at.map(format_system_time))
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn insert_peer_offence_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    offence: &PeerOffenceRecord,
) -> Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO peer_offences (
            torrent_hash,
            peer_ip,
            peer_port,
            offence_number,
            reason_code,
            observed_seconds,
            bad_seconds,
            progress_delta,
            avg_up_rate_bps,
            banned_at,
            ban_expires_at,
            ban_revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&offence.torrent_hash)
    .bind(offence.peer_ip.to_string())
    .bind(i64::from(offence.peer_port))
    .bind(i64::from(offence.offence_number))
    .bind(&offence.reason_code)
    .bind(
        i64::try_from(offence.observed_duration.as_secs())
            .context("observed duration exceeds sqlite integer range")?,
    )
    .bind(
        i64::try_from(offence.bad_duration.as_secs())
            .context("bad duration exceeds sqlite integer range")?,
    )
    .bind(f64::from(offence.progress_delta_per_mille) / 1000.0)
    .bind(
        i64::try_from(offence.avg_up_rate_bps)
            .context("avg up rate exceeds sqlite integer range")?,
    )
    .bind(format_system_time(offence.banned_at))
    .bind(format_system_time(offence.ban_expires_at))
    .bind(offence.ban_revoked_at.map(format_system_time))
    .execute(&mut **tx)
    .await?;

    Ok(result.last_insert_rowid())
}

fn progress_delta_per_mille(progress_delta: f64) -> u32 {
    if !progress_delta.is_finite() || progress_delta <= 0.0 {
        return 0;
    }

    (progress_delta * 1000.0)
        .round()
        .clamp(0.0, u32::MAX as f64) as u32
}

fn decode_active_ban(row: sqlx::sqlite::SqliteRow) -> Result<ActiveBanRecord> {
    Ok(ActiveBanRecord {
        peer_ip: row.get::<String, _>("peer_ip").parse()?,
        peer_port: u16::try_from(row.get::<i64, _>("peer_port"))?,
        scope: row.get("scope"),
        offence_number: u32::try_from(row.get::<i64, _>("offence_number"))?,
        reason: row.get("reason"),
        created_at: parse_system_time(&row.get::<String, _>("created_at"))?,
        expires_at: parse_system_time(&row.get::<String, _>("expires_at"))?,
        reconciled_at: row
            .get::<Option<String>, _>("reconciled_at")
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

fn decode_peer_offence(row: sqlx::sqlite::SqliteRow) -> Result<PeerOffenceRecord> {
    Ok(PeerOffenceRecord {
        id: Some(row.get("id")),
        torrent_hash: row.get("torrent_hash"),
        peer_ip: row.get::<String, _>("peer_ip").parse()?,
        peer_port: u16::try_from(row.get::<i64, _>("peer_port"))?,
        offence_number: u32::try_from(row.get::<i64, _>("offence_number"))?,
        reason_code: row.get("reason_code"),
        observed_duration: Duration::from_secs(u64::try_from(
            row.get::<i64, _>("observed_seconds"),
        )?),
        bad_duration: Duration::from_secs(u64::try_from(row.get::<i64, _>("bad_seconds"))?),
        progress_delta_per_mille: ((row.get::<f64, _>("progress_delta") * 1000.0).round()) as u32,
        avg_up_rate_bps: u64::try_from(row.get::<i64, _>("avg_up_rate_bps"))?,
        banned_at: parse_system_time(&row.get::<String, _>("banned_at"))?,
        ban_expires_at: parse_system_time(&row.get::<String, _>("ban_expires_at"))?,
        ban_revoked_at: row
            .get::<Option<String>, _>("ban_revoked_at")
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        time::{Duration, UNIX_EPOCH},
    };

    use tempfile::tempdir;

    use super::{
        ActiveBanRecord, CURRENT_SCHEMA_VERSION, DEFAULT_SERVICE_VERSION, EnforcementWriteResult,
        PeerOffenceRecord, Persistence, RecoverySnapshot,
    };
    use crate::{
        config::DatabaseConfig,
        types::{
            BanDecision, ExemptionReason, OffenceHistory, OffenceIdentity, PeerEvaluation,
            PeerObservationId, PeerSessionState,
        },
    };

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
    async fn peer_sessions_round_trip_and_delete() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let session = sample_peer_session();

        persistence
            .upsert_peer_session(&session, "policy-v1")
            .await
            .unwrap();
        let loaded = persistence
            .get_peer_session(&session.observation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, session);

        let listed = persistence.load_peer_sessions().await.unwrap();
        assert_eq!(listed, vec![session.clone()]);

        assert!(
            persistence
                .delete_peer_session(&session.observation_id)
                .await
                .unwrap()
        );
        assert!(
            persistence
                .get_peer_session(&session.observation_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn service_meta_round_trips_updates() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();

        let initial = persistence.get_service_meta().await.unwrap().unwrap();
        assert_eq!(initial.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(initial.service_version, DEFAULT_SERVICE_VERSION);

        let updated = persistence
            .update_service_meta("0.2.0", "config-123")
            .await
            .unwrap();
        let loaded = persistence.get_service_meta().await.unwrap().unwrap();
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.service_version, "0.2.0");
        assert_eq!(loaded.config_hash, "config-123");
        assert_eq!(
            loaded
                .updated_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated
                .updated_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    #[tokio::test]
    async fn active_bans_round_trip_expiry_and_reconciliation() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let ban = sample_active_ban();

        persistence.upsert_active_ban(&ban).await.unwrap();
        let loaded = persistence.load_active_bans().await.unwrap();
        assert_eq!(loaded, vec![ban.clone()]);

        let expired_before = persistence
            .list_expired_active_bans(UNIX_EPOCH + Duration::from_secs(3599))
            .await
            .unwrap();
        assert!(expired_before.is_empty());

        let expired_after = persistence
            .list_expired_active_bans(UNIX_EPOCH + Duration::from_secs(3600))
            .await
            .unwrap();
        assert_eq!(expired_after, vec![ban.clone()]);

        assert!(
            persistence
                .mark_active_ban_reconciled(
                    ban.peer_ip,
                    ban.peer_port,
                    &ban.scope,
                    UNIX_EPOCH + Duration::from_secs(3700),
                )
                .await
                .unwrap()
        );
        assert!(
            persistence
                .list_expired_active_bans(UNIX_EPOCH + Duration::from_secs(4000))
                .await
                .unwrap()
                .is_empty()
        );

        assert!(
            persistence
                .delete_active_ban(ban.peer_ip, ban.peer_port, &ban.scope)
                .await
                .unwrap()
        );
        assert!(persistence.load_active_bans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn peer_offences_round_trip_history_and_revocation() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let first = sample_peer_offence(1, 3600);
        let second = sample_peer_offence(2, 7200);

        let first_id = persistence.insert_peer_offence(&first).await.unwrap();
        let second_id = persistence.insert_peer_offence(&second).await.unwrap();

        let offences = persistence
            .load_peer_offences_by_ip(first.peer_ip)
            .await
            .unwrap();
        assert_eq!(offences.len(), 2);
        assert_eq!(offences[0].id, Some(first_id));
        assert_eq!(offences[1].id, Some(second_id));
        assert_eq!(offences[1].offence_number, 2);

        let history = persistence
            .load_offence_history(&OffenceIdentity {
                peer_ip: first.peer_ip,
            })
            .await
            .unwrap();
        assert_eq!(
            history,
            OffenceHistory {
                offence_count: 2,
                last_ban_expires_at: Some(UNIX_EPOCH + Duration::from_secs(7200)),
            }
        );

        assert!(
            persistence
                .revoke_peer_offence(second_id, UNIX_EPOCH + Duration::from_secs(5400))
                .await
                .unwrap()
        );
        let offences = persistence
            .load_peer_offences_by_ip(first.peer_ip)
            .await
            .unwrap();
        assert_eq!(
            offences[1].ban_revoked_at,
            Some(UNIX_EPOCH + Duration::from_secs(5400))
        );
    }

    #[tokio::test]
    async fn record_ban_enforcement_persists_session_offence_and_active_ban() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let evaluation = pending_ban_evaluation();
        let decision = sample_ban_decision();

        let result = persistence
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(900),
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            EnforcementWriteResult {
                duplicate_suppressed: false,
                offence_id: result.offence_id,
                active_ban: Some(ActiveBanRecord {
                    peer_ip: decision.peer_ip,
                    peer_port: decision.peer_port,
                    scope: "torrent:abc123".to_string(),
                    offence_number: 2,
                    reason: decision.reason.clone(),
                    created_at: UNIX_EPOCH + Duration::from_secs(900),
                    expires_at: UNIX_EPOCH + Duration::from_secs(4_500),
                    reconciled_at: None,
                }),
            }
        );
        assert!(result.offence_id.is_some());

        let stored_session = persistence
            .get_peer_session(&evaluation.session.observation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_session.last_ban_decision_at,
            Some(UNIX_EPOCH + Duration::from_secs(900))
        );
        assert_eq!(
            persistence.load_active_bans().await.unwrap(),
            vec![result.active_ban.unwrap()]
        );
        let offences = persistence
            .load_peer_offences_by_ip(decision.peer_ip)
            .await
            .unwrap();
        assert_eq!(offences.len(), 1);
        assert_eq!(offences[0].offence_number, 2);
        assert_eq!(offences[0].progress_delta_per_mille, 1);
    }

    #[tokio::test]
    async fn record_ban_enforcement_suppresses_duplicate_replays() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let evaluation = pending_ban_evaluation();
        let decision = sample_ban_decision();

        let first = persistence
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(900),
            )
            .await
            .unwrap();
        assert!(!first.duplicate_suppressed);

        let second = persistence
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(960),
            )
            .await
            .unwrap();
        assert_eq!(
            second,
            EnforcementWriteResult {
                duplicate_suppressed: true,
                offence_id: None,
                active_ban: None,
            }
        );

        assert_eq!(
            persistence
                .load_peer_offences_by_ip(decision.peer_ip)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(persistence.load_active_bans().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn recovery_snapshot_loads_meta_sessions_and_bans_together() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let session = sample_peer_session();
        let ban = sample_active_ban();

        persistence
            .upsert_peer_session(&session, "policy-v1")
            .await
            .unwrap();
        persistence.upsert_active_ban(&ban).await.unwrap();

        let snapshot = persistence.load_recovery_snapshot().await.unwrap();
        assert_eq!(
            snapshot,
            RecoverySnapshot {
                service_meta: persistence.get_service_meta().await.unwrap().unwrap(),
                peer_sessions: vec![session],
                active_bans: vec![ban],
            }
        );
    }

    #[tokio::test]
    async fn restart_persists_recovery_state_across_connections() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("restart.sqlite");

        let persistence = file_persistence(&db_path).await;
        persistence.run_migrations().await.unwrap();
        let evaluation = pending_ban_evaluation();
        let decision = sample_ban_decision();
        let stored = persistence
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(900),
            )
            .await
            .unwrap();
        let active_ban = stored.active_ban.clone().unwrap();
        drop(persistence);

        let reopened = file_persistence(&db_path).await;
        reopened.run_migrations().await.unwrap();
        let snapshot = reopened.load_recovery_snapshot().await.unwrap();

        assert_eq!(snapshot.service_meta.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(snapshot.peer_sessions.len(), 1);
        assert_eq!(snapshot.active_bans, vec![active_ban]);
        assert_eq!(
            reopened
                .load_peer_offences_by_ip(decision.peer_ip)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn duplicate_ban_suppression_survives_restart() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("duplicate.sqlite");

        let persistence = file_persistence(&db_path).await;
        persistence.run_migrations().await.unwrap();
        let evaluation = pending_ban_evaluation();
        let decision = sample_ban_decision();
        let first = persistence
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(900),
            )
            .await
            .unwrap();
        assert!(!first.duplicate_suppressed);
        drop(persistence);

        let reopened = file_persistence(&db_path).await;
        reopened.run_migrations().await.unwrap();
        let second = reopened
            .record_ban_enforcement(
                &evaluation,
                &decision,
                UNIX_EPOCH + Duration::from_secs(960),
            )
            .await
            .unwrap();

        assert_eq!(
            second,
            EnforcementWriteResult {
                duplicate_suppressed: true,
                offence_id: None,
                active_ban: None,
            }
        );
        assert_eq!(
            reopened
                .load_peer_offences_by_ip(decision.peer_ip)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(reopened.load_active_bans().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn migrations_upgrade_existing_version_one_schema() {
        let persistence = test_persistence().await;
        let mut tx = persistence.pool.begin().await.unwrap();
        super::apply_migration_1(&mut tx).await.unwrap();
        sqlx::query(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO schema_migrations (version, description) VALUES (1, 'initial schema')",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        persistence.run_migrations().await.unwrap();

        let bannable_since_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('peer_sessions') WHERE name = 'bannable_since'",
        )
        .fetch_one(&persistence.pool)
        .await
        .unwrap();
        let last_ban_decision_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('peer_sessions') WHERE name = 'last_ban_decision_at'",
        )
        .fetch_one(&persistence.pool)
        .await
        .unwrap();
        assert_eq!(bannable_since_exists, 1);
        assert_eq!(last_ban_decision_exists, 1);
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

    async fn file_persistence(path: &std::path::Path) -> Persistence {
        Persistence::connect(&DatabaseConfig {
            path: path.to_path_buf(),
            busy_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap()
    }

    fn sample_peer_session() -> PeerSessionState {
        PeerSessionState {
            observation_id: PeerObservationId {
                torrent_hash: "abc123".to_string(),
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                peer_port: 51413,
            },
            offence_identity: OffenceIdentity {
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            },
            first_seen_at: UNIX_EPOCH + Duration::from_secs(60),
            last_seen_at: UNIX_EPOCH + Duration::from_secs(180),
            baseline_progress: 0.1,
            latest_progress: 0.15,
            rolling_avg_up_rate_bps: 512,
            observed_duration: Duration::from_secs(120),
            bad_duration: Duration::from_secs(90),
            sample_count: 3,
            last_torrent_seeder_count: 5,
            last_exemption_reason: Some(ExemptionReason::NearComplete {
                progress: 0.96,
                threshold: 0.95,
            }),
            bannable_since: Some(UNIX_EPOCH + Duration::from_secs(150)),
            last_ban_decision_at: Some(UNIX_EPOCH + Duration::from_secs(180)),
        }
    }

    fn pending_ban_evaluation() -> PeerEvaluation {
        let mut session = sample_peer_session();
        session.last_ban_decision_at = None;
        session.last_exemption_reason = None;
        PeerEvaluation {
            session,
            progress_delta: 0.001,
            sample_duration: Duration::from_secs(60),
            sample_up_rate_bps: 512,
            is_bad_sample: true,
            is_bannable: true,
        }
    }

    fn sample_ban_decision() -> BanDecision {
        BanDecision {
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            peer_port: 51413,
            offence_number: 2,
            ttl: Duration::from_secs(3600),
            reason: "slow peer".to_string(),
        }
    }

    fn sample_active_ban() -> ActiveBanRecord {
        ActiveBanRecord {
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            peer_port: 51413,
            scope: "torrent:abc123".to_string(),
            offence_number: 2,
            reason: "slow peer".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(1800),
            expires_at: UNIX_EPOCH + Duration::from_secs(3600),
            reconciled_at: None,
        }
    }

    fn sample_peer_offence(offence_number: u32, ban_expires_at_secs: u64) -> PeerOffenceRecord {
        PeerOffenceRecord {
            id: None,
            torrent_hash: "abc123".to_string(),
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            peer_port: 51413,
            offence_number,
            reason_code: "slow_peer".to_string(),
            observed_duration: Duration::from_secs(600),
            bad_duration: Duration::from_secs(480),
            progress_delta_per_mille: 2,
            avg_up_rate_bps: 512,
            banned_at: UNIX_EPOCH + Duration::from_secs(ban_expires_at_secs.saturating_sub(1800)),
            ban_expires_at: UNIX_EPOCH + Duration::from_secs(ban_expires_at_secs),
            ban_revoked_at: None,
        }
    }
}
