use std::{
    env,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use humantime::{format_rfc3339_seconds, parse_rfc3339_weak};
use sqlx::{
    Executor, Row, SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqliteJournalMode,
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

const CURRENT_SCHEMA_VERSION: i64 = 3;
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
pub struct PendingBanIntentRecord {
    pub torrent_hash: String,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub offence_number: u32,
    pub reason_code: String,
    pub observed_at: SystemTime,
    pub ban_expires_at: SystemTime,
    pub bad_duration: Duration,
    pub progress_delta_per_mille: u32,
    pub avg_up_rate_bps: u64,
    pub last_error: String,
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
    pub pending_ban_intents: Vec<PendingBanIntentRecord>,
}

#[derive(Clone)]
pub struct Persistence {
    database_path: Option<PathBuf>,
    pool: SqlitePool,
    migrations_succeeded: Arc<AtomicBool>,
}

impl Persistence {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        if config.path != Path::new(":memory:")
            && let Some(parent) = config.path.parent()
        {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create database directory `{}`", parent.display())
            })?;
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
            database_path: (config.path != Path::new(":memory:")).then(|| config.path.clone()),
            pool,
            migrations_succeeded: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        self.migrations_succeeded.store(false, Ordering::Relaxed);

        let migration_path = resolve_migrations_path()?;
        let migration_path_display = migration_path.display().to_string();
        let migrator = sqlx::migrate::Migrator::new(migration_path)
            .await
            .with_context(|| {
                format!(
                    "failed to load sqlx migrations from {}",
                    migration_path_display
                )
            })?;
        migrator
            .run(&self.pool)
            .await
            .context("failed to run sqlx migrations")?;

        let mut tx = self.pool.begin().await?;
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

    #[cfg(test)]
    pub async fn load_peer_sessions(&self) -> Result<Vec<PeerSessionState>> {
        load_peer_sessions_exec(&self.pool).await
    }

    pub async fn count_peer_sessions(&self) -> Result<usize> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM peer_sessions")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as usize)
    }

    pub async fn count_active_bans(&self) -> Result<usize> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM active_bans WHERE reconciled_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    pub async fn sqlite_size_bytes(&self) -> Result<Option<u64>> {
        let Some(path) = &self.database_path else {
            return Ok(None);
        };

        let metadata = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("failed to read sqlite metadata `{}`", path.display()))?;
        Ok(Some(metadata.len()))
    }

    pub async fn get_peer_session(
        &self,
        observation_id: &PeerObservationId,
    ) -> Result<Option<PeerSessionState>> {
        get_peer_session_exec(&self.pool, observation_id).await
    }

    pub async fn get_latest_peer_session_for_torrent_ip(
        &self,
        torrent_hash: &str,
        peer_ip: IpAddr,
    ) -> Result<Option<PeerSessionState>> {
        let row = sqlx::query_as::<_, PeerSessionRow>(
            r#"
            SELECT
                torrent_hash,
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
            WHERE torrent_hash = ? AND peer_ip = ?
            ORDER BY last_seen_at DESC
            LIMIT 1
            "#,
        )
        .bind(torrent_hash)
        .bind(peer_ip.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(decode_peer_session).transpose()
    }

    pub async fn upsert_peer_session(
        &self,
        session: &PeerSessionState,
        policy_version: &str,
    ) -> Result<()> {
        upsert_peer_session_exec(&self.pool, session, policy_version).await
    }

    #[cfg(test)]
    pub async fn delete_peer_session(&self, observation_id: &PeerObservationId) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM peer_sessions WHERE torrent_hash = ? AND peer_key = ?")
                .bind(&observation_id.torrent_hash)
                .bind(peer_key(observation_id.peer_ip, observation_id.peer_port))
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg(test)]
    pub async fn get_service_meta(&self) -> Result<Option<ServiceMetaRecord>> {
        load_service_meta_exec(&self.pool).await
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

    #[cfg(test)]
    pub async fn upsert_active_ban(&self, ban: &ActiveBanRecord) -> Result<()> {
        upsert_active_ban_exec(&self.pool, ban).await
    }

    pub async fn load_active_bans(&self) -> Result<Vec<ActiveBanRecord>> {
        load_active_bans_exec(&self.pool).await
    }

    pub async fn list_expired_active_bans(
        &self,
        as_of: SystemTime,
    ) -> Result<Vec<ActiveBanRecord>> {
        let rows = sqlx::query_as::<_, ActiveBanRow>(
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

    #[cfg(test)]
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
        if let Some(session) =
            get_peer_session_exec(&mut *tx, &evaluation.session.observation_id).await?
            && session.last_ban_decision_at.is_some()
        {
            tx.commit().await?;
            return Ok(EnforcementWriteResult {
                duplicate_suppressed: true,
                offence_id: None,
                active_ban: None,
            });
        }

        let mut updated_session = evaluation.session.clone();
        updated_session.last_ban_decision_at = Some(enforced_at);
        upsert_peer_session_exec(&mut *tx, &updated_session, "policy-v1").await?;

        let offence = PeerOffenceRecord {
            id: None,
            torrent_hash: updated_session.observation_id.torrent_hash.clone(),
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            offence_number: decision.offence_number,
            reason_code: decision.reason_code.clone(),
            observed_duration: updated_session.observed_duration,
            bad_duration: updated_session.bad_duration,
            progress_delta_per_mille: progress_delta_per_mille(evaluation.progress_delta),
            avg_up_rate_bps: updated_session.rolling_avg_up_rate_bps,
            banned_at: enforced_at,
            ban_expires_at: enforced_at + decision.ttl,
            ban_revoked_at: None,
        };
        let offence_id = insert_peer_offence_exec(&mut *tx, &offence).await?;

        let active_ban = ActiveBanRecord {
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            scope: format!("torrent:{}", updated_session.observation_id.torrent_hash),
            offence_number: decision.offence_number,
            reason: decision.reason_code.clone(),
            created_at: enforced_at,
            expires_at: enforced_at + decision.ttl,
            reconciled_at: None,
        };
        upsert_active_ban_exec(&mut *tx, &active_ban).await?;

        tx.commit().await?;

        Ok(EnforcementWriteResult {
            duplicate_suppressed: false,
            offence_id: Some(offence_id),
            active_ban: Some(active_ban),
        })
    }

    pub async fn load_recovery_snapshot(&self) -> Result<RecoverySnapshot> {
        let mut tx = self.pool.begin().await?;
        let service_meta = load_service_meta_exec(&mut *tx)
            .await?
            .context("service_meta row missing after migrations")?;
        let peer_sessions = load_peer_sessions_exec(&mut *tx).await?;
        let active_bans = load_active_bans_exec(&mut *tx).await?;
        let pending_ban_intents = load_pending_ban_intents_exec(&mut *tx).await?;

        tx.commit().await?;

        Ok(RecoverySnapshot {
            service_meta,
            peer_sessions,
            active_bans,
            pending_ban_intents,
        })
    }

    #[cfg(test)]
    pub async fn insert_peer_offence(&self, offence: &PeerOffenceRecord) -> Result<i64> {
        insert_peer_offence_exec(&self.pool, offence).await
    }

    pub async fn load_peer_offences_by_ip(
        &self,
        peer_ip: IpAddr,
    ) -> Result<Vec<PeerOffenceRecord>> {
        let rows = sqlx::query_as::<_, PeerOffenceRow>(
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

    pub async fn upsert_pending_ban_intent(&self, record: &PendingBanIntentRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO pending_ban_intents (
                torrent_hash,
                peer_ip,
                peer_port,
                offence_number,
                reason_code,
                observed_at,
                ban_expires_at,
                bad_seconds,
                progress_delta,
                avg_up_rate_bps,
                last_error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(torrent_hash, peer_ip, peer_port, offence_number) DO UPDATE SET
                reason_code = excluded.reason_code,
                observed_at = excluded.observed_at,
                ban_expires_at = excluded.ban_expires_at,
                bad_seconds = excluded.bad_seconds,
                progress_delta = excluded.progress_delta,
                avg_up_rate_bps = excluded.avg_up_rate_bps,
                last_error = excluded.last_error
            "#,
        )
        .bind(&record.torrent_hash)
        .bind(record.peer_ip.to_string())
        .bind(i64::from(record.peer_port))
        .bind(i64::from(record.offence_number))
        .bind(&record.reason_code)
        .bind(format_system_time(record.observed_at))
        .bind(format_system_time(record.ban_expires_at))
        .bind(i64::try_from(record.bad_duration.as_secs())?)
        .bind(f64::from(record.progress_delta_per_mille) / 1000.0)
        .bind(i64::try_from(record.avg_up_rate_bps)?)
        .bind(&record.last_error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn load_pending_ban_intents(&self) -> Result<Vec<PendingBanIntentRecord>> {
        load_pending_ban_intents_exec(&self.pool).await
    }

    pub async fn delete_pending_ban_intent(
        &self,
        torrent_hash: &str,
        peer_ip: IpAddr,
        peer_port: u16,
        offence_number: u32,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM pending_ban_intents
            WHERE torrent_hash = ? AND peer_ip = ? AND peer_port = ? AND offence_number = ?
            "#,
        )
        .bind(torrent_hash)
        .bind(peer_ip.to_string())
        .bind(i64::from(peer_port))
        .bind(i64::from(offence_number))
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

fn resolve_migrations_path() -> Result<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("./migrations"),
        PathBuf::from("/app/migrations"),
    ];
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("migrations"));
    }

    candidates.into_iter().find(|path| path.is_dir()).ok_or_else(|| {
        anyhow::anyhow!(
            "no migrations directory found in expected locations: ./migrations, /app/migrations, <exe_dir>/migrations"
        )
    })
}

#[derive(sqlx::FromRow)]
struct ServiceMetaRow {
    schema_version: i64,
    service_version: String,
    config_hash: String,
    updated_at: String,
}

#[derive(sqlx::FromRow)]
struct PeerSessionRow {
    torrent_hash: String,
    peer_ip: String,
    peer_port: i64,
    first_seen_at: String,
    last_seen_at: String,
    baseline_progress: f64,
    latest_progress: f64,
    rolling_avg_up_rate_bps: i64,
    observed_seconds: i64,
    bad_seconds: i64,
    sample_count: i64,
    last_torrent_seeder_count: i64,
    last_exemption_reason: Option<String>,
    bannable_since: Option<String>,
    last_ban_decision_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ActiveBanRow {
    peer_ip: String,
    peer_port: i64,
    scope: String,
    offence_number: i64,
    reason: String,
    created_at: String,
    expires_at: String,
    reconciled_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PeerOffenceRow {
    id: i64,
    torrent_hash: String,
    peer_ip: String,
    peer_port: i64,
    offence_number: i64,
    reason_code: String,
    observed_seconds: i64,
    bad_seconds: i64,
    progress_delta: f64,
    avg_up_rate_bps: i64,
    banned_at: String,
    ban_expires_at: String,
    ban_revoked_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PendingBanIntentRow {
    torrent_hash: String,
    peer_ip: String,
    peer_port: i64,
    offence_number: i64,
    reason_code: String,
    observed_at: String,
    ban_expires_at: String,
    bad_seconds: i64,
    progress_delta: f64,
    avg_up_rate_bps: i64,
    last_error: String,
}

async fn upsert_service_meta(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    let existing_version = sqlx::query("SELECT schema_version FROM service_meta WHERE id = 1")
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| row.get::<i64, _>("schema_version"));

    if let Some(version) = existing_version
        && version > CURRENT_SCHEMA_VERSION
    {
        bail!(
            "service_meta schema version {} is newer than supported version {}",
            version,
            CURRENT_SCHEMA_VERSION
        );
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

fn decode_peer_session(row: PeerSessionRow) -> Result<PeerSessionState> {
    let peer_ip = row.peer_ip.parse::<IpAddr>()?;
    let peer_port = u16::try_from(row.peer_port)?;
    Ok(PeerSessionState {
        observation_id: PeerObservationId {
            torrent_hash: row.torrent_hash,
            peer_ip,
            peer_port,
        },
        offence_identity: OffenceIdentity { peer_ip },
        first_seen_at: parse_system_time(&row.first_seen_at)?,
        last_seen_at: parse_system_time(&row.last_seen_at)?,
        baseline_progress: row.baseline_progress,
        latest_progress: row.latest_progress,
        rolling_avg_up_rate_bps: u64::try_from(row.rolling_avg_up_rate_bps)?,
        observed_duration: Duration::from_secs(u64::try_from(row.observed_seconds)?),
        bad_duration: Duration::from_secs(u64::try_from(row.bad_seconds)?),
        sample_count: u32::try_from(row.sample_count)?,
        last_torrent_seeder_count: u32::try_from(row.last_torrent_seeder_count)?,
        last_exemption_reason: row
            .last_exemption_reason
            .map(|value| decode_exemption_reason(&value))
            .transpose()?,
        bannable_since: row
            .bannable_since
            .map(|value| parse_system_time(&value))
            .transpose()?,
        last_ban_decision_at: row
            .last_ban_decision_at
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

fn decode_service_meta(row: ServiceMetaRow) -> Result<ServiceMetaRecord> {
    Ok(ServiceMetaRecord {
        schema_version: row.schema_version,
        service_version: row.service_version,
        config_hash: row.config_hash,
        updated_at: parse_system_time(&row.updated_at)?,
    })
}

async fn load_service_meta_exec<'e, E>(executor: E) -> Result<Option<ServiceMetaRecord>>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query_as::<_, ServiceMetaRow>(
        r#"
        SELECT schema_version, service_version, config_hash, updated_at
        FROM service_meta
        WHERE id = 1
        "#,
    )
    .fetch_optional(executor)
    .await?;

    row.map(decode_service_meta).transpose()
}

async fn get_peer_session_exec<'e, E>(
    executor: E,
    observation_id: &PeerObservationId,
) -> Result<Option<PeerSessionState>>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query_as::<_, PeerSessionRow>(
        r#"
        SELECT
            torrent_hash,
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
    .fetch_optional(executor)
    .await?;

    row.map(decode_peer_session).transpose()
}

async fn load_peer_sessions_exec<'e, E>(executor: E) -> Result<Vec<PeerSessionState>>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let rows = sqlx::query_as::<_, PeerSessionRow>(
        r#"
        SELECT
            torrent_hash,
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
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(decode_peer_session).collect()
}

async fn upsert_peer_session_exec<'e, E>(
    executor: E,
    session: &PeerSessionState,
    policy_version: &str,
) -> Result<()>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
    .await?;

    Ok(())
}

async fn load_active_bans_exec<'e, E>(executor: E) -> Result<Vec<ActiveBanRecord>>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let rows = sqlx::query_as::<_, ActiveBanRow>(
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
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(decode_active_ban).collect()
}

async fn upsert_active_ban_exec<'e, E>(executor: E, ban: &ActiveBanRecord) -> Result<()>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
    .await?;

    Ok(())
}

async fn load_pending_ban_intents_exec<'e, E>(executor: E) -> Result<Vec<PendingBanIntentRecord>>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let rows = sqlx::query_as::<_, PendingBanIntentRow>(
        r#"
        SELECT
            torrent_hash,
            peer_ip,
            peer_port,
            offence_number,
            reason_code,
            observed_at,
            ban_expires_at,
            bad_seconds,
            progress_delta,
            avg_up_rate_bps,
            last_error
        FROM pending_ban_intents
        ORDER BY observed_at, torrent_hash, peer_ip, peer_port, offence_number
        "#,
    )
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(decode_pending_ban_intent).collect()
}

async fn insert_peer_offence_exec<'e, E>(executor: E, offence: &PeerOffenceRecord) -> Result<i64>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
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
    .execute(executor)
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

fn decode_active_ban(row: ActiveBanRow) -> Result<ActiveBanRecord> {
    Ok(ActiveBanRecord {
        peer_ip: row.peer_ip.parse()?,
        peer_port: u16::try_from(row.peer_port)?,
        scope: row.scope,
        offence_number: u32::try_from(row.offence_number)?,
        reason: row.reason,
        created_at: parse_system_time(&row.created_at)?,
        expires_at: parse_system_time(&row.expires_at)?,
        reconciled_at: row
            .reconciled_at
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

fn decode_peer_offence(row: PeerOffenceRow) -> Result<PeerOffenceRecord> {
    Ok(PeerOffenceRecord {
        id: Some(row.id),
        torrent_hash: row.torrent_hash,
        peer_ip: row.peer_ip.parse()?,
        peer_port: u16::try_from(row.peer_port)?,
        offence_number: u32::try_from(row.offence_number)?,
        reason_code: row.reason_code,
        observed_duration: Duration::from_secs(u64::try_from(row.observed_seconds)?),
        bad_duration: Duration::from_secs(u64::try_from(row.bad_seconds)?),
        progress_delta_per_mille: ((row.progress_delta * 1000.0).round()) as u32,
        avg_up_rate_bps: u64::try_from(row.avg_up_rate_bps)?,
        banned_at: parse_system_time(&row.banned_at)?,
        ban_expires_at: parse_system_time(&row.ban_expires_at)?,
        ban_revoked_at: row
            .ban_revoked_at
            .map(|value| parse_system_time(&value))
            .transpose()?,
    })
}

fn decode_pending_ban_intent(row: PendingBanIntentRow) -> Result<PendingBanIntentRecord> {
    Ok(PendingBanIntentRecord {
        torrent_hash: row.torrent_hash,
        peer_ip: row.peer_ip.parse()?,
        peer_port: u16::try_from(row.peer_port)?,
        offence_number: u32::try_from(row.offence_number)?,
        reason_code: row.reason_code,
        observed_at: parse_system_time(&row.observed_at)?,
        ban_expires_at: parse_system_time(&row.ban_expires_at)?,
        bad_duration: Duration::from_secs(u64::try_from(row.bad_seconds)?),
        progress_delta_per_mille: ((row.progress_delta * 1000.0).round()) as u32,
        avg_up_rate_bps: u64::try_from(row.avg_up_rate_bps)?,
        last_error: row.last_error,
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
        PeerOffenceRecord, PendingBanIntentRecord, Persistence, RecoverySnapshot,
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
            "_sqlx_migrations",
            "peer_sessions",
            "peer_offences",
            "active_bans",
            "pending_ban_intents",
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
    async fn latest_peer_session_lookup_prefers_most_recent_port_for_same_ip() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let old_session = sample_peer_session();
        let mut new_session = old_session.clone();
        new_session.observation_id.peer_port = 51414;
        new_session.last_seen_at = old_session.last_seen_at + Duration::from_secs(60);

        persistence
            .upsert_peer_session(&old_session, "policy-v1")
            .await
            .unwrap();
        persistence
            .upsert_peer_session(&new_session, "policy-v1")
            .await
            .unwrap();

        let latest = persistence
            .get_latest_peer_session_for_torrent_ip(
                &old_session.observation_id.torrent_hash,
                old_session.observation_id.peer_ip,
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(latest.observation_id.peer_port, 51414);
        assert_eq!(latest.last_seen_at, new_session.last_seen_at);
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
    async fn pending_ban_intents_round_trip_and_delete() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let record = PendingBanIntentRecord {
            torrent_hash: "abc123".to_string(),
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            peer_port: 51413,
            offence_number: 2,
            reason_code: "slow_non_progressing".to_string(),
            observed_at: UNIX_EPOCH + Duration::from_secs(900),
            ban_expires_at: UNIX_EPOCH + Duration::from_secs(4_500),
            bad_duration: Duration::from_secs(1_200),
            progress_delta_per_mille: 1,
            avg_up_rate_bps: 128,
            last_error: "qbittorrent request failed".to_string(),
        };

        persistence
            .upsert_pending_ban_intent(&record)
            .await
            .unwrap();
        let loaded = persistence.load_pending_ban_intents().await.unwrap();
        assert_eq!(loaded, vec![record.clone()]);

        assert!(
            persistence
                .delete_pending_ban_intent(
                    &record.torrent_hash,
                    record.peer_ip,
                    record.peer_port,
                    record.offence_number,
                )
                .await
                .unwrap()
        );
        assert!(
            persistence
                .load_pending_ban_intents()
                .await
                .unwrap()
                .is_empty()
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
                    reason: decision.reason_code.clone(),
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
                pending_ban_intents: vec![],
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
        assert!(snapshot.pending_ban_intents.is_empty());
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
    async fn migrations_can_run_repeatedly() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
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
        let pending_ban_intents_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'pending_ban_intents'",
        )
        .fetch_one(&persistence.pool)
        .await
        .unwrap();
        assert_eq!(bannable_since_exists, 1);
        assert_eq!(last_ban_decision_exists, 1);
        assert_eq!(pending_ban_intents_exists, 1);
    }

    #[tokio::test]
    async fn migrations_fail_when_db_has_unknown_applied_version() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();

        sqlx::query(
            r#"
            INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
            VALUES (?, 'future', TRUE, X'00', -1)
            "#,
        )
        .bind(CURRENT_SCHEMA_VERSION + 1)
        .execute(&persistence.pool)
        .await
        .unwrap();

        let error = persistence.run_migrations().await.unwrap_err();
        assert!(error.to_string().contains("failed to run sqlx migrations"));
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
            reason_code: "slow_non_progressing".to_string(),
            reason_details:
                "slow peer: avg_up_rate_bps=512 progress_delta=0.0010 bad_seconds=120 observed_seconds=180"
                    .to_string(),
        }
    }

    fn sample_active_ban() -> ActiveBanRecord {
        ActiveBanRecord {
            peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            peer_port: 51413,
            scope: "torrent:abc123".to_string(),
            offence_number: 2,
            reason: "slow_non_progressing".to_string(),
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
            reason_code: "slow_non_progressing".to_string(),
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
