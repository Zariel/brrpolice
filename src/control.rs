use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::{sync::watch, time};
use tracing::{debug, error, info, warn};

use crate::{
    config::AppConfig,
    metrics::AppMetrics,
    persistence::{ActiveBanRecord, Persistence, RecoverySnapshot},
    policy::PolicyEngine,
    qbittorrent::QbittorrentClient,
    runtime::ServiceState,
    types::{BanDisposition, PeerContext, TorrentScope},
};

pub struct ControlLoop {
    config: Arc<AppConfig>,
    persistence: Arc<Persistence>,
    qbittorrent: Arc<QbittorrentClient>,
    policy: Arc<PolicyEngine>,
    service_state: Arc<ServiceState>,
    metrics: Arc<AppMetrics>,
    shutdown: watch::Receiver<bool>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollCycleResult {
    pub torrent_count: usize,
    pub peer_count: usize,
    pub ban_count: usize,
}

const MAX_CYCLE_RETRIES: usize = 3;
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(50);

impl ControlLoop {
    pub fn new(
        config: Arc<AppConfig>,
        persistence: Arc<Persistence>,
        qbittorrent: Arc<QbittorrentClient>,
        policy: Arc<PolicyEngine>,
        service_state: Arc<ServiceState>,
        metrics: Arc<AppMetrics>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            persistence,
            qbittorrent,
            policy,
            service_state,
            metrics,
            shutdown,
        }
    }

    pub async fn recover_startup_state(&self) -> Result<RecoverySnapshot> {
        let snapshot = self.persistence.load_recovery_snapshot().await?;
        let now = std::time::SystemTime::now();
        let active_bans = snapshot
            .active_bans
            .iter()
            .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at > now)
            .cloned()
            .collect::<Vec<_>>();
        let expired_bans = snapshot
            .active_bans
            .iter()
            .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at <= now)
            .cloned()
            .collect::<Vec<_>>();
        let sync_result = self
            .qbittorrent
            .reconcile_expired_bans(&active_bans)
            .await?;
        self.mark_expired_bans_reconciled(&expired_bans, now)
            .await?;
        self.refresh_gauges().await?;
        self.service_state.mark_recovery_complete();
        info!(
            peer_session_count = snapshot.peer_sessions.len(),
            active_ban_count = snapshot.active_bans.len(),
            enforced_banned_ip_count = sync_result.banned_ips.len(),
            expired_ban_count = expired_bans.len(),
            "startup recovery completed"
        );
        Ok(snapshot)
    }

    pub async fn run(mut self) -> Result<()> {
        let mut interval = time::interval(self.config.qbittorrent.poll_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        self.service_state.mark_poll_loop_entered();

        info!("control loop started");

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.run_poll_cycle_with_retry().await {
                        Ok(cycle) => {
                            debug!(
                                torrent_count = cycle.torrent_count,
                                peer_count = cycle.peer_count,
                                ban_count = cycle.ban_count,
                                "control loop tick completed"
                            );
                        }
                        Err(error) => {
                            error!(?error, "control loop tick failed after retries");
                        }
                    }
                }
                _ = self.shutdown.changed() => {
                    info!("control loop stopping");
                    return Ok(());
                }
            }
        }
    }

    pub async fn run_poll_cycle(&self) -> Result<PollCycleResult> {
        let observed_at = std::time::SystemTime::now();
        self.reconcile_expired_bans(observed_at).await?;
        let torrents = self.qbittorrent.list_in_scope_torrents().await?;
        self.metrics.set_in_scope_torrents(torrents.len());
        let mut active_bans = self.persistence.load_active_bans().await?;
        let mut peer_count = 0;
        let mut ban_count = 0;

        for torrent in &torrents {
            let torrent_scope = TorrentScope {
                hash: torrent.hash.clone(),
                category: torrent.category.clone(),
                tags: torrent.tags.clone(),
                total_seeders: torrent.total_seeders,
                in_scope: true,
            };
            let peers = match self.qbittorrent.list_torrent_peers(&torrent.hash).await {
                Ok(peers) => peers,
                Err(error) => {
                    warn!(
                        torrent_hash = %torrent.hash,
                        error = ?error,
                        "skipping torrent after peer fetch failure"
                    );
                    continue;
                }
            };
            for peer in peers {
                peer_count += 1;
                let existing = self
                    .persistence
                    .get_peer_session(&peer.observation_id)
                    .await?;
                let first_seen_at = existing
                    .as_ref()
                    .map(|session| session.first_seen_at)
                    .unwrap_or(observed_at);
                let has_active_ban = has_active_ban(
                    &active_bans,
                    peer.observation_id.peer_ip,
                    peer.observation_id.peer_port,
                    &torrent.hash,
                    observed_at,
                );
                let peer_context = PeerContext {
                    torrent: torrent_scope.clone(),
                    peer: peer.peer.clone(),
                    first_seen_at,
                    observed_at,
                    has_active_ban,
                };
                let evaluation = self.policy.evaluate_peer(&peer_context, existing.as_ref());
                self.metrics.record_peer_evaluated(evaluation.is_bad_sample);
                let history = self
                    .persistence
                    .load_offence_history(&evaluation.session.offence_identity)
                    .await?;

                if evaluation.is_bad_sample {
                    warn!(
                        torrent_hash = %torrent.hash,
                        peer_ip = %peer.peer.ip,
                        peer_port = peer.peer.port,
                        observed_at = ?observed_at,
                        sample_duration_seconds = evaluation.sample_duration.as_secs(),
                        bad_time_seconds = evaluation.session.bad_duration.as_secs(),
                        progress_delta = evaluation.progress_delta,
                        average_upload_rate_bps = evaluation.session.rolling_avg_up_rate_bps,
                        "peer classified bad"
                    );
                }

                match self.policy.decide_ban(&peer_context, &evaluation, &history) {
                    BanDisposition::Ban(decision) => {
                        let active_before = active_bans
                            .iter()
                            .filter(|ban| {
                                ban.reconciled_at.is_none() && ban.expires_at > observed_at
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        self.qbittorrent
                            .apply_peer_ban(
                                &ActiveBanRecord {
                                    peer_ip: decision.peer_ip,
                                    peer_port: decision.peer_port,
                                    scope: format!("torrent:{}", torrent.hash),
                                    offence_number: decision.offence_number,
                                    reason: decision.reason.clone(),
                                    created_at: observed_at,
                                    expires_at: observed_at + decision.ttl,
                                    reconciled_at: None,
                                },
                                &active_before,
                            )
                            .await
                            .inspect_err(|error| {
                                self.metrics.record_ban_failure();
                                error!(
                                    torrent_hash = %torrent.hash,
                                    peer_ip = %decision.peer_ip,
                                    peer_port = decision.peer_port,
                                    offence_number = decision.offence_number,
                                    observed_at = ?observed_at,
                                    bad_time_seconds = evaluation.session.bad_duration.as_secs(),
                                    progress_delta = evaluation.progress_delta,
                                    average_upload_rate_bps = evaluation.session.rolling_avg_up_rate_bps,
                                    selected_ban_ttl_seconds = decision.ttl.as_secs(),
                                    reason_code = %decision.reason,
                                    error = ?error,
                                    "peer ban application failed"
                                );
                            })?;
                        let stored = self
                            .persistence
                            .record_ban_enforcement(&evaluation, &decision, observed_at)
                            .await
                            .inspect_err(|error| {
                                self.metrics.record_ban_failure();
                                error!(
                                    torrent_hash = %torrent.hash,
                                    peer_ip = %decision.peer_ip,
                                    peer_port = decision.peer_port,
                                    offence_number = decision.offence_number,
                                    observed_at = ?observed_at,
                                    bad_time_seconds = evaluation.session.bad_duration.as_secs(),
                                    progress_delta = evaluation.progress_delta,
                                    average_upload_rate_bps = evaluation.session.rolling_avg_up_rate_bps,
                                    selected_ban_ttl_seconds = decision.ttl.as_secs(),
                                    reason_code = %decision.reason,
                                    error = ?error,
                                    "peer ban persistence failed"
                                );
                            })?;
                        if let Some(active_ban) = stored.active_ban {
                            active_bans.push(active_ban);
                        }
                        if !stored.duplicate_suppressed {
                            ban_count += 1;
                            self.metrics
                                .record_ban_applied(evaluation.session.bad_duration);
                            info!(
                                torrent_hash = %torrent.hash,
                                peer_ip = %decision.peer_ip,
                                peer_port = decision.peer_port,
                                offence_number = decision.offence_number,
                                observed_at = ?observed_at,
                                bad_time_seconds = evaluation.session.bad_duration.as_secs(),
                                progress_delta = evaluation.progress_delta,
                                average_upload_rate_bps = evaluation.session.rolling_avg_up_rate_bps,
                                selected_ban_ttl_seconds = decision.ttl.as_secs(),
                                reason_code = %decision.reason,
                                "peer ban applied"
                            );
                        }
                    }
                    BanDisposition::Exempt(reason) => {
                        debug!(
                            torrent_hash = %torrent.hash,
                            peer_ip = %peer.peer.ip,
                            peer_port = peer.peer.port,
                            observed_at = ?observed_at,
                            bad_time_seconds = evaluation.session.bad_duration.as_secs(),
                            progress_delta = evaluation.progress_delta,
                            average_upload_rate_bps = evaluation.session.rolling_avg_up_rate_bps,
                            exemption_reason = ?reason,
                            "peer exemption decision"
                        );
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                    _ => {
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                }
            }
        }

        self.refresh_gauges().await?;

        Ok(PollCycleResult {
            torrent_count: torrents.len(),
            peer_count,
            ban_count,
        })
    }

    async fn run_poll_cycle_with_retry(&mut self) -> Result<PollCycleResult> {
        let mut attempt = 0;
        loop {
            let started = std::time::Instant::now();
            match self.run_poll_cycle().await {
                Ok(result) => {
                    self.metrics.record_poll_loop_duration(started.elapsed());
                    self.metrics
                        .mark_successful_poll(std::time::SystemTime::now());
                    self.service_state.mark_runtime_healthy();
                    return Ok(result);
                }
                Err(error) => {
                    self.metrics.record_poll_loop_duration(started.elapsed());
                    self.service_state.mark_runtime_unhealthy();
                    if attempt >= MAX_CYCLE_RETRIES {
                        return Err(error);
                    }

                    let delay = RETRY_BACKOFF_BASE * (1_u32 << attempt);
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_CYCLE_RETRIES,
                        backoff_ms = delay.as_millis(),
                        error = ?error,
                        "control loop tick failed; retrying"
                    );
                    time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn reconcile_expired_bans(&self, reconciled_at: std::time::SystemTime) -> Result<usize> {
        let expired_bans = self
            .persistence
            .list_expired_active_bans(reconciled_at)
            .await?;
        if expired_bans.is_empty() {
            return Ok(0);
        }

        let remaining_active_bans = self
            .persistence
            .load_active_bans()
            .await?
            .into_iter()
            .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at > reconciled_at)
            .collect::<Vec<_>>();

        self.qbittorrent
            .reconcile_expired_bans(&remaining_active_bans)
            .await
            .inspect_err(|error| {
                error!(
                    expired_ban_count = expired_bans.len(),
                    remaining_active_ban_count = remaining_active_bans.len(),
                    reconciled_at = ?reconciled_at,
                    error = ?error,
                    "expired ban reconciliation failed"
                );
            })?;

        self.mark_expired_bans_reconciled(&expired_bans, reconciled_at)
            .await?;
        self.metrics.record_bans_expired(expired_bans.len());
        self.refresh_gauges().await?;

        Ok(expired_bans.len())
    }

    async fn refresh_gauges(&self) -> Result<()> {
        self.metrics
            .set_active_tracked_peers(self.persistence.count_peer_sessions().await?);
        self.metrics
            .set_active_bans(self.persistence.count_active_bans().await?);
        self.metrics
            .set_sqlite_size_bytes(self.persistence.sqlite_size_bytes().await?);
        Ok(())
    }

    async fn mark_expired_bans_reconciled(
        &self,
        expired_bans: &[ActiveBanRecord],
        reconciled_at: std::time::SystemTime,
    ) -> Result<()> {
        for ban in expired_bans {
            self.persistence
                .mark_active_ban_reconciled(ban.peer_ip, ban.peer_port, &ban.scope, reconciled_at)
                .await?;
            self.revoke_expired_offence(ban, reconciled_at).await?;
            info!(
                scope = %ban.scope,
                peer_ip = %ban.peer_ip,
                peer_port = ban.peer_port,
                offence_number = ban.offence_number,
                created_at = ?ban.created_at,
                expires_at = ?ban.expires_at,
                reconciled_at = ?reconciled_at,
                reason_code = %ban.reason,
                "peer ban expired"
            );
        }

        Ok(())
    }

    async fn revoke_expired_offence(
        &self,
        ban: &ActiveBanRecord,
        revoked_at: std::time::SystemTime,
    ) -> Result<()> {
        let Some(torrent_hash) = ban.scope.strip_prefix("torrent:") else {
            return Ok(());
        };

        let offences = self
            .persistence
            .load_peer_offences_by_ip(ban.peer_ip)
            .await?;
        if let Some(offence_id) = offences
            .into_iter()
            .find(|offence| {
                offence.torrent_hash == torrent_hash
                    && offence.peer_port == ban.peer_port
                    && offence.offence_number == ban.offence_number
                    && offence.ban_revoked_at.is_none()
            })
            .and_then(|offence| offence.id)
        {
            self.persistence
                .revoke_peer_offence(offence_id, revoked_at)
                .await?;
        }

        Ok(())
    }
}

fn has_active_ban(
    active_bans: &[ActiveBanRecord],
    peer_ip: std::net::IpAddr,
    peer_port: u16,
    torrent_hash: &str,
    observed_at: std::time::SystemTime,
) -> bool {
    let scope = format!("torrent:{torrent_hash}");
    active_bans.iter().any(|ban| {
        ban.peer_ip == peer_ip
            && ban.peer_port == peer_port
            && ban.scope == scope
            && ban.reconciled_at.is_none()
            && ban.expires_at > observed_at
    })
}

#[cfg(test)]
mod tests {
    use std::{io, path::PathBuf, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::watch,
    };

    use crate::{
        config::{
            AppConfig, BanLadderConfig, DatabaseConfig, FiltersConfig, HttpConfig, LoggingConfig,
            PolicyConfig, QbittorrentConfig,
        },
        metrics::AppMetrics,
        persistence::{ActiveBanRecord, Persistence},
        policy::PolicyEngine,
        runtime::ServiceState,
        types::{OffenceIdentity, PeerObservationId, PeerSessionState},
    };

    use super::ControlLoop;

    #[tokio::test]
    async fn startup_recovery_loads_snapshot_and_marks_recovery_complete() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let rounded_now = std::time::UNIX_EPOCH
            + Duration::from_secs(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        let active_ban = ActiveBanRecord {
            peer_ip: "10.0.0.10".parse().unwrap(),
            peer_port: 51413,
            scope: "torrent:abc123".to_string(),
            offence_number: 1,
            reason: "slow peer".to_string(),
            created_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
            expires_at: rounded_now + Duration::from_secs(3600),
            reconciled_at: None,
        };
        persistence.upsert_active_ban(&active_ban).await.unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json=", "10.0.0.10"],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["cookie: SID=abc", "json=", "10.0.0.10"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();

        let config = Arc::new(test_config(&base_url));
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let control = ControlLoop::new(
            config,
            persistence,
            qbittorrent,
            policy,
            state.clone(),
            metrics,
            shutdown_rx,
        );

        let snapshot = control.recover_startup_state().await.unwrap();
        assert_eq!(snapshot.active_bans, vec![active_ban]);
        assert!(!state.is_ready());
        state.mark_poll_loop_entered();
        assert!(state.is_ready());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_recovery_reconciles_expired_bans_and_revokes_offence() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let expired_ban = ActiveBanRecord {
            peer_ip: "10.0.0.10".parse().unwrap(),
            peer_port: 51413,
            scope: "torrent:abc123".to_string(),
            offence_number: 2,
            reason: "slow peer".to_string(),
            created_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
            expires_at: std::time::UNIX_EPOCH + Duration::from_secs(120),
            reconciled_at: None,
        };
        persistence.upsert_active_ban(&expired_ban).await.unwrap();
        let offence_id = persistence
            .insert_peer_offence(&crate::persistence::PeerOffenceRecord {
                id: None,
                torrent_hash: "abc123".to_string(),
                peer_ip: "10.0.0.10".parse().unwrap(),
                peer_port: 51413,
                offence_number: 2,
                reason_code: "slow peer".to_string(),
                observed_duration: Duration::from_secs(120),
                bad_duration: Duration::from_secs(120),
                progress_delta_per_mille: 0,
                avg_up_rate_bps: 128,
                banned_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
                ban_expires_at: std::time::UNIX_EPOCH + Duration::from_secs(120),
                ban_revoked_at: None,
            })
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![ExpectedRequest {
            method: "POST",
            path: "/api/v2/app/setPreferences",
            must_contain: vec!["json="],
            response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();

        let config = Arc::new(test_config(&base_url));
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let control = ControlLoop::new(
            config,
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        control.recover_startup_state().await.unwrap();

        let active_bans = persistence.load_active_bans().await.unwrap();
        assert_eq!(active_bans.len(), 1);
        assert!(active_bans[0].reconciled_at.is_some());
        let offences = persistence
            .load_peer_offences_by_ip("10.0.0.10".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(offences.len(), 1);
        assert_eq!(offences[0].id, Some(offence_id));
        assert!(offences[0].ban_revoked_at.is_some());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_orchestrates_ban_and_persistence() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        persistence
            .upsert_peer_session(
                &PeerSessionState {
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip: "10.0.0.10".parse().unwrap(),
                        peer_port: 51413,
                    },
                    offence_identity: OffenceIdentity {
                        peer_ip: "10.0.0.10".parse().unwrap(),
                    },
                    first_seen_at: std::time::UNIX_EPOCH,
                    last_seen_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
                    baseline_progress: 0.10,
                    latest_progress: 0.10,
                    rolling_avg_up_rate_bps: 512,
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    sample_count: 2,
                    last_torrent_seeder_count: 5,
                    last_exemption_reason: None,
                    bannable_since: Some(std::time::UNIX_EPOCH + Duration::from_secs(30)),
                    last_ban_decision_at: None,
                },
                "policy-v1",
            )
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"abc123\",\"name\":\"Example\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5}]",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51413\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51413,\"progress\":0.1005,\"dl_speed\":1024,\"up_speed\":128}},\"peers_removed\":[]}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["cookie: SID=abc", "peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["cookie: SID=abc", "json=", "10.0.0.10"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();

        let mut config = test_config(&base_url);
        config.policy = PolicyConfig {
            slow_rate_bps: 1024,
            min_progress_delta: 0.01,
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(1),
            bad_for_duration: Duration::from_secs(1),
            decay_window: Duration::from_secs(3600),
            ignore_peer_progress_at_or_above: 0.95,
            min_total_seeders: 1,
            reban_cooldown: Duration::from_secs(1),
            ban_ladder: BanLadderConfig {
                durations: vec![Duration::from_secs(3600)],
            },
        };
        let config = Arc::new(config);
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let control = ControlLoop::new(
            config,
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        let result = control.run_poll_cycle().await.unwrap();
        assert_eq!(
            result,
            super::PollCycleResult {
                torrent_count: 1,
                peer_count: 1,
                ban_count: 1,
            }
        );
        assert_eq!(persistence.load_active_bans().await.unwrap().len(), 1);
        assert_eq!(
            persistence
                .load_peer_offences_by_ip("10.0.0.10".parse().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            persistence
                .get_peer_session(&PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.10".parse().unwrap(),
                    peer_port: 51413,
                })
                .await
                .unwrap()
                .unwrap()
                .last_ban_decision_at
                .is_some()
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_skips_torrent_after_peer_fetch_failure() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"bad111\",\"name\":\"Broken\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5},{\"hash\":\"good222\",\"name\":\"Healthy\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5}]",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=bad111&rid=0",
                must_contain: vec![],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=good222&rid=0",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.20:51413\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.20\",\"port\":51413,\"progress\":0.10,\"dl_speed\":1024,\"up_speed\":2048}},\"peers_removed\":[]}",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();

        let config = Arc::new(test_config(&base_url));
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let control = ControlLoop::new(
            config,
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        let result = control.run_poll_cycle().await.unwrap();
        assert_eq!(
            result,
            super::PollCycleResult {
                torrent_count: 2,
                peer_count: 1,
                ban_count: 0,
            }
        );
        assert!(
            persistence
                .get_peer_session(&PeerObservationId {
                    torrent_hash: "good222".to_string(),
                    peer_ip: "10.0.0.20".parse().unwrap(),
                    peer_port: 51413,
                })
                .await
                .unwrap()
                .is_some()
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_with_retry_restores_readiness_after_transient_failure() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=seeding",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();
        state.mark_poll_loop_entered();
        assert!(state.is_ready());

        let config = Arc::new(test_config(&base_url));
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
            config,
            persistence,
            qbittorrent,
            policy,
            state.clone(),
            metrics,
            shutdown_rx,
        );

        let task = tokio::spawn(async move { control.run_poll_cycle_with_retry().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!state.is_ready());

        let result = task.await.unwrap();
        assert_eq!(
            result,
            super::PollCycleResult {
                torrent_count: 0,
                peer_count: 0,
                ban_count: 0,
            }
        );
        assert!(state.is_ready());

        server.await.unwrap();
    }

    fn test_config(base_url: &str) -> AppConfig {
        AppConfig {
            qbittorrent: QbittorrentConfig {
                base_url: base_url.to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: Duration::from_secs(30),
                request_timeout: Duration::from_secs(10),
            },
            policy: PolicyConfig {
                slow_rate_bps: 262_144,
                min_progress_delta: 0.0025,
                new_peer_grace_period: Duration::from_secs(300),
                min_observation_duration: Duration::from_secs(1200),
                bad_for_duration: Duration::from_secs(900),
                decay_window: Duration::from_secs(3600),
                ignore_peer_progress_at_or_above: 0.95,
                min_total_seeders: 3,
                reban_cooldown: Duration::from_secs(1800),
                ban_ladder: BanLadderConfig {
                    durations: vec![Duration::from_secs(3600)],
                },
            },
            filters: FiltersConfig::default(),
            database: DatabaseConfig {
                path: PathBuf::from(":memory:"),
                busy_timeout: Duration::from_secs(1),
            },
            http: HttpConfig {
                bind: "127.0.0.1:0".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "plain".to_string(),
            },
        }
    }

    async fn test_persistence() -> Persistence {
        Persistence::connect(&DatabaseConfig {
            path: PathBuf::from(":memory:"),
            busy_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap()
    }

    #[derive(Clone)]
    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        must_contain: Vec<&'static str>,
        response: &'static str,
    }

    async fn spawn_server(
        expected_requests: Vec<ExpectedRequest>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for expected in expected_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut stream).await.unwrap();
                assert!(request.starts_with(&format!("{} {} ", expected.method, expected.path)));
                for needle in expected.must_contain {
                    assert!(
                        request.contains(needle),
                        "request missing `{needle}`: {request}"
                    );
                }
                stream
                    .write_all(expected.response.as_bytes())
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        (format!("http://{address}/"), handle)
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> io::Result<String> {
        let mut buffer = Vec::new();
        let mut header = [0_u8; 1024];
        loop {
            let read = stream.read(&mut header).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&header[..read]);
            if let Some(request) = complete_request(&buffer) {
                return Ok(request);
            }
        }
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    fn complete_request(buffer: &[u8]) -> Option<String> {
        let marker = b"\r\n\r\n";
        let header_end = buffer
            .windows(marker.len())
            .position(|window| window == marker)?;
        let header_end = header_end + marker.len();
        let request = String::from_utf8_lossy(buffer).to_string();
        let content_length = request
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if buffer.len() >= header_end + content_length {
            Some(request)
        } else {
            None
        }
    }
}
