use std::sync::Arc;

use anyhow::Result;
use tokio::{sync::watch, time};
use tracing::{debug, info};

use crate::{
    config::AppConfig,
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
    shutdown: watch::Receiver<bool>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollCycleResult {
    pub torrent_count: usize,
    pub peer_count: usize,
    pub ban_count: usize,
}

impl ControlLoop {
    pub fn new(
        config: Arc<AppConfig>,
        persistence: Arc<Persistence>,
        qbittorrent: Arc<QbittorrentClient>,
        policy: Arc<PolicyEngine>,
        service_state: Arc<ServiceState>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            persistence,
            qbittorrent,
            policy,
            service_state,
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
        let sync_result = self.qbittorrent.reconcile_expired_bans(&active_bans).await?;
        self.service_state.mark_recovery_complete();
        info!(
            peer_session_count = snapshot.peer_sessions.len(),
            active_ban_count = snapshot.active_bans.len(),
            enforced_banned_ip_count = sync_result.banned_ips.len(),
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
                    let cycle = self.run_poll_cycle().await?;
                    debug!(
                        torrent_count = cycle.torrent_count,
                        peer_count = cycle.peer_count,
                        ban_count = cycle.ban_count,
                        "control loop tick completed"
                    );
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
        let torrents = self.qbittorrent.list_in_scope_torrents().await?;
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
            let peers = self.qbittorrent.list_torrent_peers(&torrent.hash).await?;
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
                let history = self
                    .persistence
                    .load_offence_history(&evaluation.session.offence_identity)
                    .await?;

                match self.policy.decide_ban(&peer_context, &evaluation, &history) {
                    BanDisposition::Ban(decision) => {
                        let active_before = active_bans
                            .iter()
                            .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at > observed_at)
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
                            .await?;
                        let stored = self
                            .persistence
                            .record_ban_enforcement(&evaluation, &decision, observed_at)
                            .await?;
                        if let Some(active_ban) = stored.active_ban {
                            active_bans.push(active_ban);
                        }
                        if !stored.duplicate_suppressed {
                            ban_count += 1;
                        }
                    }
                    _ => {
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                }
            }
        }

        Ok(PollCycleResult {
            torrent_count: torrents.len(),
            peer_count,
            ban_count,
        })
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
    use std::{env, io, path::PathBuf, sync::Arc, time::Duration};

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

        let previous = env::var_os("QBITTORRENT_PASSWORD");
        unsafe { env::set_var("QBITTORRENT_PASSWORD", "secret") };

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();

        let config = Arc::new(test_config(&base_url));
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
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
            shutdown_rx,
        );

        let snapshot = control.recover_startup_state().await.unwrap();
        assert_eq!(snapshot.active_bans, vec![active_ban]);
        assert!(!state.is_ready());
        state.mark_poll_loop_entered();
        assert!(state.is_ready());

        restore_env("QBITTORRENT_PASSWORD", previous);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_orchestrates_ban_and_persistence() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
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

        let previous = env::var_os("QBITTORRENT_PASSWORD");
        unsafe { env::set_var("QBITTORRENT_PASSWORD", "secret") };

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
                config.filters.clone(),
                config.policy.min_total_seeders,
                config.qbittorrent.request_timeout,
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
            persistence.load_peer_offences_by_ip("10.0.0.10".parse().unwrap()).await.unwrap().len(),
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

        restore_env("QBITTORRENT_PASSWORD", previous);
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
                    assert!(request.contains(needle), "request missing `{needle}`: {request}");
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

    fn restore_env(key: &str, previous: Option<std::ffi::OsString>) {
        if let Some(value) = previous {
            unsafe { env::set_var(key, value) };
        } else {
            unsafe { env::remove_var(key) };
        }
    }
}
