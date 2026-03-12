use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::{sync::watch, time};
use tracing::{debug, info, warn};

use crate::{
    backoff::jittered_exponential_backoff,
    config::AppConfig,
    metrics::AppMetrics,
    persistence::{ActiveBanRecord, PendingBanIntentRecord, Persistence, RecoverySnapshot},
    policy::PolicyEngine,
    qbittorrent::QbittorrentClient,
    runtime::ServiceState,
    types::{
        BanDecision, BanDisposition, OffenceIdentity, PeerContext, PeerEvaluation,
        PeerObservationId, PeerSessionState, TorrentScope,
    },
};

macro_rules! info_peer_decision {
    (
        $message:literal,
        $torrent:expr,
        $torrent_tracker:expr,
        $peer:expr,
        $evaluation:expr,
        $observed_at_rfc3339:expr
        $(, $extra_key:ident = $extra_value:expr )* $(,)?
    ) => {
        info!(
            torrent_hash = %$torrent.hash,
            torrent_name = %$torrent.name,
            torrent_tracker = %$torrent_tracker,
            peer_ip = %$peer.peer.ip,
            peer_port = $peer.peer.port,
            observed_at = %$observed_at_rfc3339,
            bad_time_seconds = $evaluation.session.bad_duration.as_secs(),
            ban_score = $evaluation.session.ban_score,
            ban_score_above_threshold_seconds = $evaluation
                .session
                .ban_score_above_threshold_duration
                .as_secs(),
            sample_score_risk = $evaluation.sample_score_risk,
            progress_delta = $evaluation.progress_delta,
            average_upload_rate_bps = $evaluation.session.rolling_avg_up_rate_bps,
            churn_reconnect_count = $evaluation.session.churn_reconnect_count,
            churn_penalty = $evaluation.session.churn_penalty,
            sample_count = $evaluation.session.sample_count,
            $( $extra_key = $extra_value, )*
            $message
        );
    };
}

macro_rules! warn_ban_action {
    (
        $message:literal,
        $action:expr,
        $observed_at_rfc3339:expr
        $(, $extra_key:ident = $extra_value:expr )* $(,)?
    ) => {
        warn!(
            torrent_hash = %$action.torrent_hash,
            torrent_name = %$action.torrent_name,
            torrent_tracker = %$action.torrent_tracker,
            peer_ip = %$action.decision.peer_ip,
            peer_port = $action.decision.peer_port,
            offence_number = $action.decision.offence_number,
            observed_at = $observed_at_rfc3339,
            bad_time_seconds = $action.evaluation.session.bad_duration.as_secs(),
            ban_score = $action.evaluation.session.ban_score,
            ban_score_above_threshold_seconds = $action
                .evaluation
                .session
                .ban_score_above_threshold_duration
                .as_secs(),
            sample_score_risk = $action.evaluation.sample_score_risk,
            progress_delta = $action.evaluation.progress_delta,
            average_upload_rate_bps = $action.evaluation.session.rolling_avg_up_rate_bps,
            churn_reconnect_count = $action.evaluation.session.churn_reconnect_count,
            churn_penalty = $action.evaluation.session.churn_penalty,
            sample_count = $action.evaluation.session.sample_count,
            selected_ban_ttl_seconds = $action.decision.ttl.as_secs(),
            reason_code = %$action.decision.reason_code,
            reason_details = %$action.decision.reason_details,
            $( $extra_key = $extra_value, )*
            $message
        );
    };
}

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

#[derive(Debug, Clone)]
struct PendingBanAction {
    torrent_hash: String,
    torrent_name: String,
    torrent_tracker: String,
    decision: BanDecision,
    evaluation: PeerEvaluation,
    pending_intent: PendingBanIntentRecord,
}

const MAX_CYCLE_RETRIES: usize = 3;
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(50);
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(2);
const STARTUP_RETRY_BACKOFF_BASE: Duration = Duration::from_millis(250);
const STARTUP_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(5);
const MAX_PENDING_REPLAY_RETRIES: usize = 3;
const PENDING_REPLAY_BACKOFF_BASE: Duration = Duration::from_millis(50);
const PENDING_REPLAY_BACKOFF_MAX: Duration = Duration::from_secs(2);

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
        // Only unreconciled + unexpired rows represent bans that should still exist in qBittorrent.
        let mut active_bans = snapshot
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
        let previously_managed_bans = active_bans
            .iter()
            .chain(expired_bans.iter())
            .cloned()
            .collect::<Vec<_>>();
        let sync_result = self
            .qbittorrent
            .reconcile_expired_bans(&active_bans, &previously_managed_bans)
            .await?;
        self.mark_expired_bans_reconciled(&expired_bans, now)
            .await?;
        let (replayed_pending_count, dropped_stale_pending_count, failed_pending_count) = self
            .replay_pending_ban_intents(&snapshot.pending_ban_intents, &mut active_bans, now)
            .await?;
        self.refresh_gauges().await?;
        self.service_state.mark_recovery_complete();
        info!(
            peer_session_count = snapshot.peer_sessions.len(),
            active_ban_count = snapshot.active_bans.len(),
            enforced_banned_ip_count = sync_result.banned_ips.len(),
            expired_ban_count = expired_bans.len(),
            pending_ban_intent_count = snapshot.pending_ban_intents.len(),
            replayed_pending_ban_count = replayed_pending_count,
            dropped_stale_pending_ban_count = dropped_stale_pending_count,
            failed_pending_ban_replay_count = failed_pending_count,
            "startup recovery completed"
        );
        Ok(snapshot)
    }

    pub async fn run(mut self) -> Result<()> {
        info!("control loop starting");
        if !self.initialize_until_ready().await? {
            info!("control loop stopped before initialization completed");
            return Ok(());
        }

        let mut interval = time::interval(self.config.qbittorrent.poll_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        self.service_state.mark_poll_loop_entered();
        info!("control loop initialized and started");

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.run_poll_cycle_with_retry().await {
                        Ok(cycle) => {
                            if self.shutdown_requested() {
                                info!("control loop stopping");
                                return Ok(());
                            }
                            debug!(
                                torrent_count = cycle.torrent_count,
                                peer_count = cycle.peer_count,
                                ban_count = cycle.ban_count,
                                "control loop tick completed"
                            );
                        }
                        Err(error) => {
                            if self.shutdown_requested() {
                                info!("control loop stopping");
                                return Ok(());
                            }
                            warn!(?error, "control loop tick failed after retries");
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

    async fn initialize_until_ready(&mut self) -> Result<bool> {
        let mut attempt = 0_u32;
        loop {
            match self.initialize_once().await {
                Ok(()) => {
                    self.service_state.mark_runtime_healthy();
                    return Ok(true);
                }
                Err(error) => {
                    self.service_state.mark_runtime_unhealthy();
                    let delay = startup_retry_backoff(attempt);
                    warn!(
                        attempt = attempt + 1,
                        backoff_ms = delay.as_millis(),
                        error = ?error,
                        "control loop startup initialization failed; retrying"
                    );
                    attempt = attempt.saturating_add(1);
                    tokio::select! {
                        _ = time::sleep(delay) => {}
                        _ = self.shutdown.changed() => {
                            return Ok(false);
                        }
                    }
                }
            }
        }
    }

    async fn initialize_once(&self) -> Result<()> {
        self.qbittorrent.authenticate().await?;
        self.service_state.mark_qbittorrent_ready();
        let _ = self.recover_startup_state().await?;
        Ok(())
    }

    pub async fn run_poll_cycle(&self) -> Result<PollCycleResult> {
        let observed_at = std::time::SystemTime::now();
        let observed_at_rfc3339 = humantime::format_rfc3339_millis(observed_at).to_string();
        self.reconcile_expired_bans(observed_at).await?;
        let torrents = self.qbittorrent.list_in_scope_torrents().await?;
        self.metrics.set_in_scope_torrents(torrents.len());
        let mut active_bans = self.persistence.load_active_bans().await?;
        let mut peer_count = 0;
        let mut pending_ban_actions = Vec::new();

        'torrents: for torrent in &torrents {
            if self.shutdown_requested() {
                info!("shutdown requested; stopping poll cycle");
                break;
            }
            let torrent_scope = TorrentScope {
                hash: torrent.hash.clone(),
                name: torrent.name.clone(),
                tracker: torrent.tracker.clone(),
                category: torrent.category.clone(),
                tags: torrent.tags.clone(),
                total_seeders: torrent.total_seeders,
                in_scope: true,
            };
            let torrent_tracker = tracker_hostname(torrent.tracker.as_deref());
            let peers = match self.qbittorrent.list_torrent_peers(&torrent.hash).await {
                Ok(peers) => peers,
                Err(error) => {
                    warn!(
                        torrent_hash = %torrent.hash,
                        torrent_name = %torrent.name,
                        torrent_tracker = %torrent_tracker,
                        error = ?error,
                        "skipping torrent after peer fetch failure"
                    );
                    continue;
                }
            };
            for peer in peers {
                if self.shutdown_requested() {
                    info!("shutdown requested; stopping poll cycle");
                    break 'torrents;
                }
                peer_count += 1;
                let existing = self
                    .persistence
                    .get_peer_session(&peer.observation_id)
                    .await?;
                let carryover = if existing.is_none() {
                    self.persistence
                        .get_latest_peer_session_for_torrent_ip(
                            &peer.observation_id.torrent_hash,
                            peer.observation_id.peer_ip,
                        )
                        .await?
                        .filter(|session| {
                            observed_at >= session.last_seen_at
                                && observed_at
                                    .duration_since(session.last_seen_at)
                                    .unwrap_or_default()
                                    <= self.config.policy.decay_window
                        })
                } else {
                    None
                };
                let first_seen_at = existing
                    .as_ref()
                    .or(carryover.as_ref())
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
                let evaluation = self
                    .policy
                    .evaluate_peer(&peer_context, existing.as_ref().or(carryover.as_ref()));
                self.metrics.record_peer_evaluated(evaluation.is_bad_sample);
                self.metrics.record_score_evaluation(
                    evaluation.session.ban_score,
                    evaluation.sample_score_risk,
                    evaluation.session.ban_score_above_threshold_duration,
                    evaluation.is_bannable,
                );
                let history = self
                    .persistence
                    .load_offence_history(&evaluation.session.offence_identity)
                    .await?;

                if evaluation.is_bad_sample {
                    info_peer_decision!(
                        "peer classified bad",
                        torrent,
                        torrent_tracker,
                        peer,
                        evaluation,
                        observed_at_rfc3339,
                        sample_duration_seconds = evaluation.sample_duration.as_secs(),
                        latest_peer_progress = peer.peer.progress
                    );
                }

                match self.policy.decide_ban(&peer_context, &evaluation, &history) {
                    BanDisposition::Ban(decision) => {
                        self.metrics.record_policy_ban_decision();
                        // Persist intent before calling qBittorrent so startup recovery can
                        // replay or cleanly drop unfinished enforcement attempts.
                        let pending_intent = PendingBanIntentRecord {
                            torrent_hash: torrent.hash.clone(),
                            peer_ip: decision.peer_ip,
                            peer_port: decision.peer_port,
                            offence_number: decision.offence_number,
                            reason_code: decision.reason_code.clone(),
                            observed_at,
                            ban_expires_at: observed_at + decision.ttl,
                            bad_duration: evaluation.session.bad_duration,
                            progress_delta_per_mille: progress_delta_per_mille(
                                evaluation.progress_delta,
                            ),
                            avg_up_rate_bps: evaluation.session.rolling_avg_up_rate_bps,
                            last_error: "pending qbittorrent enforcement".to_string(),
                        };
                        self.persistence
                            .upsert_pending_ban_intent(&pending_intent)
                            .await?;
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                        pending_ban_actions.push(PendingBanAction {
                            torrent_hash: torrent.hash.clone(),
                            torrent_name: torrent.name.clone(),
                            torrent_tracker: torrent_tracker.clone(),
                            decision,
                            evaluation,
                            pending_intent,
                        });
                    }
                    BanDisposition::Exempt(reason) => {
                        self.metrics.record_policy_exemption_decision();
                        info_peer_decision!(
                            "peer exemption decision",
                            torrent,
                            torrent_tracker,
                            peer,
                            evaluation,
                            observed_at_rfc3339,
                            exemption_reason = format!("{reason:?}"),
                            latest_peer_progress = peer.peer.progress
                        );
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                    BanDisposition::NotBannableYet {
                        observed_duration,
                        required_observation,
                        bad_duration,
                        required_bad_duration,
                    } => {
                        self.metrics.record_policy_not_bannable_decision();
                        info_peer_decision!(
                            "peer not bannable yet decision",
                            torrent,
                            torrent_tracker,
                            peer,
                            evaluation,
                            observed_at_rfc3339,
                            observed_duration_seconds = observed_duration.as_secs(),
                            required_observation_seconds = required_observation.as_secs(),
                            observed_bad_duration_seconds = bad_duration.as_secs(),
                            required_bad_duration_seconds = required_bad_duration.as_secs(),
                            latest_peer_progress = peer.peer.progress
                        );
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                    BanDisposition::RebanCooldown { remaining } => {
                        self.metrics.record_policy_reban_cooldown_decision();
                        info_peer_decision!(
                            "peer reban cooldown decision",
                            torrent,
                            torrent_tracker,
                            peer,
                            evaluation,
                            observed_at_rfc3339,
                            reban_cooldown_remaining_seconds = remaining.as_secs(),
                            latest_peer_progress = peer.peer.progress
                        );
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                    BanDisposition::DuplicateSuppressed => {
                        self.metrics.record_policy_duplicate_suppressed_decision();
                        info_peer_decision!(
                            "peer duplicate ban suppression decision",
                            torrent,
                            torrent_tracker,
                            peer,
                            evaluation,
                            observed_at_rfc3339,
                            latest_peer_progress = peer.peer.progress
                        );
                        self.persistence
                            .upsert_peer_session(&evaluation.session, "policy-v1")
                            .await?;
                    }
                }
            }
        }

        let ban_count = self
            .enforce_pending_bans(
                &pending_ban_actions,
                &mut active_bans,
                observed_at,
                &observed_at_rfc3339,
            )
            .await?;
        self.refresh_gauges().await?;

        Ok(PollCycleResult {
            torrent_count: torrents.len(),
            peer_count,
            ban_count,
        })
    }

    async fn enforce_pending_bans(
        &self,
        actions: &[PendingBanAction],
        active_bans: &mut Vec<ActiveBanRecord>,
        observed_at: std::time::SystemTime,
        observed_at_rfc3339: &str,
    ) -> Result<usize> {
        if actions.is_empty() {
            return Ok(0);
        }

        let active_before = active_bans
            .iter()
            .filter(|ban| ban.reconciled_at.is_none() && ban.expires_at > observed_at)
            .cloned()
            .collect::<Vec<_>>();
        let requested_bans = actions
            .iter()
            .map(|action| ActiveBanRecord {
                peer_ip: action.decision.peer_ip,
                peer_port: action.decision.peer_port,
                scope: format!("torrent:{}", action.torrent_hash),
                offence_number: action.decision.offence_number,
                reason: action.decision.reason_code.clone(),
                created_at: observed_at,
                expires_at: observed_at + action.decision.ttl,
                reconciled_at: None,
            })
            .collect::<Vec<_>>();

        if let Err(error) = self
            .qbittorrent
            .apply_peer_bans(&requested_bans, &active_before)
            .await
        {
            for action in actions {
                self.metrics.record_ban_failure();
                warn_ban_action!(
                    "peer ban application failed",
                    action,
                    observed_at_rfc3339,
                    error = error.to_string(),
                );
                let mut failed_intent = action.pending_intent.clone();
                failed_intent.last_error = error.to_string();
                self.persistence
                    .upsert_pending_ban_intent(&failed_intent)
                    .await?;
            }
            return Err(error);
        }

        let mut ban_count = 0;
        for action in actions {
            let stored = match self
                .persistence
                .record_ban_enforcement(&action.evaluation, &action.decision, observed_at)
                .await
            {
                Ok(stored) => stored,
                Err(error) => {
                    self.metrics.record_ban_failure();
                    warn_ban_action!(
                        "peer ban persistence failed",
                        action,
                        observed_at_rfc3339,
                        error = error.to_string(),
                    );
                    let mut failed_intent = action.pending_intent.clone();
                    failed_intent.last_error = error.to_string();
                    self.persistence
                        .upsert_pending_ban_intent(&failed_intent)
                        .await?;
                    return Err(error);
                }
            };
            self.persistence
                .delete_pending_ban_intent(
                    &action.torrent_hash,
                    action.decision.peer_ip,
                    action.decision.peer_port,
                    action.decision.offence_number,
                )
                .await?;
            if let Some(active_ban) = stored.active_ban {
                active_bans.push(active_ban);
            }
            if !stored.duplicate_suppressed {
                ban_count += 1;
                self.metrics.record_ban_applied(
                    action.evaluation.session.bad_duration,
                    &action.decision.reason_code,
                );
                warn_ban_action!("peer ban applied", action, observed_at_rfc3339,);
            }
        }

        Ok(ban_count)
    }

    async fn run_poll_cycle_with_retry(&mut self) -> Result<PollCycleResult> {
        let mut attempt = 0;
        let mut shutdown = self.shutdown.clone();
        loop {
            if *shutdown.borrow() {
                return Ok(PollCycleResult::default());
            }

            let started = std::time::Instant::now();
            // Allow shutdown to preempt an in-flight poll cycle at await boundaries
            // instead of waiting for the next outer interval tick.
            let cycle_result = tokio::select! {
                result = self.run_poll_cycle() => result,
                _ = wait_for_shutdown_signal(&mut shutdown) => {
                    return Ok(PollCycleResult::default());
                }
            };

            match cycle_result {
                Ok(result) => {
                    self.metrics.record_poll_loop_duration(started.elapsed());
                    self.metrics
                        .mark_successful_poll(std::time::SystemTime::now());
                    self.service_state.mark_runtime_healthy();
                    return Ok(result);
                }
                Err(error) => {
                    self.metrics.record_poll_loop_duration(started.elapsed());
                    if attempt >= MAX_CYCLE_RETRIES {
                        self.service_state.mark_runtime_unhealthy();
                        return Err(error);
                    }

                    let delay = jittered_exponential_backoff(
                        RETRY_BACKOFF_BASE,
                        attempt as u32,
                        RETRY_BACKOFF_MAX,
                    );
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_CYCLE_RETRIES,
                        backoff_ms = delay.as_millis(),
                        error = ?error,
                        "control loop tick failed; retrying"
                    );
                    tokio::select! {
                        _ = time::sleep(delay) => {}
                        _ = wait_for_shutdown_signal(&mut shutdown) => {
                            return Ok(PollCycleResult::default());
                        }
                    }
                    attempt += 1;
                }
            }
        }
    }

    fn shutdown_requested(&self) -> bool {
        *self.shutdown.borrow()
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
            .reconcile_expired_bans(&remaining_active_bans, &expired_bans)
            .await
            .inspect_err(|error| {
                warn!(
                    expired_ban_count = expired_bans.len(),
                    remaining_active_ban_count = remaining_active_bans.len(),
                    reconciled_at = %format_timestamp(reconciled_at),
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

    async fn replay_pending_ban_intents(
        &self,
        pending_ban_intents: &[PendingBanIntentRecord],
        active_bans: &mut Vec<ActiveBanRecord>,
        recovered_at: std::time::SystemTime,
    ) -> Result<(usize, usize, usize)> {
        let mut replayed = 0;
        let mut stale_dropped = 0;
        let mut failed = 0;

        let mut shutdown = self.shutdown.clone();
        for intent in pending_ban_intents {
            if intent.ban_expires_at <= recovered_at {
                self.persistence
                    .delete_pending_ban_intent(
                        &intent.torrent_hash,
                        intent.peer_ip,
                        intent.peer_port,
                        intent.offence_number,
                    )
                    .await?;
                stale_dropped += 1;
                info!(
                    torrent_hash = %intent.torrent_hash,
                    peer_ip = %intent.peer_ip,
                    peer_port = intent.peer_port,
                    offence_number = intent.offence_number,
                    ban_expires_at = %format_timestamp(intent.ban_expires_at),
                    "dropped stale pending ban intent during startup recovery"
                );
                continue;
            }

            let mut attempt = 0;
            loop {
                match self
                    .replay_pending_ban_intent(intent, active_bans, recovered_at)
                    .await
                {
                    Ok(()) => {
                        replayed += 1;
                        break;
                    }
                    Err(error) if attempt + 1 < MAX_PENDING_REPLAY_RETRIES => {
                        let delay = jittered_exponential_backoff(
                            PENDING_REPLAY_BACKOFF_BASE,
                            attempt as u32,
                            PENDING_REPLAY_BACKOFF_MAX,
                        );
                        warn!(
                            torrent_hash = %intent.torrent_hash,
                            peer_ip = %intent.peer_ip,
                            peer_port = intent.peer_port,
                            offence_number = intent.offence_number,
                            retry_attempt = attempt + 1,
                            max_retries = MAX_PENDING_REPLAY_RETRIES,
                            backoff_ms = delay.as_millis(),
                            error = ?error,
                            "pending ban replay failed; retrying"
                        );
                        tokio::select! {
                            _ = time::sleep(delay) => {}
                            _ = wait_for_shutdown_signal(&mut shutdown) => {
                                return Ok((replayed, stale_dropped, failed));
                            }
                        }
                        attempt += 1;
                    }
                    Err(error) => {
                        failed += 1;
                        warn!(
                            torrent_hash = %intent.torrent_hash,
                            peer_ip = %intent.peer_ip,
                            peer_port = intent.peer_port,
                            offence_number = intent.offence_number,
                            retries = MAX_PENDING_REPLAY_RETRIES,
                            error = ?error,
                            "pending ban replay exhausted retries; intent retained"
                        );
                        break;
                    }
                }
            }
        }

        Ok((replayed, stale_dropped, failed))
    }

    async fn replay_pending_ban_intent(
        &self,
        intent: &PendingBanIntentRecord,
        active_bans: &mut Vec<ActiveBanRecord>,
        recovered_at: std::time::SystemTime,
    ) -> Result<()> {
        let ttl = intent
            .ban_expires_at
            .duration_since(recovered_at)
            .unwrap_or_default();
        if ttl.is_zero() {
            self.persistence
                .delete_pending_ban_intent(
                    &intent.torrent_hash,
                    intent.peer_ip,
                    intent.peer_port,
                    intent.offence_number,
                )
                .await?;
            return Ok(());
        }

        let active_ban = ActiveBanRecord {
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
            scope: format!("torrent:{}", intent.torrent_hash),
            offence_number: intent.offence_number,
            reason: intent.reason_code.clone(),
            created_at: recovered_at,
            expires_at: intent.ban_expires_at,
            reconciled_at: None,
        };

        if let Err(error) = self
            .qbittorrent
            .apply_peer_ban(&active_ban, active_bans)
            .await
        {
            self.persistence
                .upsert_pending_ban_intent(&PendingBanIntentRecord {
                    last_error: error.to_string(),
                    ..intent.clone()
                })
                .await?;
            self.metrics.record_ban_failure();
            return Err(error);
        }

        let observation_id = PeerObservationId {
            torrent_hash: intent.torrent_hash.clone(),
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
        };
        let existing_session = self.persistence.get_peer_session(&observation_id).await?;
        let session = existing_session.unwrap_or(PeerSessionState {
            observation_id,
            offence_identity: OffenceIdentity {
                torrent_hash: intent.torrent_hash.clone(),
                peer_ip: intent.peer_ip,
            },
            first_seen_at: intent.observed_at,
            last_seen_at: intent.observed_at,
            baseline_progress: 0.0,
            latest_progress: f64::from(intent.progress_delta_per_mille) / 1000.0,
            rolling_avg_up_rate_bps: intent.avg_up_rate_bps,
            observed_duration: intent.bad_duration,
            bad_duration: intent.bad_duration,
            ban_score: 0.0,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_penalty: 0.0,
            sample_count: 1,
            last_torrent_seeder_count: 0,
            last_exemption_reason: None,
            bannable_since: Some(intent.observed_at),
            last_ban_decision_at: None,
        });
        let progress_delta = f64::from(intent.progress_delta_per_mille) / 1000.0;
        let evaluation = PeerEvaluation {
            session,
            progress_delta,
            sample_duration: intent.bad_duration,
            sample_up_rate_bps: intent.avg_up_rate_bps,
            is_bad_sample: true,
            is_bannable: true,
            sample_score_risk: 0.0,
        };
        let decision = BanDecision {
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
            offence_number: intent.offence_number,
            ttl,
            reason_code: intent.reason_code.clone(),
            reason_details: "replayed pending intent".to_string(),
        };

        let stored = match self
            .persistence
            .record_ban_enforcement(&evaluation, &decision, recovered_at)
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                self.persistence
                    .upsert_pending_ban_intent(&PendingBanIntentRecord {
                        last_error: error.to_string(),
                        ..intent.clone()
                    })
                    .await?;
                self.metrics.record_ban_failure();
                return Err(error);
            }
        };
        self.persistence
            .delete_pending_ban_intent(
                &intent.torrent_hash,
                intent.peer_ip,
                intent.peer_port,
                intent.offence_number,
            )
            .await?;
        if let Some(active_ban) = stored.active_ban {
            active_bans.push(active_ban);
        }
        if !stored.duplicate_suppressed {
            self.metrics
                .record_ban_applied(intent.bad_duration, &intent.reason_code);
        }

        warn!(
            torrent_hash = %intent.torrent_hash,
            peer_ip = %intent.peer_ip,
            peer_port = intent.peer_port,
            offence_number = intent.offence_number,
            ban_expires_at = %format_timestamp(intent.ban_expires_at),
            "replayed pending ban intent during startup recovery"
        );
        Ok(())
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
                created_at = %format_timestamp(ban.created_at),
                expires_at = %format_timestamp(ban.expires_at),
                reconciled_at = %format_timestamp(reconciled_at),
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

fn startup_retry_backoff(attempt: u32) -> Duration {
    jittered_exponential_backoff(
        STARTUP_RETRY_BACKOFF_BASE,
        attempt.min(6),
        STARTUP_RETRY_BACKOFF_MAX,
    )
}

fn format_timestamp(value: std::time::SystemTime) -> String {
    humantime::format_rfc3339_millis(value).to_string()
}

async fn wait_for_shutdown_signal(shutdown: &mut watch::Receiver<bool>) {
    loop {
        match shutdown.changed().await {
            Ok(()) => {
                if *shutdown.borrow() {
                    return;
                }
            }
            Err(_) => std::future::pending::<()>().await,
        }
    }
}

fn progress_delta_per_mille(progress_delta: f64) -> u32 {
    (progress_delta.max(0.0) * 1000.0).round() as u32
}

fn tracker_hostname(tracker: Option<&str>) -> String {
    let Some(tracker) = tracker.map(str::trim).filter(|tracker| !tracker.is_empty()) else {
        return String::new();
    };

    parse_hostname(tracker)
        .or_else(|| parse_hostname(&format!("https://{tracker}")))
        .unwrap_or_default()
}

fn parse_hostname(input: &str) -> Option<String> {
    reqwest::Url::parse(input)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
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
    use std::{
        collections::VecDeque,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use tokio::{
        sync::watch,
        time::{self, timeout},
    };
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::any};

    use crate::{
        config::{
            AppConfig, BanLadderConfig, DatabaseConfig, FiltersConfig, HttpConfig, LoggingConfig,
            PolicyConfig, QbittorrentConfig,
        },
        metrics::AppMetrics,
        persistence::{ActiveBanRecord, PendingBanIntentRecord, Persistence},
        policy::PolicyEngine,
        runtime::ServiceState,
        types::{OffenceIdentity, PeerObservationId, PeerSessionState},
    };

    use super::{ControlLoop, tracker_hostname};

    #[test]
    fn tracker_hostname_extracts_hostname_from_url() {
        assert_eq!(
            tracker_hostname(Some("https://tracker.example.org/announce")),
            "tracker.example.org"
        );
        assert_eq!(
            tracker_hostname(Some("udp://tracker.example.org:1337/announce")),
            "tracker.example.org"
        );
    }

    #[test]
    fn tracker_hostname_handles_plain_hosts_and_invalid_values() {
        assert_eq!(
            tracker_hostname(Some("tracker.example.org:443")),
            "tracker.example.org"
        );
        assert_eq!(tracker_hostname(Some("not a valid tracker value")), "");
        assert_eq!(tracker_hostname(Some("")), "");
        assert_eq!(tracker_hostname(None), "");
    }

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
            reason: "slow_non_progressing".to_string(),
            created_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
            expires_at: rounded_now + Duration::from_secs(3600),
            reconciled_at: None,
        };
        persistence.upsert_active_ban(&active_ban).await.unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
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
                path: "/api/v2/app/preferences",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
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
            reason: "slow_non_progressing".to_string(),
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
                reason_code: "slow_non_progressing".to_string(),
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

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"10.0.0.10\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json="],
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
    async fn startup_recovery_replays_pending_ban_intent_and_clears_it() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        let intent = pending_ban_intent(
            "abc123",
            "10.0.0.10",
            51413,
            1,
            now - Duration::from_secs(30),
            now + Duration::from_secs(3600),
            "failed to apply qbittorrent peer ban",
        );
        persistence
            .upsert_pending_ban_intent(&intent)
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json="],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json=", "10.0.0.10"],
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
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        control.recover_startup_state().await.unwrap();
        assert!(
            persistence
                .load_pending_ban_intents()
                .await
                .unwrap()
                .is_empty()
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

        server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_recovery_drops_stale_pending_ban_intents() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        persistence
            .upsert_pending_ban_intent(&pending_ban_intent(
                "abc123",
                "10.0.0.10",
                51413,
                1,
                now - Duration::from_secs(600),
                now - Duration::from_secs(300),
                "expired while down",
            ))
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json="],
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
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        control.recover_startup_state().await.unwrap();
        assert!(
            persistence
                .load_pending_ban_intents()
                .await
                .unwrap()
                .is_empty()
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_recovery_retries_pending_ban_replay_and_retains_on_failure() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        persistence
            .upsert_pending_ban_intent(&pending_ban_intent(
                "abc123",
                "10.0.0.10",
                51413,
                1,
                now - Duration::from_secs(60),
                now + Duration::from_secs(600),
                "initial failure",
            ))
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["json="],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
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
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        control.recover_startup_state().await.unwrap();
        let pending = persistence.load_pending_ban_intents().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].last_error.contains("failed to apply"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_retries_startup_until_qb_becomes_available() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/auth/login",
                must_contain: vec!["username=admin", "password=secret"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: SID=abc; Path=/; HttpOnly\r\n\r\nOk.",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/app/setPreferences",
                must_contain: vec!["cookie: SID=abc", "json="],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=active",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        assert!(!state.is_ready());

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
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let control = ControlLoop::new(
            config,
            persistence,
            qbittorrent,
            policy,
            state.clone(),
            metrics,
            shutdown_rx,
        );

        let task = tokio::spawn(async move { control.run().await });

        timeout(Duration::from_secs(3), async {
            loop {
                if state.is_ready() {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("service should become ready after startup retry succeeds");

        time::sleep(Duration::from_millis(100)).await;
        shutdown_tx.send(true).unwrap();
        task.await.unwrap().unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_orchestrates_ban_and_persistence() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let seeded_now = std::time::SystemTime::now();
        persistence
            .upsert_peer_session(
                &PeerSessionState {
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip: "10.0.0.10".parse().unwrap(),
                        peer_port: 51413,
                    },
                    offence_identity: OffenceIdentity {
                        torrent_hash: "abc123".to_string(),
                        peer_ip: "10.0.0.10".parse().unwrap(),
                    },
                    first_seen_at: seeded_now - Duration::from_secs(180),
                    last_seen_at: seeded_now - Duration::from_secs(60),
                    baseline_progress: 0.10,
                    latest_progress: 0.10,
                    rolling_avg_up_rate_bps: 512,
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    ban_score: 0.0,
                    ban_score_above_threshold_duration: Duration::ZERO,
                    churn_reconnect_count: 0,
                    churn_window_started_at: None,
                    churn_penalty: 0.0,
                    sample_count: 2,
                    last_torrent_seeder_count: 5,
                    last_exemption_reason: None,
                    bannable_since: Some(seeded_now - Duration::from_secs(30)),
                    last_ban_decision_at: None,
                },
                "policy-v1",
            )
            .await
            .unwrap();

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=active",
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
                path: "/api/v2/torrents/info?filter=active",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"abc123\",\"name\":\"Example\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5}]",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51414\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51414,\"progress\":0.1005,\"dl_speed\":1024,\"up_speed\":128}},\"peers_removed\":[]}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["cookie: SID=abc", "peers=10.0.0.10%3A51414"],
                response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/app/preferences",
                must_contain: vec!["cookie: SID=abc"],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"banned_IPs\":\"\"}",
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
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(3600),
            ignore_peer_progress_at_or_above: 0.95,
            min_total_seeders: 1,
            reban_cooldown: Duration::from_secs(1),
            score: crate::config::ScorePolicyConfig {
                target_rate_bps: 1_024,
                required_progress_delta: 0.01,
                weight_rate: 0.7,
                weight_progress: 0.3,
                rate_risk_floor: 0.4,
                ban_threshold: 0.5,
                clear_threshold: 0.25,
                sustain_duration: Duration::from_secs(1),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(1),
                max_score: 5.0,
                ..crate::config::ScorePolicyConfig::default()
            },
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
                .load_pending_ban_intents()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            persistence
                .get_peer_session(&PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip: "10.0.0.10".parse().unwrap(),
                    peer_port: 51414,
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
                path: "/api/v2/torrents/info?filter=active",
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
    async fn run_poll_cycle_with_retry_keeps_readiness_during_transient_failure() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let (base_url, server) = spawn_server(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=active",
                must_contain: vec![],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=active",
                must_contain: vec![],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/torrents/info?filter=active",
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
        let monitor_running = Arc::new(AtomicBool::new(true));
        let saw_unready = Arc::new(AtomicBool::new(false));
        let monitor_running_flag = monitor_running.clone();
        let saw_unready_flag = saw_unready.clone();
        let monitor_state = state.clone();
        let monitor = tokio::spawn(async move {
            while monitor_running_flag.load(Ordering::Relaxed) {
                if !monitor_state.is_ready() {
                    saw_unready_flag.store(true, Ordering::Relaxed);
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        });

        let result = timeout(Duration::from_secs(1), task)
            .await
            .expect("poll cycle retry task should complete")
            .unwrap();
        monitor_running.store(false, Ordering::Relaxed);
        monitor.await.unwrap();

        assert_eq!(
            result,
            super::PollCycleResult {
                torrent_count: 0,
                peer_count: 0,
                ban_count: 0,
            }
        );
        assert!(
            !saw_unready.load(Ordering::Relaxed),
            "service readiness should not flap during retry backoff"
        );
        assert!(state.is_ready());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_with_retry_stops_promptly_on_shutdown_during_backoff() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());

        let (base_url, server) = spawn_server(vec![ExpectedRequest {
            method: "GET",
            path: "/api/v2/torrents/info?filter=active",
            must_contain: vec![],
            response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
        }])
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
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
            config,
            persistence,
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        let task = tokio::spawn(async move { control.run_poll_cycle_with_retry().await.unwrap() });
        time::sleep(Duration::from_millis(10)).await;
        shutdown_tx.send(true).unwrap();

        let result = timeout(Duration::from_millis(250), task)
            .await
            .expect("poll cycle should stop promptly after shutdown signal")
            .unwrap();
        assert_eq!(result, super::PollCycleResult::default());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn run_poll_cycle_persists_pending_ban_intent_when_qb_ban_fails() {
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
                        torrent_hash: "abc123".to_string(),
                        peer_ip: "10.0.0.10".parse().unwrap(),
                    },
                    first_seen_at: std::time::UNIX_EPOCH,
                    last_seen_at: std::time::UNIX_EPOCH + Duration::from_secs(60),
                    baseline_progress: 0.10,
                    latest_progress: 0.10,
                    rolling_avg_up_rate_bps: 512,
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    ban_score: 0.0,
                    ban_score_above_threshold_duration: Duration::ZERO,
                    churn_reconnect_count: 0,
                    churn_window_started_at: None,
                    churn_penalty: 0.0,
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
                path: "/api/v2/torrents/info?filter=active",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"abc123\",\"name\":\"Example\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5}]",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51413\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51413,\"progress\":0.1005,\"dl_speed\":1024,\"up_speed\":128}},\"peers_removed\":[]}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51413"],
                response: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nnope\n",
            },
        ])
        .await;

        let state = Arc::new(ServiceState::new());
        state.mark_database_ready();
        state.mark_qbittorrent_ready();
        state.mark_recovery_complete();

        let mut config = test_config(&base_url);
        config.policy = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(3600),
            ignore_peer_progress_at_or_above: 0.95,
            min_total_seeders: 1,
            reban_cooldown: Duration::from_secs(1),
            score: crate::config::ScorePolicyConfig {
                target_rate_bps: 1_024,
                required_progress_delta: 0.01,
                weight_rate: 0.7,
                weight_progress: 0.3,
                rate_risk_floor: 0.4,
                ban_threshold: 0.5,
                clear_threshold: 0.25,
                sustain_duration: Duration::from_secs(1),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(1),
                max_score: 5.0,
                ..crate::config::ScorePolicyConfig::default()
            },
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

        let error = control.run_poll_cycle().await.unwrap_err();
        assert!(error.to_string().contains("failed to apply"));
        let pending = persistence.load_pending_ban_intents().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].torrent_hash, "abc123");
        assert_eq!(
            pending[0].peer_ip,
            "10.0.0.10".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(pending[0].peer_port, 51413);
        assert_eq!(pending[0].offence_number, 1);
        assert!(pending[0].last_error.contains("failed to apply"));
        let persisted_session = persistence
            .get_peer_session(&PeerObservationId {
                torrent_hash: "abc123".to_string(),
                peer_ip: "10.0.0.10".parse().unwrap(),
                peer_port: 51413,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted_session.sample_count, 3);
        assert_eq!(persisted_session.latest_progress, 0.1005);
        assert_eq!(persisted_session.last_ban_decision_at, None);
        assert!(persistence.load_active_bans().await.unwrap().is_empty());
        assert!(
            persistence
                .load_peer_offences_by_ip("10.0.0.10".parse().unwrap())
                .await
                .unwrap()
                .is_empty()
        );

        server.await.unwrap();
    }

    fn test_config(base_url: &str) -> AppConfig {
        AppConfig {
            qbittorrent: QbittorrentConfig {
                base_url: base_url.to_string(),
                username: "admin".to_string(),
                password_env: "QBITTORRENT_PASSWORD".to_string(),
                poll_interval: Duration::from_secs(15),
                request_timeout: Duration::from_secs(10),
                transient_retries: 10,
            },
            policy: PolicyConfig {
                new_peer_grace_period: Duration::from_secs(300),
                decay_window: Duration::from_secs(3600),
                ignore_peer_progress_at_or_above: 0.95,
                min_total_seeders: 3,
                reban_cooldown: Duration::from_secs(1800),
                score: crate::config::ScorePolicyConfig::default(),
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

    fn pending_ban_intent(
        torrent_hash: &str,
        peer_ip: &str,
        peer_port: u16,
        offence_number: u32,
        observed_at: std::time::SystemTime,
        ban_expires_at: std::time::SystemTime,
        last_error: &str,
    ) -> PendingBanIntentRecord {
        PendingBanIntentRecord {
            torrent_hash: torrent_hash.to_string(),
            peer_ip: peer_ip.parse().unwrap(),
            peer_port,
            offence_number,
            reason_code: "slow_non_progressing".to_string(),
            observed_at,
            ban_expires_at,
            bad_duration: Duration::from_secs(120),
            progress_delta_per_mille: 0,
            avg_up_rate_bps: 128,
            last_error: last_error.to_string(),
        }
    }

    #[derive(Clone)]
    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        must_contain: Vec<&'static str>,
        response: &'static str,
    }

    struct SequenceResponder {
        expected_requests: Arc<Mutex<VecDeque<ExpectedRequest>>>,
    }

    impl Respond for SequenceResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let expected = self
                .expected_requests
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected request: {}", format_request(request)));

            assert_eq!(
                request.method.as_str(),
                expected.method,
                "method mismatch for request: {}",
                format_request(request)
            );
            assert_eq!(
                request_path_and_query(request),
                expected.path,
                "path mismatch for request: {}",
                format_request(request)
            );
            let rendered = format_request(request);
            for needle in expected.must_contain {
                assert!(
                    rendered.contains(needle),
                    "request missing `{needle}`: {rendered}"
                );
            }

            response_template(expected.response)
        }
    }

    async fn spawn_server(
        expected_requests: Vec<ExpectedRequest>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let server = MockServer::start().await;
        let expected_requests = Arc::new(Mutex::new(VecDeque::from(expected_requests)));
        Mock::given(any())
            .respond_with(SequenceResponder {
                expected_requests: expected_requests.clone(),
            })
            .mount(&server)
            .await;
        let base_url = format!("{}/", server.uri());
        let handle = tokio::spawn(async move {
            let mut remaining = expected_requests.lock().unwrap().len();
            for _ in 0..500 {
                if remaining == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                remaining = expected_requests.lock().unwrap().len();
            }
            assert_eq!(
                remaining, 0,
                "{remaining} expected request(s) were not observed"
            );
            drop(server);
        });

        (base_url, handle)
    }

    fn request_path_and_query(request: &Request) -> String {
        let mut path = request.url.path().to_string();
        if let Some(query) = request.url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    }

    fn format_request(request: &Request) -> String {
        let mut rendered = format!("{} {}", request.method, request_path_and_query(request));
        for (name, value) in &request.headers {
            rendered.push_str("\r\n");
            rendered.push_str(name.as_str().to_ascii_lowercase().as_str());
            rendered.push_str(": ");
            rendered.push_str(value.to_str().unwrap_or_default());
        }
        rendered.push_str("\r\n\r\n");
        rendered.push_str(String::from_utf8_lossy(&request.body).as_ref());
        rendered
    }

    fn response_template(raw: &str) -> ResponseTemplate {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(200);
        let mut response = ResponseTemplate::new(status);
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                response = response.insert_header(name.trim(), value.trim());
            }
        }
        if !body.is_empty() {
            response = response.set_body_string(body.to_string());
        }
        response
    }
}
