use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::{sync::watch, time};
use tracing::{debug, info, warn};

use crate::{
    backoff::jittered_exponential_backoff,
    config::AppConfig,
    metrics::AppMetrics,
    persistence::{ActiveBanRecord, PendingBanIntentRecord, Persistence, RecoverySnapshot},
    policy::{PeerPolicyAdapter, PolicyCycleCache, PolicyDataStore, PolicyEngine},
    qbittorrent::QbittorrentClient,
    runtime::ServiceState,
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceIdentity, PeerContext,
        PeerPolicyAssessment, PolicyEvaluation, TorrentPeer, TorrentScope, TorrentSummary,
    },
};

macro_rules! log_ban_action {
    (
        $log:ident,
        $message:literal,
        $state:expr,
        $action:expr,
        $observed_at_rfc3339:expr
        $(, $extra_key:ident = $extra_value:expr )* $(,)?
    ) => {
        $log!(
            state = $state,
            policy_name = %$action.policy_name,
            torrent_hash = %$action.torrent_hash,
            torrent_name = %$action.torrent_name,
            torrent_tracker = %$action.torrent_tracker,
            peer_ip = %$action.decision.peer_ip,
            peer_port = $action.decision.peer_port,
            offence_number = $action.decision.offence_number,
            observed_at = $observed_at_rfc3339,
            bad_time_seconds = $action.evaluation.bad_duration().as_secs(),
            average_upload_rate_bps = $action.evaluation.avg_upload_rate_bps(),
            sample_count = $action.evaluation.sample_count(),
            selected_ban_ttl_seconds = $action.decision.ttl.as_secs(),
            reason_code = %$action.decision.reason_code,
            reason_details = %$action.decision.reason_details,
            diagnostics = ?$action.diagnostics,
            $( $extra_key = $extra_value, )*
            $message
        );
    };
}

macro_rules! log_policy_run {
    (
        $log:ident,
        $message:literal,
        $state:expr,
        $run:expr,
        $torrent:expr,
        $torrent_tracker:expr,
        $peer:expr,
        $observed_at_rfc3339:expr
        $(, $extra_key:ident = $extra_value:expr )* $(,)?
    ) => {
        $log!(
            state = $state,
            policy_name = %$run.policy_name,
            torrent_hash = %$torrent.hash,
            torrent_name = %$torrent.name,
            torrent_tracker = %$torrent_tracker,
            peer_ip = %$peer.peer.ip,
            peer_port = $peer.peer.port,
            observed_at = %$observed_at_rfc3339,
            bad_time_seconds = $run.evaluation.bad_duration().as_secs(),
            average_upload_rate_bps = $run.evaluation.avg_upload_rate_bps(),
            sample_count = $run.evaluation.sample_count(),
            latest_peer_progress = $peer.peer.progress,
            diagnostics = ?$run.diagnostics,
            $( $extra_key = $extra_value, )*
            $message
        );
    };
}

pub struct ControlLoop {
    config: Arc<AppConfig>,
    persistence: Arc<Persistence>,
    qbittorrent: Arc<QbittorrentClient>,
    peer_policies: Vec<Arc<dyn PeerPolicyAdapter>>,
    replay_policies: Vec<Arc<dyn PeerPolicyAdapter>>,
    service_state: Arc<ServiceState>,
    metrics: Arc<AppMetrics>,
    shutdown: watch::Receiver<bool>,
    peer_decision_log_states: HashMap<String, PeerDecisionLogState>,
    last_retention_prune_at: Option<std::time::SystemTime>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollCycleResult {
    pub torrent_count: usize,
    pub peer_count: usize,
    pub ban_count: usize,
}

#[derive(Clone)]
struct PendingBanAction {
    policy: Arc<dyn PeerPolicyAdapter>,
    torrent_hash: String,
    torrent_name: String,
    torrent_tracker: String,
    decision: BanDecision,
    evaluation: PendingBanEvaluation,
    policy_name: String,
    diagnostics: Vec<crate::types::PolicyDiagnostic>,
    pending_intent: PendingBanIntentRecord,
}

#[derive(Clone)]
struct PeerPolicyRun {
    policy: Arc<dyn PeerPolicyAdapter>,
    policy_name: &'static str,
    metric_label: &'static str,
    peer_key: String,
    evaluation: PendingBanEvaluation,
    disposition: BanDisposition,
    diagnostics: Vec<crate::types::PolicyDiagnostic>,
}

type PendingBanEvaluation = Box<dyn PolicyEvaluation>;

#[cfg(test)]
#[derive(Debug, PartialEq)]
struct PolicyRunLogSnapshot {
    state: &'static str,
    policy_name: &'static str,
    torrent_hash: String,
    torrent_name: String,
    torrent_tracker: String,
    peer_ip: std::net::IpAddr,
    peer_port: u16,
    bad_time_seconds: u64,
    average_upload_rate_bps: u64,
    sample_count: u32,
    latest_peer_progress: f64,
    diagnostics_count: usize,
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
struct BanActionLogSnapshot {
    state: &'static str,
    policy_name: String,
    torrent_hash: String,
    peer_ip: std::net::IpAddr,
    peer_port: u16,
    offence_number: u32,
    bad_time_seconds: u64,
    average_upload_rate_bps: u64,
    sample_count: u32,
    selected_ban_ttl_seconds: u64,
    reason_code: String,
    diagnostics_count: usize,
}

#[derive(Clone)]
struct ObservedPeer {
    torrent: TorrentSummary,
    torrent_tracker: String,
    peer: TorrentPeer,
    peer_context: PeerContext,
}

impl PeerPolicyRun {
    fn assessment(&self) -> PeerPolicyAssessment {
        PeerPolicyAssessment {
            policy_name: self.policy_name,
            evaluation: self.evaluation.clone(),
            disposition: self.disposition.clone(),
            diagnostics: self.diagnostics.clone(),
        }
    }

    #[cfg(test)]
    fn log_snapshot(
        &self,
        state: &'static str,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
    ) -> PolicyRunLogSnapshot {
        PolicyRunLogSnapshot {
            state,
            policy_name: self.policy_name,
            torrent_hash: torrent.hash.clone(),
            torrent_name: torrent.name.clone(),
            torrent_tracker: torrent_tracker.to_string(),
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
            bad_time_seconds: self.evaluation.bad_duration().as_secs(),
            average_upload_rate_bps: self.evaluation.avg_upload_rate_bps(),
            sample_count: self.evaluation.sample_count(),
            latest_peer_progress: peer.peer.progress,
            diagnostics_count: self.diagnostics.len(),
        }
    }
}

#[cfg(test)]
impl PendingBanAction {
    fn log_snapshot(&self, state: &'static str) -> BanActionLogSnapshot {
        BanActionLogSnapshot {
            state,
            policy_name: self.policy_name.clone(),
            torrent_hash: self.torrent_hash.clone(),
            peer_ip: self.decision.peer_ip,
            peer_port: self.decision.peer_port,
            offence_number: self.decision.offence_number,
            bad_time_seconds: self.evaluation.bad_duration().as_secs(),
            average_upload_rate_bps: self.evaluation.avg_upload_rate_bps(),
            sample_count: self.evaluation.sample_count(),
            selected_ban_ttl_seconds: self.decision.ttl.as_secs(),
            reason_code: self.decision.reason_code.clone(),
            diagnostics_count: self.diagnostics.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerDecisionLogState {
    Exempt {
        reason_code: &'static str,
    },
    NotBannableYet {
        policy_threshold_met: bool,
        unmet_observation_guardrail: bool,
        unmet_sustain_guardrail: bool,
    },
    RebanCooldown,
    DuplicateSuppressed,
    BanPending,
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
        let peer_policies = policy.enabled_peer_policies();
        let replay_policies = policy.replay_peer_policies();
        Self {
            config,
            persistence,
            qbittorrent,
            peer_policies,
            replay_policies,
            service_state,
            metrics,
            shutdown,
            peer_decision_log_states: HashMap::new(),
            last_retention_prune_at: None,
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
        let (replayed_pending_count, failed_pending_count) = self
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

    pub async fn run_poll_cycle(&mut self) -> Result<PollCycleResult> {
        let observed_at = std::time::SystemTime::now();
        let observed_at_rfc3339 = humantime::format_rfc3339_millis(observed_at).to_string();
        self.reconcile_expired_bans(observed_at).await?;
        let torrents = self.qbittorrent.list_in_scope_torrents().await?;
        self.metrics.set_in_scope_torrents(torrents.len());
        let mut active_bans = self.persistence.load_active_bans().await?;
        let mut peer_count = 0;
        let mut observed_peers = Vec::new();
        let mut pending_ban_actions = Vec::new();
        let mut seen_peer_keys = HashSet::new();

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
                    first_seen_at: observed_at,
                    observed_at,
                    has_active_ban,
                };
                observed_peers.push(ObservedPeer {
                    torrent: torrent.clone(),
                    torrent_tracker: torrent_tracker.to_string(),
                    peer,
                    peer_context,
                });
            }
        }

        let torrent_hashes = torrents
            .iter()
            .map(|torrent| torrent.hash.clone())
            .collect::<Vec<_>>();
        let policy_cache = PolicyCycleCache::load(
            self.persistence.as_ref(),
            &self.peer_policies,
            &torrent_hashes,
        )
        .await?;
        for observed_peer in &observed_peers {
            for policy in self.peer_policies.clone() {
                let run = self
                    .load_peer_policy_run(policy, &policy_cache, observed_peer, observed_at)
                    .await?;
                seen_peer_keys.insert(run.peer_key.clone());
                self.handle_peer_policy_run(
                    run,
                    &observed_peer.torrent,
                    &observed_peer.torrent_tracker,
                    &observed_peer.peer,
                    observed_at,
                    &observed_at_rfc3339,
                    &mut pending_ban_actions,
                )
                .await?;
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
        self.maybe_run_retention_prune(observed_at).await;
        self.peer_decision_log_states
            .retain(|key, _| seen_peer_keys.contains(key));
        self.refresh_gauges().await?;

        Ok(PollCycleResult {
            torrent_count: torrents.len(),
            peer_count,
            ban_count,
        })
    }

    async fn load_peer_policy_run(
        &self,
        policy: Arc<dyn PeerPolicyAdapter>,
        policy_store: &dyn PolicyDataStore,
        observed_peer: &ObservedPeer,
        observed_at: std::time::SystemTime,
    ) -> Result<PeerPolicyRun> {
        let previous_session = policy
            .load_previous_session(
                policy_store,
                &observed_peer.peer,
                observed_at,
                self.config.policy.decay_window,
            )
            .await?;
        let mut policy_context = observed_peer.peer_context.clone();
        if let Some(previous) = previous_session.as_ref() {
            policy_context.first_seen_at = previous.first_seen_at();
        }
        let history = policy
            .load_offence_history(policy_store, &policy_context)
            .await?;
        let assessment = policy.assess_peer(crate::types::PeerPolicyInput {
            peer: &policy_context,
            previous_session: previous_session.as_deref(),
            offence_history: &history,
        })?;
        if assessment.policy_name != policy.name() {
            bail!(
                "policy adapter `{}` returned assessment for `{}`",
                policy.name(),
                assessment.policy_name
            );
        }
        assessment.validate_telemetry()?;
        self.metrics
            .record_peer_evaluated(policy.metric_label(), assessment.evaluation.is_bad_sample());
        self.metrics
            .record_policy_evaluation(policy.metric_label(), assessment.evaluation.is_bannable());
        policy.record_policy_specific_metrics(&self.metrics, &assessment);
        let peer_key = peer_log_state_key(policy.name(), assessment.evaluation.offence_identity());
        let metric_label = policy.metric_label();
        Ok(PeerPolicyRun {
            policy,
            policy_name: assessment.policy_name,
            metric_label,
            peer_key,
            evaluation: assessment.evaluation,
            disposition: assessment.disposition,
            diagnostics: assessment.diagnostics,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_peer_policy_run(
        &mut self,
        run: PeerPolicyRun,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at: std::time::SystemTime,
        observed_at_rfc3339: &str,
        pending_ban_actions: &mut Vec<PendingBanAction>,
    ) -> Result<()> {
        let policy_name = run.policy_name;
        match &run.disposition {
            BanDisposition::Ban(decision) => {
                self.metrics.record_policy_ban_decision(run.metric_label);
                self.log_peer_policy_ban_pending(
                    &run,
                    decision,
                    torrent,
                    torrent_tracker,
                    peer,
                    observed_at_rfc3339,
                );
                let pending_intent = self.pending_ban_intent(&run, decision, torrent, observed_at);
                self.persistence
                    .upsert_pending_ban_intent(&pending_intent)
                    .await?;
                self.persist_peer_policy_assessment(&run).await?;
                pending_ban_actions.push(PendingBanAction {
                    policy: run.policy.clone(),
                    torrent_hash: torrent.hash.clone(),
                    torrent_name: torrent.name.clone(),
                    torrent_tracker: torrent_tracker.to_string(),
                    decision: decision.clone(),
                    evaluation: run.evaluation,
                    policy_name: policy_name.to_string(),
                    diagnostics: run.diagnostics,
                    pending_intent,
                });
            }
            BanDisposition::Exempt(reason) => {
                self.metrics
                    .record_policy_exemption_decision(run.metric_label);
                let state = PeerDecisionLogState::Exempt {
                    reason_code: exemption_reason_code(reason),
                };
                self.log_peer_policy_exempt(
                    &run,
                    reason,
                    state,
                    torrent,
                    torrent_tracker,
                    peer,
                    observed_at_rfc3339,
                );
                self.persist_peer_policy_assessment(&run).await?;
            }
            BanDisposition::NotBannableYet {
                observed_duration,
                required_observation,
                bad_duration,
                required_bad_duration,
            } => {
                self.metrics
                    .record_policy_not_bannable_decision(run.metric_label);
                let unmet_observation_guardrail = observed_duration < required_observation;
                let unmet_sustain_guardrail = bad_duration < required_bad_duration;
                let state = PeerDecisionLogState::NotBannableYet {
                    policy_threshold_met: run
                        .assessment()
                        .diagnostic_bool("threshold_met")
                        .unwrap_or_else(|| run.evaluation.is_bad_sample()),
                    unmet_observation_guardrail,
                    unmet_sustain_guardrail,
                };
                self.log_peer_policy_not_bannable(
                    &run,
                    *observed_duration,
                    *required_observation,
                    *bad_duration,
                    *required_bad_duration,
                    state,
                    torrent,
                    torrent_tracker,
                    peer,
                    observed_at_rfc3339,
                );
                self.persist_peer_policy_assessment(&run).await?;
            }
            BanDisposition::RebanCooldown { remaining } => {
                self.metrics
                    .record_policy_reban_cooldown_decision(run.metric_label);
                self.log_peer_policy_reban_cooldown(
                    &run,
                    *remaining,
                    torrent,
                    torrent_tracker,
                    peer,
                    observed_at_rfc3339,
                );
                self.persist_peer_policy_assessment(&run).await?;
            }
            BanDisposition::DuplicateSuppressed => {
                self.metrics
                    .record_policy_duplicate_suppressed_decision(run.metric_label);
                self.log_peer_policy_duplicate_suppressed(
                    &run,
                    torrent,
                    torrent_tracker,
                    peer,
                    observed_at_rfc3339,
                );
                self.persist_peer_policy_assessment(&run).await?;
            }
        }
        Ok(())
    }

    async fn persist_peer_policy_assessment(&self, run: &PeerPolicyRun) -> Result<()> {
        let assessment = run.assessment();
        run.policy
            .persist_assessment(&self.persistence, &assessment)
            .await
    }

    fn pending_ban_intent(
        &self,
        run: &PeerPolicyRun,
        decision: &BanDecision,
        torrent: &TorrentSummary,
        observed_at: std::time::SystemTime,
    ) -> PendingBanIntentRecord {
        let assessment = run.assessment();
        PendingBanIntentRecord {
            torrent_hash: torrent.hash.clone(),
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            policy_name: run.policy_name.to_string(),
            offence_number: decision.offence_number,
            reason_code: decision.reason_code.clone(),
            observed_at,
            ban_expires_at: observed_at + decision.ttl,
            bad_duration: assessment.evaluation.bad_duration(),
            progress_delta_per_mille: assessment.evaluation.progress_delta_per_mille(),
            avg_up_rate_bps: assessment.evaluation.avg_upload_rate_bps(),
            last_error: "pending qbittorrent enforcement".to_string(),
        }
    }

    fn log_peer_policy_ban_pending(
        &mut self,
        run: &PeerPolicyRun,
        decision: &BanDecision,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at_rfc3339: &str,
    ) {
        let state = PeerDecisionLogState::BanPending;
        log_policy_run!(
            info,
            "peer policy update",
            "ban_pending",
            run,
            torrent,
            torrent_tracker,
            peer,
            observed_at_rfc3339,
            offence_number = decision.offence_number,
            selected_ban_ttl_seconds = decision.ttl.as_secs(),
            reason_code = decision.reason_code.as_str(),
            reason_details = decision.reason_details.as_str()
        );
        if self.should_log_peer_decision_state_change(&run.peer_key, state) {
            log_policy_run!(
                warn,
                "peer ban pending decision",
                "ban_pending",
                run,
                torrent,
                torrent_tracker,
                peer,
                observed_at_rfc3339,
                offence_number = decision.offence_number,
                selected_ban_ttl_seconds = decision.ttl.as_secs(),
                reason_code = decision.reason_code.as_str(),
                reason_details = decision.reason_details.as_str()
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_peer_policy_exempt(
        &mut self,
        run: &PeerPolicyRun,
        reason: &ExemptionReason,
        state: PeerDecisionLogState,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at_rfc3339: &str,
    ) {
        log_policy_run!(
            info,
            "peer policy update",
            "exempt",
            run,
            torrent,
            torrent_tracker,
            peer,
            observed_at_rfc3339,
            exemption_reason = format!("{reason:?}")
        );
        if self.should_log_peer_decision_state_change(&run.peer_key, state) {
            log_policy_run!(
                warn,
                "peer exemption decision",
                "exempt",
                run,
                torrent,
                torrent_tracker,
                peer,
                observed_at_rfc3339,
                exemption_reason = format!("{reason:?}")
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_peer_policy_not_bannable(
        &mut self,
        run: &PeerPolicyRun,
        observed_duration: Duration,
        required_observation: Duration,
        bad_duration: Duration,
        required_bad_duration: Duration,
        state: PeerDecisionLogState,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at_rfc3339: &str,
    ) {
        let unmet_observation_guardrail = observed_duration < required_observation;
        let unmet_sustain_guardrail = bad_duration < required_bad_duration;
        let policy_threshold_met = run
            .assessment()
            .diagnostic_bool("threshold_met")
            .unwrap_or_else(|| run.evaluation.is_bad_sample());
        log_policy_run!(
            info,
            "peer policy update",
            "not_bannable",
            run,
            torrent,
            torrent_tracker,
            peer,
            observed_at_rfc3339,
            observed_duration_seconds = observed_duration.as_secs(),
            required_observation_seconds = required_observation.as_secs(),
            observed_bad_duration_seconds = bad_duration.as_secs(),
            required_bad_duration_seconds = required_bad_duration.as_secs(),
            policy_threshold_met = policy_threshold_met,
            is_bad_sample = run.evaluation.is_bad_sample(),
            unmet_observation_guardrail = unmet_observation_guardrail,
            unmet_sustain_guardrail = unmet_sustain_guardrail
        );
        if self.should_log_peer_decision_state_change(&run.peer_key, state) {
            log_policy_run!(
                warn,
                "peer not bannable yet decision",
                "not_bannable",
                run,
                torrent,
                torrent_tracker,
                peer,
                observed_at_rfc3339,
                observed_duration_seconds = observed_duration.as_secs(),
                required_observation_seconds = required_observation.as_secs(),
                observed_bad_duration_seconds = bad_duration.as_secs(),
                required_bad_duration_seconds = required_bad_duration.as_secs(),
                policy_threshold_met = policy_threshold_met,
                is_bad_sample = run.evaluation.is_bad_sample(),
                unmet_observation_guardrail = unmet_observation_guardrail,
                unmet_sustain_guardrail = unmet_sustain_guardrail
            );
        }
    }

    fn log_peer_policy_reban_cooldown(
        &mut self,
        run: &PeerPolicyRun,
        remaining: Duration,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at_rfc3339: &str,
    ) {
        log_policy_run!(
            info,
            "peer policy update",
            "reban_cooldown",
            run,
            torrent,
            torrent_tracker,
            peer,
            observed_at_rfc3339,
            reban_cooldown_remaining_seconds = remaining.as_secs()
        );
        if self.should_log_peer_decision_state_change(
            &run.peer_key,
            PeerDecisionLogState::RebanCooldown,
        ) {
            log_policy_run!(
                warn,
                "peer reban cooldown decision",
                "reban_cooldown",
                run,
                torrent,
                torrent_tracker,
                peer,
                observed_at_rfc3339,
                reban_cooldown_remaining_seconds = remaining.as_secs()
            );
        }
    }

    fn log_peer_policy_duplicate_suppressed(
        &mut self,
        run: &PeerPolicyRun,
        torrent: &TorrentSummary,
        torrent_tracker: &str,
        peer: &TorrentPeer,
        observed_at_rfc3339: &str,
    ) {
        log_policy_run!(
            info,
            "peer policy update",
            "duplicate_suppressed",
            run,
            torrent,
            torrent_tracker,
            peer,
            observed_at_rfc3339
        );
        if self.should_log_peer_decision_state_change(
            &run.peer_key,
            PeerDecisionLogState::DuplicateSuppressed,
        ) {
            log_policy_run!(
                warn,
                "peer duplicate ban suppression decision",
                "duplicate_suppressed",
                run,
                torrent,
                torrent_tracker,
                peer,
                observed_at_rfc3339
            );
        }
    }

    fn should_log_peer_decision_state_change(
        &mut self,
        key: &str,
        new_state: PeerDecisionLogState,
    ) -> bool {
        if self.peer_decision_log_states.get(key) == Some(&new_state) {
            return false;
        }
        self.peer_decision_log_states
            .insert(key.to_string(), new_state);
        true
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
        let mut requested_by_ip: HashMap<std::net::IpAddr, ActiveBanRecord> = HashMap::new();
        for action in actions {
            let requested = ActiveBanRecord {
                peer_ip: action.decision.peer_ip,
                peer_port: action.decision.peer_port,
                scope: format!("torrent:{}", action.torrent_hash),
                offence_number: action.decision.offence_number,
                reason: action.decision.reason_code.clone(),
                created_at: observed_at,
                expires_at: observed_at + action.decision.ttl,
                reconciled_at: None,
            };
            requested_by_ip
                .entry(requested.peer_ip)
                .and_modify(|existing| {
                    if requested.expires_at > existing.expires_at {
                        *existing = requested.clone();
                    }
                })
                .or_insert(requested);
        }
        let requested_bans = requested_by_ip.into_values().collect::<Vec<_>>();

        if let Err(error) = self
            .qbittorrent
            .apply_peer_bans(&requested_bans, &active_before)
            .await
        {
            for action in actions {
                self.metrics.record_ban_failure();
                log_ban_action!(
                    warn,
                    "peer ban application failed",
                    "ban_failed",
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
        let mut action_order = (0..actions.len()).collect::<Vec<_>>();
        action_order.sort_by_key(|index| actions[*index].decision.ttl);
        for index in action_order {
            let action = &actions[index];
            let stored = match self.record_ban_enforcement(action, observed_at).await {
                Ok(stored) => stored,
                Err(error) => {
                    self.metrics.record_ban_failure();
                    log_ban_action!(
                        warn,
                        "peer ban persistence failed",
                        "ban_persist_failed",
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
                    &action.policy_name,
                    action.decision.offence_number,
                )
                .await?;
            if let Some(active_ban) = stored.active_ban {
                active_bans.push(active_ban);
            }
            if !stored.duplicate_suppressed {
                ban_count += 1;
                self.metrics.record_ban_applied(
                    action.policy.metric_label(),
                    action.evaluation.bad_duration(),
                    action
                        .policy
                        .reason_metric_label(&action.decision.reason_code),
                );
                log_ban_action!(
                    info,
                    "peer policy update",
                    "ban",
                    action,
                    observed_at_rfc3339,
                );
                log_ban_action!(warn, "peer ban applied", "ban", action, observed_at_rfc3339,);
            }
        }

        Ok(ban_count)
    }

    async fn record_ban_enforcement(
        &self,
        action: &PendingBanAction,
        observed_at: std::time::SystemTime,
    ) -> Result<crate::persistence::EnforcementWriteResult> {
        action
            .policy
            .record_enforcement(
                &self.persistence,
                &PeerPolicyAssessment {
                    policy_name: action.policy.name(),
                    evaluation: action.evaluation.clone(),
                    disposition: BanDisposition::Ban(action.decision.clone()),
                    diagnostics: action.diagnostics.clone(),
                },
                &action.decision,
                observed_at,
            )
            .await
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
    ) -> Result<(usize, usize)> {
        let mut replayed = 0;
        let mut failed = 0;

        let mut shutdown = self.shutdown.clone();
        for intent in pending_ban_intents {
            if intent.ban_expires_at <= recovered_at {
                debug!(
                    torrent_hash = %intent.torrent_hash,
                    policy_name = %intent.policy_name,
                    peer_ip = %intent.peer_ip,
                    peer_port = intent.peer_port,
                    offence_number = intent.offence_number,
                    ban_expires_at = %format_timestamp(intent.ban_expires_at),
                    "skipping expired pending ban intent during startup recovery; periodic retention prune will clean it up"
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
                            policy_name = %intent.policy_name,
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
                                return Ok((replayed, failed));
                            }
                        }
                        attempt += 1;
                    }
                    Err(error) => {
                        failed += 1;
                        warn!(
                            torrent_hash = %intent.torrent_hash,
                            policy_name = %intent.policy_name,
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

        Ok((replayed, failed))
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
                    &intent.policy_name,
                    intent.offence_number,
                )
                .await?;
            return Ok(());
        }

        let Some(policy) = self.peer_policy_by_name(&intent.policy_name) else {
            let error = format!(
                "unsupported policy `{}` in pending ban intent",
                intent.policy_name
            );
            self.persistence
                .upsert_pending_ban_intent(&PendingBanIntentRecord {
                    last_error: error.clone(),
                    ..intent.clone()
                })
                .await?;
            self.metrics.record_ban_failure();
            bail!("{error}");
        };
        if let Err(error) = policy
            .validate_replay_intent(&self.persistence, intent)
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

        let decision = BanDecision {
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
            offence_number: intent.offence_number,
            ttl,
            reason_code: intent.reason_code.clone(),
            reason_details: "replayed pending intent".to_string(),
        };
        let stored = policy
            .record_replayed_intent(&self.persistence, intent, &decision, recovered_at)
            .await;
        let stored = match stored {
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
                &intent.policy_name,
                intent.offence_number,
            )
            .await?;
        if let Some(active_ban) = stored.active_ban {
            active_bans.push(active_ban);
        }
        if !stored.duplicate_suppressed {
            self.metrics.record_ban_applied(
                policy.metric_label(),
                intent.bad_duration,
                policy.reason_metric_label(&intent.reason_code),
            );
        }

        warn!(
            torrent_hash = %intent.torrent_hash,
            policy_name = %intent.policy_name,
            peer_ip = %intent.peer_ip,
            peer_port = intent.peer_port,
            offence_number = intent.offence_number,
            ban_expires_at = %format_timestamp(intent.ban_expires_at),
            "replayed pending ban intent during startup recovery"
        );
        Ok(())
    }

    fn peer_policy_by_name(&self, policy_name: &str) -> Option<Arc<dyn PeerPolicyAdapter>> {
        self.replay_policies
            .iter()
            .find(|policy| policy.name() == policy_name)
            .cloned()
    }

    async fn refresh_gauges(&self) -> Result<()> {
        self.metrics
            .set_active_tracked_peers(self.persistence.count_tracked_peer_sessions().await?);
        self.metrics
            .set_active_bans(self.persistence.count_active_bans().await?);
        self.metrics
            .set_sqlite_size_bytes(self.persistence.sqlite_size_bytes().await?);
        Ok(())
    }

    async fn maybe_run_retention_prune(&mut self, now: std::time::SystemTime) {
        if !self.config.retention.enabled {
            return;
        }

        if let Some(last_pruned_at) = self.last_retention_prune_at
            && now.duration_since(last_pruned_at).unwrap_or_default()
                < self.config.retention.prune_interval
        {
            return;
        }
        self.last_retention_prune_at = Some(now);
        let started = std::time::Instant::now();

        match self
            .persistence
            .run_retention_prune(&self.config.retention, now)
            .await
        {
            Ok(pruned) => {
                let duration = started.elapsed();
                self.metrics.record_prune_success(
                    duration,
                    pruned.peer_sessions_deleted,
                    pruned.peer_policy_sessions_deleted,
                    pruned.peer_offences_deleted,
                    pruned.active_bans_deleted,
                    pruned.pending_ban_intents_deleted,
                    pruned.incremental_vacuum_pages,
                );
                info!(
                    prune_duration_ms = duration.as_millis(),
                    peer_sessions_deleted = pruned.peer_sessions_deleted,
                    peer_policy_sessions_deleted = pruned.peer_policy_sessions_deleted,
                    peer_offences_deleted = pruned.peer_offences_deleted,
                    active_bans_deleted = pruned.active_bans_deleted,
                    pending_ban_intents_deleted = pruned.pending_ban_intents_deleted,
                    incremental_vacuum_pages = pruned.incremental_vacuum_pages,
                    "retention prune completed"
                );
            }
            Err(error) => {
                self.metrics.record_prune_failure(started.elapsed());
                warn!(?error, "retention prune failed");
            }
        }
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
                    && offence.reason_code == ban.reason
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

fn tracker_hostname(tracker: Option<&str>) -> String {
    let Some(tracker) = tracker.map(str::trim).filter(|tracker| !tracker.is_empty()) else {
        return String::new();
    };

    parse_hostname(tracker)
        .or_else(|| parse_hostname(&format!("https://{tracker}")))
        .unwrap_or_default()
}

fn peer_log_state_key(policy_name: &str, identity: &OffenceIdentity) -> String {
    format!(
        "{policy_name}|{}|{}",
        identity.torrent_hash, identity.peer_ip
    )
}

fn exemption_reason_code(reason: &ExemptionReason) -> &'static str {
    match reason {
        ExemptionReason::TorrentExcluded => "torrent_excluded",
        ExemptionReason::AllowlistedPeer => "allowlisted_peer",
        ExemptionReason::NearComplete { .. } => "near_complete",
        ExemptionReason::NewPeerGracePeriod { .. } => "new_peer_grace_period",
        ExemptionReason::AlreadyBanned => "already_banned",
    }
}

fn parse_hostname(input: &str) -> Option<String> {
    reqwest::Url::parse(input)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

fn has_active_ban(
    active_bans: &[ActiveBanRecord],
    peer_ip: std::net::IpAddr,
    _peer_port: u16,
    _torrent_hash: &str,
    observed_at: std::time::SystemTime,
) -> bool {
    active_bans.iter().any(|ban| {
        ban.peer_ip == peer_ip && ban.reconciled_at.is_none() && ban.expires_at > observed_at
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, UNIX_EPOCH},
    };

    use tokio::{
        sync::{Notify, watch},
        time::{self, timeout},
    };
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::any};

    use crate::{
        config::{
            AppConfig, BanLadderConfig, DatabaseConfig, FiltersConfig, HttpConfig, LoggingConfig,
            PolicyConfig, QbittorrentConfig, RetentionConfig,
        },
        metrics::AppMetrics,
        persistence::{ActiveBanRecord, PeerOffenceRecord, PendingBanIntentRecord, Persistence},
        policy::{PolicyDataStore, PolicyEngine},
        runtime::ServiceState,
        types::{
            BanDecision, OffenceHistory, OffenceIdentity, PeerContext, PeerObservationId,
            PeerPolicyInput, PeerPolicySessionState, PeerSessionState, PeerSnapshot,
            PolicyDiagnostic, PolicyDiagnosticValue, TorrentPeer, TorrentScope, TorrentSummary,
        },
    };

    use super::{ControlLoop, ObservedPeer, PeerPolicyRun, PolicyCycleCache, tracker_hostname};

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

    #[test]
    fn generic_policy_log_snapshots_include_stable_fields() {
        let mut config = PolicyConfig::default();
        config.score.enabled = false;
        config.receive_idle.enabled = true;
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let policy = engine.enabled_peer_policies().remove(0);
        let torrent = TorrentSummary {
            hash: "abc123".to_string(),
            name: "Example".to_string(),
            tracker: Some("https://tracker.example.org/announce".to_string()),
            total_seeders: 5,
            category: None,
            tags: vec![],
        };
        let peer_context = PeerContext {
            torrent: TorrentScope {
                hash: torrent.hash.clone(),
                name: torrent.name.clone(),
                tracker: torrent.tracker.clone(),
                category: torrent.category.clone(),
                tags: torrent.tags.clone(),
                total_seeders: torrent.total_seeders,
                in_scope: true,
            },
            peer: PeerSnapshot {
                ip: "10.0.0.10".parse().unwrap(),
                port: 51414,
                progress: 0.1005,
                up_rate_bps: 0,
                uploaded_bytes: Some(0),
            },
            first_seen_at: UNIX_EPOCH,
            observed_at: UNIX_EPOCH + Duration::from_secs(180),
            has_active_ban: false,
        };
        let torrent_peer = TorrentPeer {
            observation_id: engine.peer_observation_id(&peer_context),
            peer: peer_context.peer.clone(),
            client_name: None,
        };
        let history = OffenceHistory {
            offence_count: 0,
            last_ban_expires_at: None,
        };
        let mut assessment = policy
            .assess_peer(PeerPolicyInput {
                peer: &peer_context,
                previous_session: None,
                offence_history: &history,
            })
            .unwrap();
        assessment.diagnostics.push(PolicyDiagnostic {
            name: "threshold_met",
            value: PolicyDiagnosticValue::Bool(false),
        });
        let run = PeerPolicyRun {
            policy: policy.clone(),
            policy_name: assessment.policy_name,
            metric_label: policy.metric_label(),
            peer_key: "receive_idle|abc123|10.0.0.10".to_string(),
            evaluation: assessment.evaluation,
            disposition: assessment.disposition,
            diagnostics: assessment.diagnostics,
        };
        let run_snapshot = run.log_snapshot(
            "not_bannable",
            &torrent,
            "tracker.example.org",
            &torrent_peer,
        );

        assert_eq!(run_snapshot.state, "not_bannable");
        assert_eq!(
            run_snapshot.policy_name,
            crate::policy::RECEIVE_IDLE_POLICY_NAME
        );
        assert_eq!(run_snapshot.torrent_hash, "abc123");
        assert_eq!(run_snapshot.torrent_tracker, "tracker.example.org");
        assert_eq!(
            run_snapshot.peer_ip,
            "10.0.0.10".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(run_snapshot.peer_port, 51414);
        assert_eq!(run_snapshot.latest_peer_progress, 0.1005);
        assert!(run_snapshot.diagnostics_count > 0);

        let decision = BanDecision {
            peer_ip: torrent_peer.peer.ip,
            peer_port: torrent_peer.peer.port,
            offence_number: 1,
            ttl: Duration::from_secs(600),
            reason_code: "receive_idle".to_string(),
            reason_details: "receive idle regression".to_string(),
        };
        let action = super::PendingBanAction {
            policy,
            torrent_hash: torrent.hash.clone(),
            torrent_name: torrent.name.clone(),
            torrent_tracker: "tracker.example.org".to_string(),
            decision,
            evaluation: run.evaluation.clone(),
            policy_name: run.policy_name.to_string(),
            diagnostics: run.diagnostics.clone(),
            pending_intent: PendingBanIntentRecord {
                torrent_hash: "abc123".to_string(),
                peer_ip: "10.0.0.10".parse().unwrap(),
                peer_port: 51414,
                policy_name: "receive_idle".to_string(),
                offence_number: 1,
                reason_code: "receive_idle".to_string(),
                observed_at: UNIX_EPOCH + Duration::from_secs(180),
                ban_expires_at: UNIX_EPOCH + Duration::from_secs(780),
                bad_duration: Duration::from_secs(120),
                progress_delta_per_mille: 0,
                avg_up_rate_bps: 0,
                last_error: "pending qbittorrent enforcement".to_string(),
            },
        };
        let action_snapshot = action.log_snapshot("ban_pending");

        assert_eq!(action_snapshot.state, "ban_pending");
        assert_eq!(action_snapshot.policy_name, "receive_idle");
        assert_eq!(action_snapshot.reason_code, "receive_idle");
        assert_eq!(action_snapshot.selected_ban_ttl_seconds, 600);
        assert_eq!(action_snapshot.diagnostics_count, run.diagnostics.len());
    }

    #[tokio::test]
    async fn policy_cycle_cache_preloads_large_peer_set_state_and_histories() {
        let persistence = test_persistence().await;
        persistence.run_migrations().await.unwrap();
        let mut config = PolicyConfig::default();
        config.score.enabled = true;
        config.receive_idle.enabled = true;
        let policy = PolicyEngine::new(config, &FiltersConfig::default());
        let mut policies = policy.enabled_peer_policies();
        let receive_idle_policy = policies
            .iter()
            .find(|policy| policy.name() == crate::policy::RECEIVE_IDLE_POLICY_NAME)
            .unwrap()
            .clone();
        policies.push(receive_idle_policy);
        let torrent = TorrentSummary {
            hash: "abc123".to_string(),
            name: "Example".to_string(),
            tracker: Some("https://tracker.example.org/announce".to_string()),
            total_seeders: 5,
            category: None,
            tags: vec![],
        };
        let torrent_scope = TorrentScope {
            hash: torrent.hash.clone(),
            name: torrent.name.clone(),
            tracker: torrent.tracker.clone(),
            category: torrent.category.clone(),
            tags: torrent.tags.clone(),
            total_seeders: torrent.total_seeders,
            in_scope: true,
        };
        let mut observed_peers = Vec::new();

        for index in 1..=64_u8 {
            let peer_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, index));
            let peer_port = 51000 + u16::from(index);
            let observation_id = PeerObservationId {
                torrent_hash: torrent.hash.clone(),
                peer_ip,
                peer_port,
            };
            let offence_identity = OffenceIdentity {
                torrent_hash: torrent.hash.clone(),
                peer_ip,
            };
            persistence
                .upsert_peer_session(
                    &PeerSessionState {
                        observation_id: observation_id.clone(),
                        offence_identity: offence_identity.clone(),
                        first_seen_at: UNIX_EPOCH + Duration::from_secs(10),
                        last_seen_at: UNIX_EPOCH + Duration::from_secs(u64::from(index)),
                        baseline_progress: 0.1,
                        latest_progress: 0.1,
                        rolling_avg_up_rate_bps: 0,
                        observed_duration: Duration::from_secs(120),
                        bad_duration: Duration::from_secs(120),
                        ban_score: 1.0,
                        ban_score_above_threshold_duration: Duration::from_secs(120),
                        churn_reconnect_count: 0,
                        churn_window_started_at: None,
                        churn_amplifier: 0.0,
                        sample_count: 2,
                        last_torrent_seeder_count: 5,
                        last_exemption_reason: None,
                        bannable_since: None,
                        last_ban_decision_at: None,
                    },
                    "policy-v1",
                )
                .await
                .unwrap();
            persistence
                .upsert_peer_policy_session(
                    &PeerPolicySessionState {
                        policy_name: crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string(),
                        policy_version: "policy-v1".to_string(),
                        observation_id: observation_id.clone(),
                        offence_identity: offence_identity.clone(),
                        first_seen_at: UNIX_EPOCH + Duration::from_secs(10),
                        last_seen_at: UNIX_EPOCH + Duration::from_secs(u64::from(index)),
                        observed_duration: Duration::from_secs(120),
                        bad_duration: Duration::from_secs(120),
                        sample_count: 2,
                        last_uploaded_bytes: Some(0),
                        last_upload_rate_bps: 0,
                        state_json: serde_json::json!({}),
                        last_exemption_reason: None,
                        bannable_since: None,
                        last_ban_decision_at: None,
                    },
                    "policy-v1",
                )
                .await
                .unwrap();
            for (policy_name, reason_code) in [
                (crate::policy::SCORE_POLICY_NAME, "score_based"),
                (crate::policy::RECEIVE_IDLE_POLICY_NAME, "receive_idle"),
            ] {
                persistence
                    .insert_peer_offence(&PeerOffenceRecord {
                        id: None,
                        torrent_hash: torrent.hash.clone(),
                        peer_ip,
                        peer_port,
                        policy_name: policy_name.to_string(),
                        offence_number: 1,
                        reason_code: reason_code.to_string(),
                        observed_duration: Duration::from_secs(120),
                        bad_duration: Duration::from_secs(120),
                        progress_delta_per_mille: 0,
                        avg_up_rate_bps: 0,
                        banned_at: UNIX_EPOCH + Duration::from_secs(200),
                        ban_expires_at: UNIX_EPOCH + Duration::from_secs(800),
                        ban_revoked_at: None,
                    })
                    .await
                    .unwrap();
            }
            let peer = TorrentPeer {
                observation_id: observation_id.clone(),
                peer: PeerSnapshot {
                    ip: peer_ip,
                    port: peer_port,
                    progress: 0.1,
                    up_rate_bps: 0,
                    uploaded_bytes: Some(0),
                },
                client_name: None,
            };
            observed_peers.push(ObservedPeer {
                torrent: torrent.clone(),
                torrent_tracker: "tracker.example.org".to_string(),
                peer: peer.clone(),
                peer_context: PeerContext {
                    torrent: torrent_scope.clone(),
                    peer: peer.peer,
                    first_seen_at: UNIX_EPOCH + Duration::from_secs(130),
                    observed_at: UNIX_EPOCH + Duration::from_secs(130),
                    has_active_ban: false,
                },
            });
        }

        let cache =
            PolicyCycleCache::load(&persistence, &policies, std::slice::from_ref(&torrent.hash))
                .await
                .unwrap();
        assert_eq!(cache.batch_load_count(), 3);
        for observed_peer in &observed_peers {
            let identity = OffenceIdentity {
                torrent_hash: observed_peer.torrent.hash.clone(),
                peer_ip: observed_peer.peer.observation_id.peer_ip,
            };
            for policy in &policies {
                assert!(
                    cache
                        .get_previous_session(
                            policy.name(),
                            &observed_peer.peer,
                            UNIX_EPOCH + Duration::from_secs(130),
                            Duration::from_secs(300),
                        )
                        .await
                        .unwrap()
                        .is_some()
                );
            }
            assert_eq!(
                cache
                    .load_policy_offence_history(crate::policy::SCORE_POLICY_NAME, &identity)
                    .await
                    .unwrap()
                    .offence_count,
                1
            );
            assert_eq!(
                cache
                    .load_policy_offence_history(crate::policy::RECEIVE_IDLE_POLICY_NAME, &identity)
                    .await
                    .unwrap()
                    .offence_count,
                1
            );
        }
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
                policy_name: crate::policy::SCORE_POLICY_NAME.to_string(),
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
    async fn startup_recovery_replays_known_policy_intent_even_when_policy_disabled() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        let mut intent = pending_ban_intent(
            "abc123",
            "10.0.0.10",
            51413,
            1,
            now - Duration::from_secs(30),
            now + Duration::from_secs(3600),
            "failed to apply qbittorrent peer ban",
        );
        intent.policy_name = crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string();
        intent.reason_code = "receive_idle".to_string();
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

        let mut config = test_config(&base_url);
        config.policy.receive_idle.enabled = false;
        let config = Arc::new(config);
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
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
        let offences = persistence
            .load_peer_offences_by_ip("10.0.0.10".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(offences.len(), 1);
        assert_eq!(
            offences[0].policy_name,
            crate::policy::RECEIVE_IDLE_POLICY_NAME
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_recovery_retains_unsupported_policy_pending_intent() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        let mut intent = pending_ban_intent(
            "abc123",
            "10.0.0.10",
            51413,
            1,
            now - Duration::from_secs(30),
            now + Duration::from_secs(3600),
            "failed while service was down",
        );
        intent.policy_name = "future_policy".to_string();
        intent.reason_code = "future_reason".to_string();
        persistence
            .upsert_pending_ban_intent(&intent)
            .await
            .unwrap();

        let (base_url, observed_requests, _server) = spawn_recording_server().await;

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
        assert_eq!(pending[0].policy_name, "future_policy");
        assert!(pending[0].last_error.contains("unsupported policy"));
        assert!(persistence.load_active_bans().await.unwrap().is_empty());
        assert!(
            persistence
                .load_peer_offences_by_ip("10.0.0.10".parse().unwrap())
                .await
                .unwrap()
                .is_empty()
        );

        let observed_requests = observed_requests.lock().unwrap();
        assert!(
            observed_requests
                .iter()
                .all(|request| !request.contains("/api/v2/transfer/banPeers")),
            "unsupported policy intent should not be enforced: {observed_requests:?}"
        );
    }

    #[tokio::test]
    async fn startup_recovery_validates_policy_session_before_replay_enforcement() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let now = std::time::SystemTime::now();
        let peer_ip = "10.0.0.10".parse().unwrap();
        let mut intent = pending_ban_intent(
            "abc123",
            "10.0.0.10",
            51413,
            1,
            now - Duration::from_secs(30),
            now + Duration::from_secs(3600),
            "failed while service was down",
        );
        intent.policy_name = crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string();
        intent.reason_code = "receive_idle".to_string();
        persistence
            .upsert_pending_ban_intent(&intent)
            .await
            .unwrap();
        persistence
            .upsert_peer_policy_session(
                &PeerPolicySessionState {
                    policy_name: crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string(),
                    policy_version: "policy-v2".to_string(),
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                        peer_port: 51413,
                    },
                    offence_identity: OffenceIdentity {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                    },
                    first_seen_at: now - Duration::from_secs(180),
                    last_seen_at: now - Duration::from_secs(60),
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    sample_count: 2,
                    last_uploaded_bytes: Some(0),
                    last_upload_rate_bps: 0,
                    state_json: serde_json::json!({}),
                    last_exemption_reason: None,
                    bannable_since: Some(now - Duration::from_secs(30)),
                    last_ban_decision_at: None,
                },
                "policy-v2",
            )
            .await
            .unwrap();

        let (base_url, observed_requests, _server) = spawn_recording_server().await;

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
        assert!(
            pending[0]
                .last_error
                .contains("unsupported receive-idle policy session version")
        );
        assert!(persistence.load_active_bans().await.unwrap().is_empty());
        assert!(
            persistence
                .load_peer_offences_by_ip(peer_ip)
                .await
                .unwrap()
                .is_empty()
        );
        let observed_requests = observed_requests.lock().unwrap();
        assert!(
            observed_requests
                .iter()
                .all(|request| !request.contains("/api/v2/transfer/banPeers")),
            "invalid policy session should fail before qBittorrent enforcement: {observed_requests:?}"
        );
    }

    #[tokio::test]
    async fn startup_recovery_retains_expired_pending_ban_intents_for_periodic_prune() {
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
        assert_eq!(
            persistence.load_pending_ban_intents().await.unwrap().len(),
            1
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

        let (base_url, server, observed_count, observed_notify) = spawn_server_with_progress(vec![
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
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("service should become ready after startup retry succeeds");

        wait_for_observed_requests(
            observed_count.as_ref(),
            observed_notify.as_ref(),
            5,
            Duration::from_secs(3),
        )
        .await;
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
                    churn_amplifier: 0.0,
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
            receive_idle: crate::config::ReceiveIdlePolicyConfig {
                enabled: false,
                ..crate::config::ReceiveIdlePolicyConfig::default()
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
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
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
    async fn run_poll_cycle_persists_all_policy_offences_and_applies_one_ip_ban() {
        run_multi_policy_ban_resolution_case(Duration::from_secs(3600), Duration::from_secs(7200))
            .await;
    }

    #[tokio::test]
    async fn run_poll_cycle_selects_longest_ttl_when_first_policy_is_longer() {
        run_multi_policy_ban_resolution_case(Duration::from_secs(7200), Duration::from_secs(600))
            .await;
    }

    async fn run_multi_policy_ban_resolution_case(score_ttl: Duration, receive_idle_ttl: Duration) {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let seeded_now = std::time::SystemTime::now();
        let peer_ip = "10.0.0.10".parse().unwrap();
        persistence
            .upsert_peer_session(
                &PeerSessionState {
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                        peer_port: 51413,
                    },
                    offence_identity: OffenceIdentity {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
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
                    churn_amplifier: 0.0,
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
        persistence
            .upsert_peer_policy_session(
                &PeerPolicySessionState {
                    policy_name: crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string(),
                    policy_version: "policy-v1".to_string(),
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                        peer_port: 51414,
                    },
                    offence_identity: OffenceIdentity {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                    },
                    first_seen_at: seeded_now - Duration::from_secs(180),
                    last_seen_at: seeded_now - Duration::from_secs(60),
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    sample_count: 2,
                    last_uploaded_bytes: Some(0),
                    last_upload_rate_bps: 0,
                    state_json: serde_json::json!({}),
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
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51414\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51414,\"progress\":0.1005,\"dl_speed\":1024,\"up_speed\":128,\"uploaded\":0}},\"peers_removed\":[]}",
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
            receive_idle: crate::config::ReceiveIdlePolicyConfig {
                enabled: true,
                min_observation_duration: Duration::from_secs(1),
                sustain_duration: Duration::from_secs(120),
                max_upload_rate_bps: 128,
                max_uploaded_delta_bytes: 0,
                reban_cooldown: Duration::from_secs(1),
                ban_ladder: BanLadderConfig {
                    durations: vec![receive_idle_ttl],
                },
            },
            ban_ladder: BanLadderConfig {
                durations: vec![score_ttl],
            },
        };
        let config = Arc::new(config);
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
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
                ban_count: 2,
            }
        );
        let active_bans = persistence.load_active_bans().await.unwrap();
        assert_eq!(active_bans.len(), 1);
        let offences = persistence.load_peer_offences_by_ip(peer_ip).await.unwrap();
        let receive_session = persistence
            .get_peer_policy_session(
                crate::policy::RECEIVE_IDLE_POLICY_NAME,
                &PeerObservationId {
                    torrent_hash: "abc123".to_string(),
                    peer_ip,
                    peer_port: 51414,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            offences.len(),
            2,
            "active_bans={active_bans:?} offences={offences:?} receive_session={receive_session:?}"
        );
        let expected_reason = if receive_idle_ttl >= score_ttl {
            "receive_idle"
        } else {
            "score_based"
        };
        assert_eq!(
            active_bans[0].reason, expected_reason,
            "active_bans={active_bans:?} offences={offences:?}"
        );
        assert_eq!(
            active_bans[0]
                .expires_at
                .duration_since(active_bans[0].created_at)
                .unwrap()
                .as_secs(),
            score_ttl.max(receive_idle_ttl).as_secs()
        );
        assert!(
            offences
                .iter()
                .any(|offence| offence.policy_name == crate::policy::SCORE_POLICY_NAME)
        );
        assert!(
            offences
                .iter()
                .any(|offence| offence.policy_name == crate::policy::RECEIVE_IDLE_POLICY_NAME)
        );
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
    async fn run_poll_cycle_completed_idle_torrent_reaches_receive_idle_when_score_disabled() {
        let persistence = Arc::new(test_persistence().await);
        persistence.run_migrations().await.unwrap();
        let metrics = Arc::new(AppMetrics::new());
        let metrics_handle = metrics.clone();
        let seeded_now = std::time::SystemTime::now();
        let peer_ip = "10.0.0.10".parse().unwrap();
        persistence
            .upsert_peer_policy_session(
                &PeerPolicySessionState {
                    policy_name: crate::policy::RECEIVE_IDLE_POLICY_NAME.to_string(),
                    policy_version: "policy-v1".to_string(),
                    observation_id: PeerObservationId {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                        peer_port: 51414,
                    },
                    offence_identity: OffenceIdentity {
                        torrent_hash: "abc123".to_string(),
                        peer_ip,
                    },
                    first_seen_at: seeded_now - Duration::from_secs(180),
                    last_seen_at: seeded_now - Duration::from_secs(60),
                    observed_duration: Duration::from_secs(120),
                    bad_duration: Duration::from_secs(120),
                    sample_count: 2,
                    last_uploaded_bytes: Some(0),
                    last_upload_rate_bps: 0,
                    state_json: serde_json::json!({}),
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
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"hash\":\"abc123\",\"name\":\"Example\",\"category\":\"tv\",\"tags\":\"public\",\"num_complete\":5}]",
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v2/sync/torrentPeers?hash=abc123&rid=0",
                must_contain: vec![],
                response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"rid\":15,\"peers\":{\"10.0.0.10:51414\":{\"client\":\"qBittorrent/5.0.0\",\"ip\":\"10.0.0.10\",\"port\":51414,\"progress\":0.1005,\"dl_speed\":1024,\"up_speed\":0,\"uploaded\":0}},\"peers_removed\":[]}",
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v2/transfer/banPeers",
                must_contain: vec!["peers=10.0.0.10%3A51414"],
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
        state.mark_recovery_complete();

        let mut config = test_config(&base_url);
        config.policy.new_peer_grace_period = Duration::from_secs(1);
        config.policy.score.enabled = false;
        config.policy.receive_idle = crate::config::ReceiveIdlePolicyConfig {
            enabled: true,
            min_observation_duration: Duration::from_secs(1),
            sustain_duration: Duration::from_secs(120),
            max_upload_rate_bps: 0,
            max_uploaded_delta_bytes: 0,
            reban_cooldown: Duration::from_secs(1),
            ban_ladder: BanLadderConfig {
                durations: vec![Duration::from_secs(600)],
            },
        };
        let config = Arc::new(config);
        let qbittorrent = Arc::new(
            crate::qbittorrent::QbittorrentClient::new(
                config.qbittorrent.clone(),
                "secret".to_string(),
                config.filters.clone(),
                config.policy.min_total_seeders,
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
            config,
            persistence.clone(),
            qbittorrent,
            policy,
            state,
            metrics,
            shutdown_rx,
        );

        let result = control.run_poll_cycle().await.unwrap();
        let observation_id = PeerObservationId {
            torrent_hash: "abc123".to_string(),
            peer_ip: "10.0.0.10".parse().unwrap(),
            peer_port: 51414,
        };
        let receive_after = persistence
            .get_peer_policy_session(crate::policy::RECEIVE_IDLE_POLICY_NAME, &observation_id)
            .await
            .unwrap();
        assert_eq!(
            result,
            super::PollCycleResult {
                torrent_count: 1,
                peer_count: 1,
                ban_count: 1,
            },
            "receive_after={receive_after:?}"
        );
        assert!(
            persistence
                .get_peer_session(&observation_id)
                .await
                .unwrap()
                .is_none()
        );
        let offences = persistence.load_peer_offences_by_ip(peer_ip).await.unwrap();
        assert_eq!(offences.len(), 1);
        assert_eq!(
            offences[0].policy_name,
            crate::policy::RECEIVE_IDLE_POLICY_NAME
        );
        let rendered_metrics = metrics_handle.render().unwrap();
        assert!(rendered_metrics.contains("brrpolice_active_tracked_peers 1"));
        assert!(rendered_metrics.contains(
            "brrpolice_peer_samples_total{policy_name=\"receive_idle\",sample=\"all\"} 1"
        ));
        assert!(rendered_metrics.contains(
            "brrpolice_peer_samples_total{policy_name=\"receive_idle\",sample=\"bad\"} 1"
        ));
        assert!(rendered_metrics.contains(
            "brrpolice_policy_evaluations_total{policy_name=\"receive_idle\",result=\"bannable\"} 1"
        ));
        assert!(rendered_metrics.contains(
            "brrpolice_policy_decisions_total{policy_name=\"receive_idle\",decision=\"ban\"} 1"
        ));
        assert!(rendered_metrics.contains(
            "brrpolice_ban_applied_reasons_total{policy_name=\"receive_idle\",reason_code=\"receive_idle\"} 1"
        ));

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
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
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

        let (base_url, server, observed_count, observed_notify) =
            spawn_server_with_progress(vec![ExpectedRequest {
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
        wait_for_observed_requests(
            observed_count.as_ref(),
            observed_notify.as_ref(),
            1,
            Duration::from_secs(2),
        )
        .await;
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
                    churn_amplifier: 0.0,
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
            receive_idle: crate::config::ReceiveIdlePolicyConfig {
                enabled: false,
                ..crate::config::ReceiveIdlePolicyConfig::default()
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
                metrics.clone(),
            )
            .unwrap(),
        );
        let policy = Arc::new(PolicyEngine::new(config.policy.clone(), &config.filters));
        let (_, shutdown_rx) = watch::channel(false);
        let mut control = ControlLoop::new(
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
                api_key: String::new(),
                poll_interval: Duration::from_secs(15),
                request_timeout: Duration::from_secs(10),
                pool_idle_timeout: Duration::from_secs(5),
                transient_retries: 10,
            },
            policy: PolicyConfig {
                new_peer_grace_period: Duration::from_secs(300),
                decay_window: Duration::from_secs(3600),
                ignore_peer_progress_at_or_above: 0.95,
                min_total_seeders: 3,
                reban_cooldown: Duration::from_secs(1800),
                score: crate::config::ScorePolicyConfig::default(),
                receive_idle: crate::config::ReceiveIdlePolicyConfig::default(),
                ban_ladder: BanLadderConfig {
                    durations: vec![Duration::from_secs(3600)],
                },
            },
            filters: FiltersConfig::default(),
            database: DatabaseConfig {
                path: PathBuf::from(":memory:"),
                busy_timeout: Duration::from_secs(1),
            },
            retention: RetentionConfig::default(),
            http: HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
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
            policy_name: crate::policy::SCORE_POLICY_NAME.to_string(),
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
        observed_count: Arc<AtomicUsize>,
        observed_notify: Arc<Notify>,
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
            self.observed_count.fetch_add(1, Ordering::Relaxed);
            self.observed_notify.notify_waiters();

            response_template(expected.response)
        }
    }

    async fn spawn_server(
        expected_requests: Vec<ExpectedRequest>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let (base_url, handle, _, _) = spawn_server_with_progress(expected_requests).await;
        (base_url, handle)
    }

    async fn spawn_server_with_progress(
        expected_requests: Vec<ExpectedRequest>,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
        Arc<Notify>,
    ) {
        let server = MockServer::start().await;
        let expected_requests = Arc::new(Mutex::new(VecDeque::from(expected_requests)));
        let observed_count = Arc::new(AtomicUsize::new(0));
        let observed_notify = Arc::new(Notify::new());
        Mock::given(any())
            .respond_with(SequenceResponder {
                expected_requests: expected_requests.clone(),
                observed_count: observed_count.clone(),
                observed_notify: observed_notify.clone(),
            })
            .mount(&server)
            .await;
        let base_url = format!("{}/", server.uri());
        let notify_for_handle = observed_notify.clone();
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            loop {
                let remaining = expected_requests.lock().unwrap().len();
                if remaining == 0 {
                    break;
                }
                assert!(
                    start.elapsed() < timeout,
                    "{remaining} expected request(s) were not observed"
                );
                let _ =
                    tokio::time::timeout(Duration::from_millis(50), notify_for_handle.notified())
                        .await;
            }
            drop(server);
        });

        (base_url, handle, observed_count, observed_notify)
    }

    #[derive(Clone)]
    struct RecordingResponder {
        observed_requests: Arc<Mutex<Vec<String>>>,
    }

    impl Respond for RecordingResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            self.observed_requests.lock().unwrap().push(format!(
                "{} {}",
                request.method,
                request_path_and_query(request)
            ));

            if request.method.as_str() == "GET"
                && request_path_and_query(request) == "/api/v2/app/preferences"
            {
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string("{\"banned_IPs\":\"\"}")
            } else {
                ResponseTemplate::new(200)
            }
        }
    }

    async fn spawn_recording_server() -> (String, Arc<Mutex<Vec<String>>>, MockServer) {
        let server = MockServer::start().await;
        let observed_requests = Arc::new(Mutex::new(Vec::new()));
        Mock::given(any())
            .respond_with(RecordingResponder {
                observed_requests: observed_requests.clone(),
            })
            .mount(&server)
            .await;
        let base_url = format!("{}/", server.uri());

        (base_url, observed_requests, server)
    }

    async fn wait_for_observed_requests(
        observed_count: &AtomicUsize,
        observed_notify: &Notify,
        expected: usize,
        timeout_duration: Duration,
    ) {
        timeout(timeout_duration, async {
            loop {
                if observed_count.load(Ordering::Relaxed) >= expected {
                    break;
                }
                observed_notify.notified().await;
            }
        })
        .await
        .expect("timed out waiting for expected requests");
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
