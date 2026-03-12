use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use prometheus_client::{
    encoding::text::encode,
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};

#[derive(Clone)]
pub struct AppMetrics {
    registry: Arc<Registry>,
    peers_evaluated_total: Counter,
    bad_peers_total: Counter,
    score_policy_evaluations_total: Counter,
    score_policy_bannable_total: Counter,
    policy_ban_decisions_total: Counter,
    policy_not_bannable_decisions_total: Counter,
    policy_exemption_decisions_total: Counter,
    policy_reban_cooldown_decisions_total: Counter,
    policy_duplicate_suppressed_decisions_total: Counter,
    score_policy_bans_applied_total: Counter,
    bans_applied_total: Counter,
    bans_expired_total: Counter,
    ban_failures_total: Counter,
    qbittorrent_api_errors_total: Counter,
    metrics_encode_errors_total: Counter,
    active_tracked_peers: Gauge,
    active_bans: Gauge,
    in_scope_torrents: Gauge,
    last_successful_poll_timestamp: Gauge,
    sqlite_size_bytes: Gauge,
    qbittorrent_request_duration_seconds: Histogram,
    poll_loop_duration_seconds: Histogram,
    bad_time_before_ban_seconds: Histogram,
    score_value: Histogram,
    score_sample_risk: Histogram,
    score_above_threshold_seconds: Histogram,
}

impl AppMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let peers_evaluated_total = Counter::default();
        registry.register(
            "brrpolice_peers_evaluated",
            "Total peers evaluated by the policy engine.",
            peers_evaluated_total.clone(),
        );

        let bad_peers_total = Counter::default();
        registry.register(
            "brrpolice_bad_peers",
            "Total peer evaluations classified as bad samples.",
            bad_peers_total.clone(),
        );

        let score_policy_evaluations_total = Counter::default();
        registry.register(
            "brrpolice_score_policy_evaluations",
            "Total peer evaluations processed while score policy mode is active.",
            score_policy_evaluations_total.clone(),
        );

        let score_policy_bannable_total = Counter::default();
        registry.register(
            "brrpolice_score_policy_bannable",
            "Total score policy evaluations marked bannable.",
            score_policy_bannable_total.clone(),
        );

        let policy_ban_decisions_total = Counter::default();
        registry.register(
            "brrpolice_policy_ban_decisions",
            "Total policy decisions resulting in a ban action.",
            policy_ban_decisions_total.clone(),
        );

        let policy_not_bannable_decisions_total = Counter::default();
        registry.register(
            "brrpolice_policy_not_bannable_decisions",
            "Total policy decisions that remained not bannable.",
            policy_not_bannable_decisions_total.clone(),
        );

        let policy_exemption_decisions_total = Counter::default();
        registry.register(
            "brrpolice_policy_exemption_decisions",
            "Total policy decisions that resulted in an exemption.",
            policy_exemption_decisions_total.clone(),
        );

        let policy_reban_cooldown_decisions_total = Counter::default();
        registry.register(
            "brrpolice_policy_reban_cooldown_decisions",
            "Total policy decisions blocked by reban cooldown.",
            policy_reban_cooldown_decisions_total.clone(),
        );

        let policy_duplicate_suppressed_decisions_total = Counter::default();
        registry.register(
            "brrpolice_policy_duplicate_suppressed_decisions",
            "Total policy decisions suppressed as duplicates for the same bannable episode.",
            policy_duplicate_suppressed_decisions_total.clone(),
        );

        let score_policy_bans_applied_total = Counter::default();
        registry.register(
            "brrpolice_score_policy_bans_applied",
            "Total bans applied with score-based reason code.",
            score_policy_bans_applied_total.clone(),
        );

        let bans_applied_total = Counter::default();
        registry.register(
            "brrpolice_bans_applied",
            "Total bans successfully applied.",
            bans_applied_total.clone(),
        );

        let bans_expired_total = Counter::default();
        registry.register(
            "brrpolice_bans_expired",
            "Total bans reconciled after expiry.",
            bans_expired_total.clone(),
        );

        let ban_failures_total = Counter::default();
        registry.register(
            "brrpolice_ban_failures",
            "Total enforcement failures while applying bans.",
            ban_failures_total.clone(),
        );

        let qbittorrent_api_errors_total = Counter::default();
        registry.register(
            "brrpolice_qbittorrent_api_errors",
            "Total qBittorrent API request failures.",
            qbittorrent_api_errors_total.clone(),
        );

        let metrics_encode_errors_total = Counter::default();
        registry.register(
            "brrpolice_metrics_encode_errors",
            "Total failures while encoding Prometheus metrics output.",
            metrics_encode_errors_total.clone(),
        );

        let active_tracked_peers = Gauge::default();
        registry.register(
            "brrpolice_active_tracked_peers",
            "Current number of tracked peer sessions.",
            active_tracked_peers.clone(),
        );

        let active_bans = Gauge::default();
        registry.register(
            "brrpolice_active_bans",
            "Current number of active bans.",
            active_bans.clone(),
        );

        let in_scope_torrents = Gauge::default();
        registry.register(
            "brrpolice_in_scope_torrents",
            "Current number of in-scope torrents from the latest poll.",
            in_scope_torrents.clone(),
        );

        let last_successful_poll_timestamp = Gauge::default();
        registry.register(
            "brrpolice_last_successful_poll_timestamp",
            "Unix timestamp of the most recent successful poll cycle.",
            last_successful_poll_timestamp.clone(),
        );

        let sqlite_size_bytes = Gauge::default();
        registry.register(
            "brrpolice_sqlite_size_bytes",
            "Size of the SQLite database file in bytes.",
            sqlite_size_bytes.clone(),
        );

        let qbittorrent_request_duration_seconds =
            Histogram::new(exponential_buckets(0.005, 2.0, 12));
        registry.register(
            "brrpolice_qbittorrent_request_duration_seconds",
            "Latency of qBittorrent API requests.",
            qbittorrent_request_duration_seconds.clone(),
        );

        let poll_loop_duration_seconds = Histogram::new(exponential_buckets(0.01, 2.0, 12));
        registry.register(
            "brrpolice_poll_loop_duration_seconds",
            "Duration of a poll loop attempt.",
            poll_loop_duration_seconds.clone(),
        );

        let bad_time_before_ban_seconds = Histogram::new(exponential_buckets(1.0, 2.0, 12));
        registry.register(
            "brrpolice_bad_time_before_ban_seconds",
            "Accumulated bad time observed before a ban was applied.",
            bad_time_before_ban_seconds.clone(),
        );

        let score_value = Histogram::new(exponential_buckets(0.01, 1.8, 12));
        registry.register(
            "brrpolice_score_value",
            "Observed peer score values during score-policy evaluations.",
            score_value.clone(),
        );

        let score_sample_risk = Histogram::new(exponential_buckets(0.001, 2.0, 12));
        registry.register(
            "brrpolice_score_sample_risk",
            "Per-sample risk contributions used by score policy evaluations.",
            score_sample_risk.clone(),
        );

        let score_above_threshold_seconds = Histogram::new(exponential_buckets(1.0, 2.0, 12));
        registry.register(
            "brrpolice_score_above_threshold_seconds",
            "Accumulated seconds a peer score remained above ban threshold.",
            score_above_threshold_seconds.clone(),
        );

        Self {
            registry: Arc::new(registry),
            peers_evaluated_total,
            bad_peers_total,
            score_policy_evaluations_total,
            score_policy_bannable_total,
            policy_ban_decisions_total,
            policy_not_bannable_decisions_total,
            policy_exemption_decisions_total,
            policy_reban_cooldown_decisions_total,
            policy_duplicate_suppressed_decisions_total,
            score_policy_bans_applied_total,
            bans_applied_total,
            bans_expired_total,
            ban_failures_total,
            qbittorrent_api_errors_total,
            metrics_encode_errors_total,
            active_tracked_peers,
            active_bans,
            in_scope_torrents,
            last_successful_poll_timestamp,
            sqlite_size_bytes,
            qbittorrent_request_duration_seconds,
            poll_loop_duration_seconds,
            bad_time_before_ban_seconds,
            score_value,
            score_sample_risk,
            score_above_threshold_seconds,
        }
    }

    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut encoded = String::new();
        encode(&mut encoded, self.registry.as_ref())?;
        Ok(encoded)
    }

    pub fn record_peer_evaluated(&self, is_bad_sample: bool) {
        self.peers_evaluated_total.inc();
        if is_bad_sample {
            self.bad_peers_total.inc();
        }
    }

    pub fn record_ban_applied(&self, bad_duration: Duration, reason_code: &str) {
        self.bans_applied_total.inc();
        self.bad_time_before_ban_seconds
            .observe(bad_duration.as_secs_f64());
        if reason_code == "score_based" {
            self.score_policy_bans_applied_total.inc();
        }
    }

    pub fn record_score_evaluation(
        &self,
        score: f64,
        sample_risk: f64,
        above_threshold_duration: Duration,
        is_bannable: bool,
    ) {
        self.score_policy_evaluations_total.inc();
        if is_bannable {
            self.score_policy_bannable_total.inc();
        }
        self.score_value.observe(score);
        self.score_sample_risk.observe(sample_risk);
        self.score_above_threshold_seconds
            .observe(above_threshold_duration.as_secs_f64());
    }

    pub fn record_policy_ban_decision(&self) {
        self.policy_ban_decisions_total.inc();
    }

    pub fn record_policy_not_bannable_decision(&self) {
        self.policy_not_bannable_decisions_total.inc();
    }

    pub fn record_policy_exemption_decision(&self) {
        self.policy_exemption_decisions_total.inc();
    }

    pub fn record_policy_reban_cooldown_decision(&self) {
        self.policy_reban_cooldown_decisions_total.inc();
    }

    pub fn record_policy_duplicate_suppressed_decision(&self) {
        self.policy_duplicate_suppressed_decisions_total.inc();
    }

    pub fn record_bans_expired(&self, count: usize) {
        for _ in 0..count {
            self.bans_expired_total.inc();
        }
    }

    pub fn record_ban_failure(&self) {
        self.ban_failures_total.inc();
    }

    pub fn record_qbittorrent_request(&self, duration: Duration) {
        self.qbittorrent_request_duration_seconds
            .observe(duration.as_secs_f64());
    }

    pub fn record_qbittorrent_api_error(&self) {
        self.qbittorrent_api_errors_total.inc();
    }

    pub fn record_metrics_encode_error(&self) {
        self.metrics_encode_errors_total.inc();
    }

    pub fn record_poll_loop_duration(&self, duration: Duration) {
        self.poll_loop_duration_seconds
            .observe(duration.as_secs_f64());
    }

    pub fn mark_successful_poll(&self, completed_at: SystemTime) {
        let unix_seconds = completed_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_successful_poll_timestamp.set(unix_seconds as i64);
    }

    pub fn set_active_tracked_peers(&self, count: usize) {
        self.active_tracked_peers.set(count as i64);
    }

    pub fn set_active_bans(&self, count: usize) {
        self.active_bans.set(count as i64);
    }

    pub fn set_in_scope_torrents(&self, count: usize) {
        self.in_scope_torrents.set(count as i64);
    }

    pub fn set_sqlite_size_bytes(&self, size: Option<u64>) {
        self.sqlite_size_bytes.set(size.unwrap_or_default() as i64);
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}
