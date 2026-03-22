use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PeerSampleLabels {
    sample: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PolicyDecisionLabels {
    decision: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BanResultLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BanAppliedReasonLabels {
    reason_code: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PruneRunLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PrunedRowsLabels {
    table: &'static str,
}

#[derive(Clone)]
pub struct AppMetrics {
    registry: Arc<Registry>,
    peer_samples_total: Family<PeerSampleLabels, Counter>,
    score_policy_evaluations_total: Counter,
    score_policy_bannable_total: Counter,
    policy_decisions_total: Family<PolicyDecisionLabels, Counter>,
    ban_results_total: Family<BanResultLabels, Counter>,
    ban_applied_reasons_total: Family<BanAppliedReasonLabels, Counter>,
    prune_runs_total: Family<PruneRunLabels, Counter>,
    pruned_rows_total: Family<PrunedRowsLabels, Counter>,
    sqlite_pages_freed_total: Counter,
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
    prune_duration_seconds: Histogram,
}

impl AppMetrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let peer_samples_total = Family::<PeerSampleLabels, Counter>::default();
        registry.register(
            "brrpolice_peer_samples",
            "Total peer evaluations by sample classification.",
            peer_samples_total.clone(),
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

        let policy_decisions_total = Family::<PolicyDecisionLabels, Counter>::default();
        registry.register(
            "brrpolice_policy_decisions",
            "Total policy decisions by outcome type.",
            policy_decisions_total.clone(),
        );

        let ban_results_total = Family::<BanResultLabels, Counter>::default();
        registry.register(
            "brrpolice_bans",
            "Total ban lifecycle outcomes by result.",
            ban_results_total.clone(),
        );

        let ban_applied_reasons_total = Family::<BanAppliedReasonLabels, Counter>::default();
        registry.register(
            "brrpolice_ban_applied_reasons",
            "Total successfully applied bans by bounded reason code.",
            ban_applied_reasons_total.clone(),
        );

        let prune_runs_total = Family::<PruneRunLabels, Counter>::default();
        registry.register(
            "brrpolice_prune_runs",
            "Total retention prune runs by result.",
            prune_runs_total.clone(),
        );

        let pruned_rows_total = Family::<PrunedRowsLabels, Counter>::default();
        registry.register(
            "brrpolice_pruned_rows",
            "Total rows deleted by retention pruning by table.",
            pruned_rows_total.clone(),
        );

        let sqlite_pages_freed_total = Counter::default();
        registry.register(
            "brrpolice_sqlite_pages_freed",
            "Total SQLite pages requested to be reclaimed during retention pruning.",
            sqlite_pages_freed_total.clone(),
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

        let prune_duration_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 12));
        registry.register(
            "brrpolice_prune_duration_seconds",
            "Duration of retention prune runs.",
            prune_duration_seconds.clone(),
        );

        Self {
            registry: Arc::new(registry),
            peer_samples_total,
            score_policy_evaluations_total,
            score_policy_bannable_total,
            policy_decisions_total,
            ban_results_total,
            ban_applied_reasons_total,
            prune_runs_total,
            pruned_rows_total,
            sqlite_pages_freed_total,
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
            prune_duration_seconds,
        }
    }

    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut encoded = String::new();
        encode(&mut encoded, self.registry.as_ref())?;
        Ok(encoded)
    }

    pub fn record_peer_evaluated(&self, is_bad_sample: bool) {
        self.peer_samples_total
            .get_or_create(&PeerSampleLabels { sample: "all" })
            .inc();
        if is_bad_sample {
            self.peer_samples_total
                .get_or_create(&PeerSampleLabels { sample: "bad" })
                .inc();
        }
    }

    pub fn record_ban_applied(&self, bad_duration: Duration, reason_code: &str) {
        self.ban_results_total
            .get_or_create(&BanResultLabels { result: "applied" })
            .inc();
        self.bad_time_before_ban_seconds
            .observe(bad_duration.as_secs_f64());
        let reason_code = match reason_code {
            "score_based" => "score_based",
            _ => "other",
        };
        self.ban_applied_reasons_total
            .get_or_create(&BanAppliedReasonLabels { reason_code })
            .inc();
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
        self.policy_decisions_total
            .get_or_create(&PolicyDecisionLabels { decision: "ban" })
            .inc();
    }

    pub fn record_policy_not_bannable_decision(&self) {
        self.policy_decisions_total
            .get_or_create(&PolicyDecisionLabels {
                decision: "not_bannable",
            })
            .inc();
    }

    pub fn record_policy_exemption_decision(&self) {
        self.policy_decisions_total
            .get_or_create(&PolicyDecisionLabels {
                decision: "exemption",
            })
            .inc();
    }

    pub fn record_policy_reban_cooldown_decision(&self) {
        self.policy_decisions_total
            .get_or_create(&PolicyDecisionLabels {
                decision: "reban_cooldown",
            })
            .inc();
    }

    pub fn record_policy_duplicate_suppressed_decision(&self) {
        self.policy_decisions_total
            .get_or_create(&PolicyDecisionLabels {
                decision: "duplicate_suppressed",
            })
            .inc();
    }

    pub fn record_bans_expired(&self, count: usize) {
        self.ban_results_total
            .get_or_create(&BanResultLabels { result: "expired" })
            .inc_by(count as u64);
    }

    pub fn record_ban_failure(&self) {
        self.ban_results_total
            .get_or_create(&BanResultLabels { result: "failed" })
            .inc();
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

    pub fn record_prune_success(
        &self,
        duration: Duration,
        peer_sessions_deleted: u64,
        peer_offences_deleted: u64,
        active_bans_deleted: u64,
        pending_ban_intents_deleted: u64,
        incremental_vacuum_pages: Option<u32>,
    ) {
        self.prune_runs_total
            .get_or_create(&PruneRunLabels { result: "success" })
            .inc();
        self.prune_duration_seconds.observe(duration.as_secs_f64());
        self.pruned_rows_total
            .get_or_create(&PrunedRowsLabels {
                table: "peer_sessions",
            })
            .inc_by(peer_sessions_deleted);
        self.pruned_rows_total
            .get_or_create(&PrunedRowsLabels {
                table: "peer_offences",
            })
            .inc_by(peer_offences_deleted);
        self.pruned_rows_total
            .get_or_create(&PrunedRowsLabels {
                table: "active_bans",
            })
            .inc_by(active_bans_deleted);
        self.pruned_rows_total
            .get_or_create(&PrunedRowsLabels {
                table: "pending_ban_intents",
            })
            .inc_by(pending_ban_intents_deleted);
        if let Some(pages) = incremental_vacuum_pages {
            self.sqlite_pages_freed_total.inc_by(u64::from(pages));
        }
    }

    pub fn record_prune_failure(&self, duration: Duration) {
        self.prune_runs_total
            .get_or_create(&PruneRunLabels { result: "failure" })
            .inc();
        self.prune_duration_seconds.observe(duration.as_secs_f64());
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

#[cfg(test)]
mod tests {
    use super::AppMetrics;
    use std::time::Duration;

    #[test]
    fn prune_metrics_render_with_label_families() {
        let metrics = AppMetrics::new();
        metrics.record_prune_success(Duration::from_millis(25), 3, 2, 1, 4, Some(7));
        metrics.record_prune_failure(Duration::from_millis(10));

        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("brrpolice_prune_runs_total{result=\"success\"} 1"));
        assert!(rendered.contains("brrpolice_prune_runs_total{result=\"failure\"} 1"));
        assert!(rendered.contains("brrpolice_pruned_rows_total{table=\"peer_sessions\"} 3"));
        assert!(rendered.contains("brrpolice_pruned_rows_total{table=\"peer_offences\"} 2"));
        assert!(rendered.contains("brrpolice_pruned_rows_total{table=\"active_bans\"} 1"));
        assert!(rendered.contains("brrpolice_pruned_rows_total{table=\"pending_ban_intents\"} 4"));
        assert!(rendered.contains("brrpolice_sqlite_pages_freed_total 7"));
    }

    #[test]
    fn collapsed_counters_render_expected_labels() {
        let metrics = AppMetrics::new();
        metrics.record_peer_evaluated(true);
        metrics.record_policy_ban_decision();
        metrics.record_policy_exemption_decision();
        metrics.record_ban_applied(Duration::from_secs(3), "score_based");
        metrics.record_ban_failure();
        metrics.record_bans_expired(2);

        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("brrpolice_peer_samples_total{sample=\"all\"} 1"));
        assert!(rendered.contains("brrpolice_peer_samples_total{sample=\"bad\"} 1"));
        assert!(rendered.contains("brrpolice_policy_decisions_total{decision=\"ban\"} 1"));
        assert!(rendered.contains("brrpolice_policy_decisions_total{decision=\"exemption\"} 1"));
        assert!(rendered.contains("brrpolice_bans_total{result=\"applied\"} 1"));
        assert!(rendered.contains("brrpolice_bans_total{result=\"failed\"} 1"));
        assert!(rendered.contains("brrpolice_bans_total{result=\"expired\"} 2"));
        assert!(
            rendered.contains("brrpolice_ban_applied_reasons_total{reason_code=\"score_based\"} 1")
        );
    }
}
