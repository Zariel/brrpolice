use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use humantime::parse_rfc3339;
use serde_json::Value;

use brrpolice::{
    config::{BanLadderConfig, ChurnPolicyConfig, FiltersConfig, PolicyConfig, ScorePolicyConfig},
    policy::PolicyEngine,
    policy_trace::{
        POLICY_TRACE_SCHEMA_VERSION, PolicyTraceRecord, TraceBanDisposition, TraceDecisionOutput,
        TraceExemptionReason, TraceGuardrailInputs, TraceOffenceHistory,
        TracePeerBehaviourIdentity, TracePeerObservationIdentity, TracePeerSessionState,
        TracePolicyInputs, duration_millis,
    },
    types::{
        BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity, PeerContext,
        PeerObservationId, PeerSessionState, PeerSnapshot, TorrentScope,
    },
};

fn main() -> Result<()> {
    run(std::env::args().skip(1).collect())
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SessionKey {
    torrent_hash: String,
    peer_ip: IpAddr,
    peer_port: u16,
}

impl SessionKey {
    fn from_observation_id(observation_id: &PeerObservationId) -> Self {
        Self {
            torrent_hash: observation_id.torrent_hash.clone(),
            peer_ip: observation_id.peer_ip,
            peer_port: observation_id.peer_port,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct OffenceKey {
    torrent_hash: String,
    peer_ip: IpAddr,
}

impl OffenceKey {
    fn from_offence_identity(offence_identity: &OffenceIdentity) -> Self {
        Self {
            torrent_hash: offence_identity.torrent_hash.clone(),
            peer_ip: offence_identity.peer_ip,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SimulatorConfig {
    inputs: Vec<PathBuf>,
    candidate_policy: PolicyConfig,
    candidate_overrides: Vec<PolicyOverride>,
    peer_ip: Option<IpAddr>,
}

impl SimulatorConfig {
    fn record_policy_override(&mut self, policy_override: PolicyOverride) {
        policy_override.apply(&mut self.candidate_policy);
        self.candidate_overrides.push(policy_override);
    }
}

#[derive(Debug, Clone, Copy)]
enum PolicyOverride {
    TargetRateBps(u64),
    RequiredProgressDelta(f64),
    ProgressRateScaleStart(f64),
    ProgressRateScaleEnd(f64),
    ProgressRateMinScale(f64),
    WeightRate(f64),
    WeightProgress(f64),
    RateRiskFloor(f64),
    BanThreshold(f64),
    ClearThreshold(f64),
    SustainDuration(Duration),
    DecayPerSecond(f64),
    MinObservationDuration(Duration),
    RebanCooldown(Duration),
    ChurnEnabled(bool),
    ChurnReconnectWindow(Duration),
    ChurnMinReconnects(u32),
    ChurnMaxAmplifier(f64),
    ChurnDecayPerSecond(f64),
}

impl PolicyOverride {
    fn apply(self, policy: &mut PolicyConfig) {
        match self {
            Self::TargetRateBps(value) => policy.score.target_rate_bps = value,
            Self::RequiredProgressDelta(value) => policy.score.required_progress_delta = value,
            Self::ProgressRateScaleStart(value) => policy.score.progress_rate_scale_start = value,
            Self::ProgressRateScaleEnd(value) => policy.score.progress_rate_scale_end = value,
            Self::ProgressRateMinScale(value) => policy.score.progress_rate_min_scale = value,
            Self::WeightRate(value) => policy.score.weight_rate = value,
            Self::WeightProgress(value) => policy.score.weight_progress = value,
            Self::RateRiskFloor(value) => policy.score.rate_risk_floor = value,
            Self::BanThreshold(value) => policy.score.ban_threshold = value,
            Self::ClearThreshold(value) => policy.score.clear_threshold = value,
            Self::SustainDuration(value) => policy.score.sustain_duration = value,
            Self::DecayPerSecond(value) => policy.score.decay_per_second = value,
            Self::MinObservationDuration(value) => policy.score.min_observation_duration = value,
            Self::RebanCooldown(value) => policy.reban_cooldown = value,
            Self::ChurnEnabled(value) => policy.score.churn.enabled = value,
            Self::ChurnReconnectWindow(value) => policy.score.churn.reconnect_window = value,
            Self::ChurnMinReconnects(value) => policy.score.churn.min_reconnects = value,
            Self::ChurnMaxAmplifier(value) => policy.score.churn.max_amplifier = value,
            Self::ChurnDecayPerSecond(value) => policy.score.churn.decay_per_second = value,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ActiveBanKey {
    torrent_hash: String,
    peer_ip: IpAddr,
    peer_port: u16,
}

#[derive(Default)]
struct Summary {
    lines_total: u64,
    lines_decision: u64,
    reproduction_passes: u64,
    reproduction_failures: u64,
    peers_seen: u64,
    simulated_bans: u64,
    actual_bans: u64,
    simulated_bans_with_churn: u64,
    churn_samples: u64,
    churn_max_amplifier: f64,
    churn_max_reconnect_count: u32,
    dropped_trace_records: u64,
    reproduction_problems: Vec<String>,
    decision_deltas: u64,
    decision_delta_reports: Vec<String>,
    score_state_deltas: u64,
    score_state_delta_reports: Vec<String>,
    guardrail_deltas: u64,
    guardrail_delta_reports: Vec<String>,
}

impl Summary {
    fn record_reproduction_pass(&mut self) {
        self.reproduction_passes += 1;
    }

    fn record_reproduction_problem(&mut self, problem: String) {
        self.reproduction_failures += 1;
        if self.reproduction_problems.len() < 20 {
            self.reproduction_problems.push(problem);
        }
    }

    fn record_candidate_deltas(
        &mut self,
        decision_deltas: Vec<String>,
        score_state_deltas: Vec<String>,
        guardrail_deltas: Vec<String>,
    ) {
        for delta in decision_deltas {
            self.decision_deltas += 1;
            if self.decision_delta_reports.len() < 20 {
                self.decision_delta_reports.push(delta);
            }
        }
        for delta in score_state_deltas {
            self.score_state_deltas += 1;
            if self.score_state_delta_reports.len() < 20 {
                self.score_state_delta_reports.push(delta);
            }
        }
        for delta in guardrail_deltas {
            self.guardrail_deltas += 1;
            if self.guardrail_delta_reports.len() < 20 {
                self.guardrail_delta_reports.push(delta);
            }
        }
    }

    fn has_reproduction_failures(&self) -> bool {
        self.reproduction_failures > 0 || self.dropped_trace_records > 0
    }
}

#[derive(Default)]
struct ReplayState {
    recorded_sessions: HashMap<SessionKey, PeerSessionState>,
    candidate_sessions: HashMap<SessionKey, PeerSessionState>,
    candidate_offences: HashMap<OffenceKey, OffenceHistory>,
    recorded_active_bans: HashMap<ActiveBanKey, SystemTime>,
    candidate_active_bans: HashMap<ActiveBanKey, SystemTime>,
    ban_events: HashMap<SessionKey, u32>,
}

pub fn run(args: Vec<String>) -> Result<()> {
    let config = parse_args(args)?;
    let mut state = ReplayState::default();
    let mut summary = Summary::default();

    for input in &config.inputs {
        let file = File::open(input)
            .with_context(|| format!("opening input file `{}`", input.display()))?;
        let reader = BufReader::new(file);
        process_reader(
            &config,
            reader,
            input.display().to_string(),
            &mut state,
            &mut summary,
        )?;
    }

    print_summary(&config, &summary, &state);
    if summary.has_reproduction_failures() {
        bail!(
            "current-policy reproduction failed: {} failures across {} trace records, {} dropped trace records",
            summary.reproduction_failures,
            summary.lines_decision,
            summary.dropped_trace_records
        );
    }
    Ok(())
}

fn process_reader<R: BufRead>(
    config: &SimulatorConfig,
    reader: R,
    source_name: String,
    state: &mut ReplayState,
    summary: &mut Summary,
) -> Result<()> {
    for (index, line_result) in reader.lines().enumerate() {
        let line = line_result
            .with_context(|| format!("reading line {} from `{source_name}`", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        summary.lines_total += 1;

        match parse_trace_line(&line)
            .with_context(|| format!("parsing line {} from `{source_name}`", index + 1))?
        {
            TraceInputLine::PeerObservation(record) => {
                process_trace_record(
                    config,
                    *record,
                    TraceLineContext {
                        source_name: &source_name,
                        line_number: index + 1,
                    },
                    state,
                    summary,
                )?;
            }
            TraceInputLine::DroppedRecords { dropped_count } => {
                summary.dropped_trace_records =
                    summary.dropped_trace_records.saturating_add(dropped_count);
                summary.record_reproduction_problem(format!(
                    "{source_name}:{} dropped_records notice reported {dropped_count} missing trace records",
                    index + 1
                ));
            }
        }
    }

    Ok(())
}

enum TraceInputLine {
    PeerObservation(Box<PolicyTraceRecord>),
    DroppedRecords { dropped_count: u64 },
}

#[derive(Clone, Copy)]
struct TraceLineContext<'a> {
    source_name: &'a str,
    line_number: usize,
}

struct TracePeerContext {
    torrent: TorrentScope,
    peer: PeerSnapshot,
    first_seen_at: SystemTime,
    observed_at: SystemTime,
}

struct TraceEvaluation {
    evaluation: brrpolice::types::PeerEvaluation,
    disposition: BanDisposition,
}

fn parse_trace_line(line: &str) -> Result<TraceInputLine> {
    let value: Value = serde_json::from_str(line).context("invalid JSON trace line")?;
    let record_type = value
        .get("record_type")
        .and_then(Value::as_str)
        .context("expected ADR-0004 policy trace line with top-level record_type")?;
    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .context("expected ADR-0004 policy trace line with top-level schema_version")?;
    if schema_version != u64::from(POLICY_TRACE_SCHEMA_VERSION) {
        bail!("unsupported policy trace schema_version `{schema_version}`");
    }

    match record_type {
        "peer_observation" => Ok(TraceInputLine::PeerObservation(Box::new(
            serde_json::from_value(value).context("invalid peer_observation trace record")?,
        ))),
        "dropped_records" => {
            let dropped_count = value
                .get("dropped_count")
                .and_then(Value::as_u64)
                .context("dropped_records trace line missing dropped_count")?;
            Ok(TraceInputLine::DroppedRecords { dropped_count })
        }
        other => bail!("unsupported policy trace record_type `{other}`"),
    }
}

fn process_trace_record(
    config: &SimulatorConfig,
    record: PolicyTraceRecord,
    line_context: TraceLineContext<'_>,
    state: &mut ReplayState,
    summary: &mut Summary,
) -> Result<()> {
    summary.lines_decision += 1;
    validate_required_trace_fields(&record)?;
    let observed_at =
        parse_rfc3339(&record.observed_at).context("parsing trace observed_at timestamp")?;
    let peer_ip = record
        .peer
        .ip
        .context("trace peer.ip is required for simulator replay")?;
    if let Some(filter_ip) = config.peer_ip
        && peer_ip != filter_ip
    {
        return Ok(());
    }
    state
        .recorded_active_bans
        .retain(|_, expires_at| *expires_at > observed_at);
    state
        .candidate_active_bans
        .retain(|_, expires_at| *expires_at > observed_at);

    let observation_id =
        observation_id_from_trace(&record.simulator_hints.peer_observation_identity)?;
    let session_key = SessionKey::from_observation_id(&observation_id);
    let offence_identity =
        offence_identity_from_trace(&record.simulator_hints.peer_behaviour_identity)?;
    let offence_key = OffenceKey::from_offence_identity(&offence_identity);
    let existing = record
        .prior_session
        .as_ref()
        .map(session_from_trace)
        .transpose()?;
    if !state.recorded_sessions.contains_key(&session_key) && existing.is_none() {
        summary.peers_seen += 1;
    }

    let recorded_has_active_ban = state.recorded_active_bans.contains_key(&ActiveBanKey {
        torrent_hash: record.torrent.hash.clone(),
        peer_ip,
        peer_port: record.peer.port,
    });
    let candidate_has_active_ban = state.candidate_active_bans.contains_key(&ActiveBanKey {
        torrent_hash: record.torrent.hash.clone(),
        peer_ip,
        peer_port: record.peer.port,
    });

    let peer_context = TracePeerContext {
        torrent: TorrentScope {
            hash: record.torrent.hash.clone(),
            name: record
                .torrent
                .name
                .clone()
                .unwrap_or_else(|| record.torrent.hash.clone()),
            tracker: record.torrent.tracker.clone(),
            category: record.torrent.category.clone(),
            tags: record.torrent.tags.clone(),
            total_seeders: record.torrent.total_seeders,
            in_scope: record.torrent.in_scope,
        },
        peer: PeerSnapshot {
            ip: peer_ip,
            port: record.peer.port,
            progress: record.peer.progress,
            up_rate_bps: record.peer.up_rate_bps,
        },
        first_seen_at: record
            .prior_session
            .as_ref()
            .map(|session| parse_rfc3339(&session.first_seen_at))
            .transpose()
            .context("parsing trace prior_session.first_seen_at")?
            .unwrap_or(
                parse_rfc3339(&record.evaluated_session.first_seen_at)
                    .context("parsing trace evaluated_session.first_seen_at")?,
            ),
        observed_at,
    };

    let history = OffenceHistory {
        offence_count: record.guardrail_inputs.offence_history.offence_count,
        last_ban_expires_at: record
            .guardrail_inputs
            .offence_history
            .last_ban_expires_at
            .as_ref()
            .map(|value| parse_rfc3339(value))
            .transpose()
            .context("parsing trace offence_history.last_ban_expires_at")?,
    };
    let candidate_existing = state
        .candidate_sessions
        .get(&session_key)
        .or(existing.as_ref());
    let candidate_history = state
        .candidate_offences
        .get(&offence_key)
        .cloned()
        .unwrap_or_else(|| history.clone());

    let replay_policy = policy_config_from_trace(&record.policy_inputs);
    let current = evaluate_trace(
        &replay_policy,
        &peer_context,
        recorded_has_active_ban,
        existing.as_ref(),
        &history,
    );
    let current_reproduced = check_current_policy_reproduction(
        &replay_policy,
        &record,
        &current.evaluation,
        &current.disposition,
        &history,
        summary,
        line_context,
    );

    let mut candidate_policy = replay_policy.clone();
    for policy_override in &config.candidate_overrides {
        policy_override.apply(&mut candidate_policy);
    }
    let candidate = evaluate_trace(
        &candidate_policy,
        &peer_context,
        candidate_has_active_ban,
        candidate_existing,
        &candidate_history,
    );
    if current_reproduced {
        record_candidate_deltas(
            &record,
            &candidate,
            &candidate_history,
            summary,
            line_context,
        );
    }

    if candidate.evaluation.session.churn_amplifier > 0.0 {
        summary.churn_samples += 1;
        summary.churn_max_amplifier = summary
            .churn_max_amplifier
            .max(candidate.evaluation.session.churn_amplifier);
    }
    summary.churn_max_reconnect_count = summary
        .churn_max_reconnect_count
        .max(candidate.evaluation.session.churn_reconnect_count);

    let mut candidate_session = candidate.evaluation.session.clone();
    match &candidate.disposition {
        BanDisposition::Ban(decision) => {
            summary.simulated_bans += 1;
            if candidate.evaluation.session.churn_amplifier > 0.0 {
                summary.simulated_bans_with_churn += 1;
            }
            *state.ban_events.entry(session_key.clone()).or_default() += 1;
            let expires_at = observed_at + decision.ttl;
            state.candidate_active_bans.insert(
                ActiveBanKey {
                    torrent_hash: record.torrent.hash.clone(),
                    peer_ip,
                    peer_port: record.peer.port,
                },
                expires_at,
            );
            candidate_session.last_ban_decision_at = Some(observed_at);
            state.candidate_offences.insert(
                OffenceKey::from_offence_identity(&candidate_session.offence_identity),
                OffenceHistory {
                    offence_count: decision.offence_number,
                    last_ban_expires_at: Some(expires_at),
                },
            );
        }
        BanDisposition::Exempt(_)
        | BanDisposition::NotBannableYet { .. }
        | BanDisposition::RebanCooldown { .. }
        | BanDisposition::DuplicateSuppressed => {
            state
                .candidate_offences
                .entry(offence_key)
                .or_insert(candidate_history);
        }
    }
    state
        .candidate_sessions
        .insert(session_key.clone(), candidate_session);

    if let TraceBanDisposition::Ban { decision } = &record.decision_output.disposition {
        summary.actual_bans += 1;
        record_recorded_ban(state, decision, &record.torrent.hash, observed_at)?;
    }
    state
        .recorded_sessions
        .insert(session_key, session_from_trace(&record.evaluated_session)?);
    Ok(())
}

fn evaluate_trace(
    policy_config: &PolicyConfig,
    trace_context: &TracePeerContext,
    has_active_ban: bool,
    existing: Option<&PeerSessionState>,
    history: &OffenceHistory,
) -> TraceEvaluation {
    let policy = PolicyEngine::new(policy_config.clone(), &FiltersConfig::default());
    let peer_context = PeerContext {
        torrent: trace_context.torrent.clone(),
        peer: trace_context.peer.clone(),
        first_seen_at: trace_context.first_seen_at,
        observed_at: trace_context.observed_at,
        has_active_ban,
    };
    let evaluation = policy.evaluate_peer(&peer_context, existing);
    let disposition = policy.decide_ban(&peer_context, &evaluation, history);

    TraceEvaluation {
        evaluation,
        disposition,
    }
}

fn validate_required_trace_fields(record: &PolicyTraceRecord) -> Result<()> {
    if record.record_type != brrpolice::policy_trace::PolicyTraceRecordType::PeerObservation {
        bail!("unsupported policy trace record type");
    }
    if record.schema_version != POLICY_TRACE_SCHEMA_VERSION {
        bail!(
            "unsupported policy trace schema_version `{}`",
            record.schema_version
        );
    }
    let _ = observation_id_from_trace(&record.simulator_hints.peer_observation_identity)?;
    let _ = offence_identity_from_trace(&record.simulator_hints.peer_behaviour_identity)?;
    let _ = session_from_trace(&record.evaluated_session)?;
    if record.service_version.trim().is_empty() {
        bail!("trace record missing service_version");
    }
    if record.policy_trace_id.trim().is_empty() {
        bail!("trace record missing policy_trace_id");
    }
    if record.config_fingerprint.trim().is_empty() {
        bail!("trace record missing config_fingerprint");
    }
    Ok(())
}

fn policy_config_from_trace(inputs: &TracePolicyInputs) -> PolicyConfig {
    PolicyConfig {
        new_peer_grace_period: Duration::from_millis(inputs.new_peer_grace_period_ms),
        decay_window: Duration::from_millis(inputs.decay_window_ms),
        ignore_peer_progress_at_or_above: inputs.ignore_peer_progress_at_or_above,
        min_total_seeders: inputs.min_total_seeders,
        reban_cooldown: Duration::from_millis(inputs.reban_cooldown_ms),
        score: ScorePolicyConfig {
            target_rate_bps: inputs.score.target_rate_bps,
            required_progress_delta: inputs.score.required_progress_delta,
            progress_rate_scale_start: inputs.score.progress_rate_scale_start,
            progress_rate_scale_end: inputs.score.progress_rate_scale_end,
            progress_rate_min_scale: inputs.score.progress_rate_min_scale,
            weight_rate: inputs.score.weight_rate,
            weight_progress: inputs.score.weight_progress,
            rate_risk_floor: inputs.score.rate_risk_floor,
            ban_threshold: inputs.score.ban_threshold,
            clear_threshold: inputs.score.clear_threshold,
            sustain_duration: Duration::from_millis(inputs.score.sustain_duration_ms),
            decay_per_second: inputs.score.decay_per_second,
            min_observation_duration: Duration::from_millis(
                inputs.score.min_observation_duration_ms,
            ),
            max_score: inputs.score.max_score,
            churn: ChurnPolicyConfig {
                enabled: inputs.score.churn_enabled,
                reconnect_window: Duration::from_millis(inputs.score.churn_reconnect_window_ms),
                min_reconnects: inputs.score.churn_min_reconnects,
                max_amplifier: inputs.score.churn_max_amplifier,
                decay_per_second: inputs.score.churn_decay_per_second,
            },
        },
        ban_ladder: BanLadderConfig {
            durations: inputs
                .ban_ladder_duration_ms
                .iter()
                .copied()
                .map(Duration::from_millis)
                .collect(),
        },
    }
}

fn check_current_policy_reproduction(
    replay_policy: &PolicyConfig,
    record: &PolicyTraceRecord,
    evaluation: &brrpolice::types::PeerEvaluation,
    disposition: &BanDisposition,
    history: &OffenceHistory,
    summary: &mut Summary,
    line_context: TraceLineContext<'_>,
) -> bool {
    let replayed_policy_inputs = TracePolicyInputs::from(replay_policy);
    let replayed_session = TracePeerSessionState::from(&evaluation.session);
    let replayed_decision_output =
        TraceDecisionOutput::from_evaluation_and_disposition(evaluation, disposition);
    let replayed_guardrail_inputs = trace_guardrail_inputs(evaluation, disposition, history);
    let context = trace_report_context(record, line_context);

    let mut reproduction_problems = Vec::new();
    if record.policy_inputs != replayed_policy_inputs {
        reproduction_problems.push(format!(
            "{context} policy_inputs recorded={} replayed={}",
            abbrev_debug(&record.policy_inputs),
            abbrev_debug(&replayed_policy_inputs)
        ));
    }
    if record.evaluated_session != replayed_session {
        reproduction_problems.push(format!(
            "{context} evaluated_session recorded={} replayed={}",
            abbrev_debug(&record.evaluated_session),
            abbrev_debug(&replayed_session)
        ));
    }
    if record.decision_output != replayed_decision_output {
        reproduction_problems.push(format!(
            "{context} decision_output recorded={} replayed={}",
            abbrev_debug(&record.decision_output),
            abbrev_debug(&replayed_decision_output)
        ));
    }
    if record.guardrail_inputs != replayed_guardrail_inputs {
        reproduction_problems.push(format!(
            "{context} guardrail_inputs recorded={} replayed={}",
            abbrev_debug(&record.guardrail_inputs),
            abbrev_debug(&replayed_guardrail_inputs)
        ));
    }

    if reproduction_problems.is_empty() {
        summary.record_reproduction_pass();
        true
    } else {
        summary.reproduction_failures += 1;
        for problem in reproduction_problems {
            if summary.reproduction_problems.len() < 20 {
                summary.reproduction_problems.push(problem);
            }
        }
        false
    }
}

fn record_candidate_deltas(
    record: &PolicyTraceRecord,
    candidate: &TraceEvaluation,
    history: &OffenceHistory,
    summary: &mut Summary,
    line_context: TraceLineContext<'_>,
) {
    let candidate_session = TracePeerSessionState::from(&candidate.evaluation.session);
    let candidate_decision_output = TraceDecisionOutput::from_evaluation_and_disposition(
        &candidate.evaluation,
        &candidate.disposition,
    );
    let candidate_guardrail_inputs =
        trace_guardrail_inputs(&candidate.evaluation, &candidate.disposition, history);
    let context = trace_report_context(record, line_context);

    let decision_deltas = if record.decision_output != candidate_decision_output {
        vec![format!(
            "{context} decision_output recorded={} candidate={}",
            abbrev_debug(&record.decision_output),
            abbrev_debug(&candidate_decision_output)
        )]
    } else {
        Vec::new()
    };
    let score_state_deltas = if record.evaluated_session != candidate_session {
        vec![format!(
            "{context} evaluated_session recorded={} candidate={}",
            abbrev_debug(&record.evaluated_session),
            abbrev_debug(&candidate_session)
        )]
    } else {
        Vec::new()
    };
    let guardrail_deltas = if record.guardrail_inputs != candidate_guardrail_inputs {
        vec![format!(
            "{context} guardrail_inputs recorded={} candidate={}",
            abbrev_debug(&record.guardrail_inputs),
            abbrev_debug(&candidate_guardrail_inputs)
        )]
    } else {
        Vec::new()
    };

    summary.record_candidate_deltas(decision_deltas, score_state_deltas, guardrail_deltas);
}

fn trace_guardrail_inputs(
    evaluation: &brrpolice::types::PeerEvaluation,
    disposition: &BanDisposition,
    history: &OffenceHistory,
) -> TraceGuardrailInputs {
    TraceGuardrailInputs {
        exemption_reason: evaluation
            .session
            .last_exemption_reason
            .as_ref()
            .map(Into::into),
        allowlisted_peer: matches!(
            evaluation.session.last_exemption_reason,
            Some(ExemptionReason::AllowlistedPeer)
        ),
        active_ban: matches!(
            evaluation.session.last_exemption_reason,
            Some(ExemptionReason::AlreadyBanned)
        ),
        reban_cooldown_remaining_ms: match disposition {
            BanDisposition::RebanCooldown { remaining } => Some(duration_millis(*remaining)),
            _ => None,
        },
        offence_history: TraceOffenceHistory::from(history),
    }
}

fn trace_report_context(record: &PolicyTraceRecord, line_context: TraceLineContext<'_>) -> String {
    format!(
        "{}:{} trace_id={} torrent_hash={} peer={}:{}",
        line_context.source_name,
        line_context.line_number,
        record.policy_trace_id,
        record.torrent.hash,
        record
            .peer
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "<redacted>".to_string()),
        record.peer.port
    )
}

fn abbrev_debug<T: std::fmt::Debug>(value: &T) -> String {
    const LIMIT: usize = 320;
    let rendered = format!("{value:?}");
    if rendered.len() <= LIMIT {
        rendered
    } else {
        format!("{}...", rendered.chars().take(LIMIT).collect::<String>())
    }
}

fn record_recorded_ban(
    state: &mut ReplayState,
    decision: &brrpolice::policy_trace::TraceBanDecision,
    torrent_hash: &str,
    observed_at: SystemTime,
) -> Result<()> {
    let peer_ip = decision
        .peer_ip
        .context("recorded ban decision peer_ip is required for simulator replay")?;
    let ttl = Duration::from_millis(decision.ttl_ms);
    let expires_at = observed_at + ttl;
    state.recorded_active_bans.insert(
        ActiveBanKey {
            torrent_hash: torrent_hash.to_string(),
            peer_ip,
            peer_port: decision.peer_port,
        },
        expires_at,
    );
    Ok(())
}

fn session_from_trace(value: &TracePeerSessionState) -> Result<PeerSessionState> {
    Ok(PeerSessionState {
        observation_id: observation_id_from_trace(&value.observation_id)?,
        offence_identity: offence_identity_from_trace(&value.offence_identity)?,
        first_seen_at: parse_rfc3339(&value.first_seen_at)
            .context("parsing trace session first_seen_at")?,
        last_seen_at: parse_rfc3339(&value.last_seen_at)
            .context("parsing trace session last_seen_at")?,
        baseline_progress: value.baseline_progress,
        latest_progress: value.latest_progress,
        rolling_avg_up_rate_bps: value.rolling_avg_up_rate_bps,
        observed_duration: Duration::from_millis(value.observed_duration_ms),
        bad_duration: Duration::from_millis(value.bad_duration_ms),
        ban_score: value.ban_score,
        ban_score_above_threshold_duration: Duration::from_millis(
            value.ban_score_above_threshold_duration_ms,
        ),
        churn_reconnect_count: value.churn_reconnect_count,
        churn_window_started_at: value
            .churn_window_started_at
            .as_ref()
            .map(|timestamp| parse_rfc3339(timestamp))
            .transpose()
            .context("parsing trace session churn_window_started_at")?,
        churn_amplifier: value.churn_amplifier,
        sample_count: value.sample_count,
        last_torrent_seeder_count: value.last_torrent_seeder_count,
        last_exemption_reason: value
            .last_exemption_reason
            .as_ref()
            .map(exemption_from_trace)
            .transpose()?,
        bannable_since: value
            .bannable_since
            .as_ref()
            .map(|timestamp| parse_rfc3339(timestamp))
            .transpose()
            .context("parsing trace session bannable_since")?,
        last_ban_decision_at: value
            .last_ban_decision_at
            .as_ref()
            .map(|timestamp| parse_rfc3339(timestamp))
            .transpose()
            .context("parsing trace session last_ban_decision_at")?,
    })
}

fn observation_id_from_trace(value: &TracePeerObservationIdentity) -> Result<PeerObservationId> {
    Ok(PeerObservationId {
        torrent_hash: value.torrent_hash.clone(),
        peer_ip: value
            .peer_ip
            .context("trace peer observation identity peer_ip is required for simulator replay")?,
        peer_port: value.peer_port,
    })
}

fn offence_identity_from_trace(value: &TracePeerBehaviourIdentity) -> Result<OffenceIdentity> {
    Ok(OffenceIdentity {
        torrent_hash: value.torrent_hash.clone(),
        peer_ip: value
            .peer_ip
            .context("trace peer behaviour identity peer_ip is required for simulator replay")?,
    })
}

fn exemption_from_trace(value: &TraceExemptionReason) -> Result<ExemptionReason> {
    Ok(match value {
        TraceExemptionReason::TorrentExcluded => ExemptionReason::TorrentExcluded,
        TraceExemptionReason::AllowlistedPeer => ExemptionReason::AllowlistedPeer,
        TraceExemptionReason::NearComplete {
            progress,
            threshold,
        } => ExemptionReason::NearComplete {
            progress: *progress,
            threshold: *threshold,
        },
        TraceExemptionReason::NewPeerGracePeriod {
            age_ms,
            grace_period_ms,
        } => ExemptionReason::NewPeerGracePeriod {
            age: Duration::from_millis(*age_ms),
            grace_period: Duration::from_millis(*grace_period_ms),
        },
        TraceExemptionReason::AlreadyBanned => ExemptionReason::AlreadyBanned,
    })
}

fn print_summary(config: &SimulatorConfig, summary: &Summary, state: &ReplayState) {
    println!("score simulator summary");
    println!(
        "inputs={}",
        config
            .inputs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "config: target_rate_bps={} required_progress_delta={:.6} progress_rate_scale(start={:.3},end={:.3},min={:.3}) weights(rate={:.3},progress={:.3}) rate_risk_floor={:.3} threshold(ban={:.3},clear={:.3}) sustain_seconds={} decay_per_second={:.6} min_observation_seconds={} reban_cooldown_seconds={} churn(enabled={},window_seconds={},min_reconnects={},max_amplifier={:.3},decay_per_second={:.6})",
        config.candidate_policy.score.target_rate_bps,
        config.candidate_policy.score.required_progress_delta,
        config.candidate_policy.score.progress_rate_scale_start,
        config.candidate_policy.score.progress_rate_scale_end,
        config.candidate_policy.score.progress_rate_min_scale,
        config.candidate_policy.score.weight_rate,
        config.candidate_policy.score.weight_progress,
        config.candidate_policy.score.rate_risk_floor,
        config.candidate_policy.score.ban_threshold,
        config.candidate_policy.score.clear_threshold,
        config.candidate_policy.score.sustain_duration.as_secs(),
        config.candidate_policy.score.decay_per_second,
        config
            .candidate_policy
            .score
            .min_observation_duration
            .as_secs(),
        config.candidate_policy.reban_cooldown.as_secs(),
        config.candidate_policy.score.churn.enabled,
        config
            .candidate_policy
            .score
            .churn
            .reconnect_window
            .as_secs(),
        config.candidate_policy.score.churn.min_reconnects,
        config.candidate_policy.score.churn.max_amplifier,
        config.candidate_policy.score.churn.decay_per_second,
    );
    println!(
        "candidate_overrides={}",
        if config.candidate_overrides.is_empty() {
            "none".to_string()
        } else {
            config.candidate_overrides.len().to_string()
        }
    );
    if let Some(peer_ip) = config.peer_ip {
        println!("peer_filter_ip={peer_ip}");
    }
    println!(
        "lines_total={} decision_lines={} dropped_trace_records={} reproduction_passes={} reproduction_failures={} peers_seen={} simulated_bans={} actual_bans={} simulated_bans_with_churn={} churn_samples={} churn_max_amplifier={:.4} churn_max_reconnect_count={}",
        summary.lines_total,
        summary.lines_decision,
        summary.dropped_trace_records,
        summary.reproduction_passes,
        summary.reproduction_failures,
        summary.peers_seen,
        summary.simulated_bans,
        summary.actual_bans,
        summary.simulated_bans_with_churn,
        summary.churn_samples,
        summary.churn_max_amplifier,
        summary.churn_max_reconnect_count
    );
    println!(
        "current_policy_reproduction: passes={} failures={} data_problems={}",
        summary.reproduction_passes,
        summary.reproduction_failures,
        summary.reproduction_problems.len()
    );
    for problem in &summary.reproduction_problems {
        println!("reproduction_failure {problem}");
    }
    println!(
        "candidate_decision_deltas: count={}",
        summary.decision_deltas
    );
    for delta in &summary.decision_delta_reports {
        println!("decision_delta {delta}");
    }
    println!(
        "candidate_score_state_deltas: count={}",
        summary.score_state_deltas
    );
    for delta in &summary.score_state_delta_reports {
        println!("score_state_delta {delta}");
    }
    println!(
        "guardrail_or_exemption_deltas: count={}",
        summary.guardrail_deltas
    );
    for delta in &summary.guardrail_delta_reports {
        println!("guardrail_delta {delta}");
    }

    let mut interesting: Vec<(&SessionKey, &u32)> = state
        .ban_events
        .iter()
        .filter(|(_, count)| **count > 0)
        .collect();
    interesting.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (observation_id, count) in interesting.into_iter().take(20) {
        let final_score = state
            .candidate_sessions
            .get(observation_id)
            .map(|session| session.ban_score)
            .unwrap_or(0.0);
        println!(
            "simulated_ban peer={} port={} torrent_hash={} ban_events={} final_score={:.3} final_churn_amplifier={:.3} final_churn_reconnect_count={}",
            observation_id.peer_ip,
            observation_id.peer_port,
            observation_id.torrent_hash,
            count,
            final_score,
            state
                .candidate_sessions
                .get(observation_id)
                .map(|session| session.churn_amplifier)
                .unwrap_or(0.0),
            state
                .candidate_sessions
                .get(observation_id)
                .map(|session| session.churn_reconnect_count)
                .unwrap_or(0),
        );
    }
}

fn parse_args(args: Vec<String>) -> Result<SimulatorConfig> {
    let mut config = SimulatorConfig::default();
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                let value = iter.next().context("expected path after `--input`")?;
                config.inputs.push(PathBuf::from(value));
            }
            "--target-rate-bps" => {
                config.record_policy_override(PolicyOverride::TargetRateBps(parse_u64_arg(
                    &mut iter,
                    "--target-rate-bps",
                )?));
            }
            "--required-progress-delta" => {
                config.record_policy_override(PolicyOverride::RequiredProgressDelta(
                    parse_f64_arg(&mut iter, "--required-progress-delta")?,
                ));
            }
            "--progress-rate-scale-start" => {
                config.record_policy_override(PolicyOverride::ProgressRateScaleStart(
                    parse_f64_arg(&mut iter, "--progress-rate-scale-start")?,
                ));
            }
            "--progress-rate-scale-end" => {
                config.record_policy_override(PolicyOverride::ProgressRateScaleEnd(parse_f64_arg(
                    &mut iter,
                    "--progress-rate-scale-end",
                )?));
            }
            "--progress-rate-min-scale" => {
                config.record_policy_override(PolicyOverride::ProgressRateMinScale(parse_f64_arg(
                    &mut iter,
                    "--progress-rate-min-scale",
                )?));
            }
            "--weight-rate" => {
                config.record_policy_override(PolicyOverride::WeightRate(parse_f64_arg(
                    &mut iter,
                    "--weight-rate",
                )?));
            }
            "--weight-progress" => {
                config.record_policy_override(PolicyOverride::WeightProgress(parse_f64_arg(
                    &mut iter,
                    "--weight-progress",
                )?));
            }
            "--rate-risk-floor" => {
                config.record_policy_override(PolicyOverride::RateRiskFloor(parse_f64_arg(
                    &mut iter,
                    "--rate-risk-floor",
                )?));
            }
            "--ban-threshold" => {
                config.record_policy_override(PolicyOverride::BanThreshold(parse_f64_arg(
                    &mut iter,
                    "--ban-threshold",
                )?));
            }
            "--clear-threshold" => {
                config.record_policy_override(PolicyOverride::ClearThreshold(parse_f64_arg(
                    &mut iter,
                    "--clear-threshold",
                )?));
            }
            "--sustain-seconds" => {
                config.record_policy_override(PolicyOverride::SustainDuration(
                    Duration::from_secs(parse_u64_arg(&mut iter, "--sustain-seconds")?),
                ));
            }
            "--decay-per-second" => {
                config.record_policy_override(PolicyOverride::DecayPerSecond(parse_f64_arg(
                    &mut iter,
                    "--decay-per-second",
                )?));
            }
            "--min-observation-seconds" => {
                config.record_policy_override(PolicyOverride::MinObservationDuration(
                    Duration::from_secs(parse_u64_arg(&mut iter, "--min-observation-seconds")?),
                ));
            }
            "--reban-cooldown-seconds" => {
                config.record_policy_override(PolicyOverride::RebanCooldown(Duration::from_secs(
                    parse_u64_arg(&mut iter, "--reban-cooldown-seconds")?,
                )));
            }
            "--churn-enabled" => {
                config.record_policy_override(PolicyOverride::ChurnEnabled(true));
            }
            "--churn-disabled" => {
                config.record_policy_override(PolicyOverride::ChurnEnabled(false));
            }
            "--churn-reconnect-window-seconds" => {
                config.record_policy_override(PolicyOverride::ChurnReconnectWindow(
                    Duration::from_secs(parse_u64_arg(
                        &mut iter,
                        "--churn-reconnect-window-seconds",
                    )?),
                ));
            }
            "--churn-min-reconnects" => {
                config.record_policy_override(PolicyOverride::ChurnMinReconnects(parse_u32_arg(
                    &mut iter,
                    "--churn-min-reconnects",
                )?));
            }
            "--churn-max-amplifier" => {
                config.record_policy_override(PolicyOverride::ChurnMaxAmplifier(parse_f64_arg(
                    &mut iter,
                    "--churn-max-amplifier",
                )?));
            }
            "--churn-decay-per-second" => {
                config.record_policy_override(PolicyOverride::ChurnDecayPerSecond(parse_f64_arg(
                    &mut iter,
                    "--churn-decay-per-second",
                )?));
            }
            "--peer-ip" => {
                let value = iter.next().context("expected peer IP after `--peer-ip`")?;
                config.peer_ip = Some(
                    value
                        .parse::<IpAddr>()
                        .with_context(|| format!("invalid peer IP `{value}`"))?,
                );
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown argument `{other}`; use `score-simulator --help`"),
        }
    }

    if config.inputs.is_empty() {
        bail!("missing required `--input` argument (can be repeated)");
    }
    if !(0.0..=1.0).contains(&config.candidate_policy.score.required_progress_delta) {
        bail!("--required-progress-delta must be between 0.0 and 1.0");
    }
    if config.candidate_policy.score.progress_rate_scale_start < 1.0 {
        bail!("--progress-rate-scale-start must be >= 1.0");
    }
    if config.candidate_policy.score.progress_rate_scale_end
        < config.candidate_policy.score.progress_rate_scale_start
    {
        bail!("--progress-rate-scale-end must be >= --progress-rate-scale-start");
    }
    if !(0.0..=1.0).contains(&config.candidate_policy.score.progress_rate_min_scale) {
        bail!("--progress-rate-min-scale must be between 0.0 and 1.0");
    }
    if config.candidate_policy.score.weight_rate < 0.0
        || config.candidate_policy.score.weight_progress < 0.0
    {
        bail!("weights must be non-negative");
    }
    if !(0.0..=1.0).contains(&config.candidate_policy.score.rate_risk_floor) {
        bail!("--rate-risk-floor must be between 0.0 and 1.0");
    }
    if config.candidate_policy.score.clear_threshold > config.candidate_policy.score.ban_threshold {
        bail!("--clear-threshold must be <= --ban-threshold");
    }
    if config.candidate_policy.score.churn.min_reconnects == 0 {
        bail!("--churn-min-reconnects must be >= 1");
    }
    if config.candidate_policy.score.churn.max_amplifier < 0.0 {
        bail!("--churn-max-amplifier must be >= 0.0");
    }
    if config.candidate_policy.score.churn.decay_per_second < 0.0 {
        bail!("--churn-decay-per-second must be >= 0.0");
    }

    Ok(config)
}

fn parse_u32_arg(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<u32> {
    let value = iter
        .next()
        .with_context(|| format!("expected value after `{flag}`"))?;
    value
        .parse::<u32>()
        .with_context(|| format!("invalid integer for `{flag}`: `{value}`"))
}

fn parse_u64_arg(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<u64> {
    let value = iter
        .next()
        .with_context(|| format!("expected value after `{flag}`"))?;
    value
        .parse::<u64>()
        .with_context(|| format!("invalid integer for `{flag}`: `{value}`"))
}

fn parse_f64_arg(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<f64> {
    let value = iter
        .next()
        .with_context(|| format!("expected value after `{flag}`"))?;
    value
        .parse::<f64>()
        .with_context(|| format!("invalid number for `{flag}`: `{value}`"))
}

fn print_help() {
    println!("Usage:");
    println!("  score-simulator --input <trace.jsonl> [--input <trace.jsonl> ...] [options]");
    println!();
    println!("Input:");
    println!("  Each input must be ADR-0004 policy trace JSONL with schema_version=1 records.");
    println!("  Legacy structured operator logs are rejected.");
    println!();
    println!("Options:");
    println!("  --target-rate-bps <n>            Upload target for rate-risk");
    println!("  --required-progress-delta <f>    Required progress fraction in window");
    println!("  --progress-rate-scale-start <f>  Rate multiple where progress scaling begins");
    println!("  --progress-rate-scale-end <f>    Rate multiple where progress scaling reaches min");
    println!("  --progress-rate-min-scale <f>    Minimum scale applied to required progress");
    println!("  --weight-rate <f>                Weight for rate-risk feature");
    println!("  --weight-progress <f>            Weight for progress-risk feature");
    println!("  --rate-risk-floor <f>            Non-compensatory floor multiplier for rate risk");
    println!("  --ban-threshold <f>              Score threshold to qualify for ban");
    println!("  --clear-threshold <f>            Clear threshold after cooldown/hysteresis");
    println!("  --sustain-seconds <n>            Seconds score must stay above threshold");
    println!("  --decay-per-second <f>           Score decay rate per second");
    println!("  --min-observation-seconds <n>    Minimum observation before scoring can ban");
    println!("  --reban-cooldown-seconds <n>     Cooldown after ban expiry before re-banning");
    println!("  --churn-enabled                  Enable churn amplification feature");
    println!("  --churn-disabled                 Disable churn amplification feature");
    println!("  --churn-reconnect-window-seconds <n>  Reconnect counting window");
    println!("  --churn-min-reconnects <n>       Reconnect threshold before churn amplification");
    println!("  --churn-max-amplifier <f>        Maximum churn amplifier added to sample risk");
    println!("  --churn-decay-per-second <f>     Churn amplifier decay rate");
    println!("  --peer-ip <ip>                   Optional peer IP filter");
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::{Summary, parse_args, process_reader};
    use brrpolice::{
        policy::PolicyEngine,
        policy_trace::{
            POLICY_TRACE_SCHEMA_VERSION, PolicyTraceRecord, PolicyTraceRecordType,
            TraceDecisionOutput, TraceGuardrailInputs, TraceOffenceHistory, TracePeer,
            TracePolicyInputs, TraceSimulatorHints, TraceTorrent, trace_timestamp,
        },
        types::{OffenceHistory, PeerContext, PeerSessionState, PeerSnapshot, TorrentScope},
    };

    #[test]
    fn parse_args_supports_multiple_inputs() {
        let args = vec![
            "--input".to_string(),
            "one.jsonl".to_string(),
            "--input".to_string(),
            "two.jsonl".to_string(),
        ];
        let config = parse_args(args).expect("expected args to parse");
        assert_eq!(
            config.inputs,
            vec![PathBuf::from("one.jsonl"), PathBuf::from("two.jsonl")]
        );
    }

    #[test]
    fn parse_args_supports_churn_flags() {
        let args = vec![
            "--input".to_string(),
            "one.jsonl".to_string(),
            "--churn-enabled".to_string(),
            "--churn-reconnect-window-seconds".to_string(),
            "120".to_string(),
            "--churn-min-reconnects".to_string(),
            "2".to_string(),
            "--churn-max-amplifier".to_string(),
            "0.8".to_string(),
            "--churn-decay-per-second".to_string(),
            "0.03".to_string(),
        ];
        let config = parse_args(args).expect("expected args to parse");
        assert!(config.candidate_policy.score.churn.enabled);
        assert_eq!(
            config
                .candidate_policy
                .score
                .churn
                .reconnect_window
                .as_secs(),
            120
        );
        assert_eq!(config.candidate_policy.score.churn.min_reconnects, 2);
        assert!((config.candidate_policy.score.churn.max_amplifier - 0.8).abs() < f64::EPSILON);
        assert!((config.candidate_policy.score.churn.decay_per_second - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_args_rejects_legacy_recompute_score_flag() {
        let args = vec![
            "--input".to_string(),
            "one.jsonl".to_string(),
            "--recompute-score".to_string(),
        ];
        let error = parse_args(args).unwrap_err();
        assert!(format!("{error:#}").contains("unknown argument `--recompute-score`"));
    }

    #[test]
    fn trace_reader_consumes_schema_v1_fixtures() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();

        let replay = Cursor::new(format!(
            "{}\n{}\n{}\n",
            fixture_line(include_str!(
                "../../../testdata/policy-trace/v1-exempt-peer.json"
            )),
            fixture_line(include_str!(
                "../../../testdata/policy-trace/v1-not-bannable-peer.json"
            )),
            fixture_line(include_str!(
                "../../../testdata/policy-trace/v1-ban-decision.json"
            ))
        ));

        process_reader(
            &config,
            replay,
            "fixtures".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.lines_total, 3);
        assert_eq!(summary.lines_decision, 3);
        assert_eq!(
            summary.reproduction_passes + summary.reproduction_failures,
            3
        );
        assert_eq!(summary.actual_bans, 1);
        assert_eq!(summary.peers_seen, 1);
        assert!(state.recorded_sessions.len() >= 3);
    }

    #[test]
    fn trace_reader_passes_current_policy_reproduction_for_engine_trace() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let policy = PolicyEngine::new(config.candidate_policy.clone(), &Default::default());
        let record = replayable_trace_record(&config, &policy);
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(format!("{}\n", serde_json::to_string(&record).unwrap()));

        process_reader(
            &config,
            replay,
            "generated".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 1);
        assert_eq!(summary.reproduction_failures, 0);
        assert!(summary.reproduction_problems.is_empty());
    }

    #[test]
    fn committed_replay_corpus_reproduces_and_covers_key_cases() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let raw = include_str!("../../../testdata/policy-trace/v1-replay-corpus.jsonl");

        process_reader(
            &config,
            Cursor::new(raw),
            "corpus".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.lines_decision, 4);
        assert_eq!(summary.reproduction_passes, 4);
        assert_eq!(summary.reproduction_failures, 0);
        assert_eq!(summary.actual_bans, 1);
        assert!(summary.reproduction_problems.is_empty());

        let records = raw
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            records.iter().any(|record| {
                record["decision_output"]["disposition"]["disposition"] == "exempt"
            })
        );
        assert!(records.iter().any(|record| {
            record["decision_output"]["disposition"]["disposition"] == "not_bannable_yet"
        }));
        assert!(
            records
                .iter()
                .any(|record| { record["decision_output"]["disposition"]["disposition"] == "ban" })
        );
        assert!(
            records
                .iter()
                .any(|record| !record["prior_session"].is_null())
        );
        assert!(records.iter().any(|record| {
            record["guardrail_inputs"]["offence_history"]["offence_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        }));
        assert!(records.iter().any(|record| {
            record["policy_inputs"]["score"]["ban_threshold"]
                .as_f64()
                .is_some_and(|threshold| (threshold - 1.6).abs() > f64::EPSILON)
        }));
    }

    #[test]
    fn trace_reader_rejects_operator_logs() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(
            "{\"timestamp\":\"2026-03-12T10:00:00Z\",\"fields\":{\"message\":\"peer policy update\"}}\n",
        );

        let error = process_reader(
            &config,
            replay,
            "operator-log".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("expected ADR-0004 policy trace line"));
    }

    #[test]
    fn trace_reader_counts_dropped_record_notices() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(
            "{\"record_type\":\"dropped_records\",\"schema_version\":1,\"client_id\":1,\"dropped_count\":7}\n",
        );

        process_reader(
            &config,
            replay,
            "replay".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.lines_total, 1);
        assert_eq!(summary.lines_decision, 0);
        assert_eq!(summary.dropped_trace_records, 7);
        assert_eq!(summary.reproduction_failures, 1);
        assert!(summary.reproduction_problems[0].contains("dropped_records notice"));
    }

    #[test]
    fn trace_reader_reports_current_policy_reproduction_mismatches() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/policy-trace/v1-not-bannable-peer.json"
        ))
        .unwrap();
        fixture["policy_inputs"]["score"]["target_rate_bps"] = serde_json::json!(1);
        let replay = Cursor::new(format!("{}\n", serde_json::to_string(&fixture).unwrap()));

        process_reader(
            &config,
            replay,
            "mismatch".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 0);
        assert_eq!(summary.reproduction_failures, 1);
        assert!(
            summary
                .reproduction_problems
                .iter()
                .any(|problem| problem.contains("decision_output")
                    || problem.contains("evaluated_session"))
        );
        assert!(summary.reproduction_problems[0].contains("torrent_hash="));
    }

    #[test]
    fn current_policy_replay_deltas_are_reproduction_failures() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let policy = PolicyEngine::new(config.candidate_policy.clone(), &Default::default());
        let mut decision_record = replayable_trace_record(&config, &policy);
        decision_record.policy_trace_id = "decision-delta".to_string();
        decision_record.decision_output.is_bad_sample =
            !decision_record.decision_output.is_bad_sample;

        let mut score_record = replayable_trace_record(&config, &policy);
        score_record.policy_trace_id = "score-state-delta".to_string();
        score_record.evaluated_session.ban_score += 1.0;

        let mut guardrail_record = replayable_trace_record(&config, &policy);
        guardrail_record.policy_trace_id = "guardrail-delta".to_string();
        guardrail_record.guardrail_inputs.allowlisted_peer = true;

        let replay = Cursor::new(format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&decision_record).unwrap(),
            serde_json::to_string(&score_record).unwrap(),
            serde_json::to_string(&guardrail_record).unwrap()
        ));
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();

        process_reader(
            &config,
            replay,
            "deltas".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 0);
        assert_eq!(summary.reproduction_failures, 3);
        assert_eq!(summary.decision_deltas, 0);
        assert_eq!(summary.score_state_deltas, 0);
        assert_eq!(summary.guardrail_deltas, 0);
        assert!(
            summary
                .reproduction_problems
                .iter()
                .any(|problem| problem.contains("decision-delta"))
        );
        assert!(
            summary
                .reproduction_problems
                .iter()
                .any(|problem| problem.contains("score-state-delta"))
        );
        assert!(
            summary
                .reproduction_problems
                .iter()
                .any(|problem| problem.contains("guardrail-delta"))
        );
    }

    #[test]
    fn trace_reader_reproduces_non_default_trace_policy() {
        let mut trace_config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        trace_config.candidate_policy.score.target_rate_bps = 8_192;
        let trace_policy =
            PolicyEngine::new(trace_config.candidate_policy.clone(), &Default::default());
        let record = replayable_slow_trace_record(&trace_config, &trace_policy);
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(format!("{}\n", serde_json::to_string(&record).unwrap()));

        process_reader(
            &config,
            replay,
            "non-default".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 1);
        assert_eq!(summary.reproduction_failures, 0);
        assert_eq!(summary.decision_deltas, 0);
        assert_eq!(summary.score_state_deltas, 0);
    }

    #[test]
    fn candidate_overrides_report_deltas_without_reproduction_failure() {
        let trace_config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let trace_policy =
            PolicyEngine::new(trace_config.candidate_policy.clone(), &Default::default());
        let record = replayable_slow_trace_record(&trace_config, &trace_policy);
        let config = parse_args(vec![
            "--input".into(),
            "dummy".into(),
            "--ban-threshold".into(),
            "0.9".into(),
        ])
        .unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(format!("{}\n", serde_json::to_string(&record).unwrap()));

        process_reader(
            &config,
            replay,
            "candidate".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 1);
        assert_eq!(summary.reproduction_failures, 0);
        assert!(summary.decision_deltas >= 1 || summary.score_state_deltas >= 1);
    }

    #[test]
    fn candidate_replay_carries_state_across_records() {
        let mut trace_config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        trace_config.candidate_policy.score.ban_threshold = 10.0;
        let trace_policy =
            PolicyEngine::new(trace_config.candidate_policy.clone(), &Default::default());
        let first_observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first_record = replayable_slow_trace_record_at(
            &trace_config,
            &trace_policy,
            first_observed_at,
            None,
            OffenceHistory {
                offence_count: 0,
                last_ban_expires_at: None,
            },
            "candidate-carry-1",
        );
        let first_session = super::session_from_trace(&first_record.evaluated_session).unwrap();
        let second_record = replayable_slow_trace_record_at(
            &trace_config,
            &trace_policy,
            first_observed_at + Duration::from_secs(3_700),
            Some(&first_session),
            OffenceHistory {
                offence_count: 0,
                last_ban_expires_at: None,
            },
            "candidate-carry-2",
        );
        let config = parse_args(vec![
            "--input".into(),
            "dummy".into(),
            "--ban-threshold".into(),
            "0.9".into(),
        ])
        .unwrap();
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();
        let replay = Cursor::new(format!(
            "{}\n{}\n",
            serde_json::to_string(&first_record).unwrap(),
            serde_json::to_string(&second_record).unwrap()
        ));

        process_reader(
            &config,
            replay,
            "candidate-state".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.reproduction_passes, 2);
        assert_eq!(summary.reproduction_failures, 0);
        assert_eq!(summary.simulated_bans, 1);
        assert!(summary.decision_deltas >= 2);
        assert!(
            summary
                .decision_delta_reports
                .iter()
                .any(|report| report.contains("candidate-carry-2")
                    && report.contains("RebanCooldown"))
        );
        assert_eq!(state.candidate_sessions.len(), 1);
        assert_eq!(
            state
                .candidate_offences
                .values()
                .map(|history| history.offence_count)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn run_fails_when_reproduction_gate_fails() {
        let path = std::env::temp_dir().join(format!(
            "score-simulator-dropped-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "{\"record_type\":\"dropped_records\",\"schema_version\":1,\"client_id\":1,\"dropped_count\":1}\n",
        )
        .unwrap();

        let result = super::run(vec!["--input".into(), path.display().to_string()]);
        let _ = std::fs::remove_file(path);

        assert!(
            format!("{:#}", result.unwrap_err()).contains("current-policy reproduction failed")
        );
    }

    fn replayable_trace_record(
        config: &super::SimulatorConfig,
        policy: &PolicyEngine,
    ) -> PolicyTraceRecord {
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44));
        let torrent = TorrentScope {
            hash: "generated-trace".to_string(),
            name: "generated.iso".to_string(),
            tracker: Some("tracker.example".to_string()),
            category: Some("linux".to_string()),
            tags: vec!["public".to_string()],
            total_seeders: config.candidate_policy.min_total_seeders.max(1),
            in_scope: true,
        };
        let peer = PeerSnapshot {
            ip: peer_ip,
            port: 51413,
            progress: 0.97,
            up_rate_bps: 0,
        };
        let peer_context = PeerContext {
            torrent: torrent.clone(),
            peer: peer.clone(),
            first_seen_at: observed_at,
            observed_at,
            has_active_ban: false,
        };
        let evaluation = policy.evaluate_peer(&peer_context, None);
        let history = OffenceHistory {
            offence_count: 0,
            last_ban_expires_at: None,
        };
        let disposition = policy.decide_ban(&peer_context, &evaluation, &history);

        PolicyTraceRecord {
            record_type: PolicyTraceRecordType::PeerObservation,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            observed_at: trace_timestamp(observed_at),
            service_version: "0.1.0-test".to_string(),
            policy_trace_id: "generated-trace-1".to_string(),
            config_fingerprint: "generated-fingerprint".to_string(),
            torrent: TraceTorrent::from(&torrent),
            peer: TracePeer {
                ip: Some(peer.ip),
                port: peer.port,
                progress: peer.progress,
                up_rate_bps: peer.up_rate_bps,
            },
            prior_session: None,
            evaluated_session: (&evaluation.session).into(),
            policy_inputs: TracePolicyInputs::from(&config.candidate_policy),
            guardrail_inputs: TraceGuardrailInputs {
                exemption_reason: evaluation
                    .session
                    .last_exemption_reason
                    .as_ref()
                    .map(Into::into),
                allowlisted_peer: matches!(
                    evaluation.session.last_exemption_reason,
                    Some(brrpolice::types::ExemptionReason::AllowlistedPeer)
                ),
                active_ban: matches!(
                    evaluation.session.last_exemption_reason,
                    Some(brrpolice::types::ExemptionReason::AlreadyBanned)
                ),
                reban_cooldown_remaining_ms: None,
                offence_history: TraceOffenceHistory::from(&history),
            },
            decision_output: TraceDecisionOutput::from_evaluation_and_disposition(
                &evaluation,
                &disposition,
            ),
            simulator_hints: TraceSimulatorHints::from_evaluation(
                &evaluation,
                &config.candidate_policy,
            ),
        }
    }

    fn replayable_slow_trace_record(
        config: &super::SimulatorConfig,
        policy: &PolicyEngine,
    ) -> PolicyTraceRecord {
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        replayable_slow_trace_record_at(
            config,
            policy,
            observed_at,
            None,
            OffenceHistory {
                offence_count: 0,
                last_ban_expires_at: None,
            },
            "generated-slow-trace-1",
        )
    }

    fn replayable_slow_trace_record_at(
        config: &super::SimulatorConfig,
        policy: &PolicyEngine,
        observed_at: SystemTime,
        existing: Option<&PeerSessionState>,
        history: OffenceHistory,
        policy_trace_id: &str,
    ) -> PolicyTraceRecord {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45));
        let torrent = TorrentScope {
            hash: "generated-slow-trace".to_string(),
            name: "generated-slow.iso".to_string(),
            tracker: Some("tracker.example".to_string()),
            category: Some("linux".to_string()),
            tags: vec!["public".to_string()],
            total_seeders: config.candidate_policy.min_total_seeders.max(1),
            in_scope: true,
        };
        let peer = PeerSnapshot {
            ip: peer_ip,
            port: 51413,
            progress: 0.10,
            up_rate_bps: 0,
        };
        let peer_context = PeerContext {
            torrent: torrent.clone(),
            peer: peer.clone(),
            first_seen_at: existing
                .map(|session| session.first_seen_at)
                .unwrap_or(observed_at - Duration::from_secs(180)),
            observed_at,
            has_active_ban: false,
        };
        let evaluation = policy.evaluate_peer(&peer_context, existing);
        let disposition = policy.decide_ban(&peer_context, &evaluation, &history);

        PolicyTraceRecord {
            record_type: PolicyTraceRecordType::PeerObservation,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            observed_at: trace_timestamp(observed_at),
            service_version: "0.1.0-test".to_string(),
            policy_trace_id: policy_trace_id.to_string(),
            config_fingerprint: "generated-fingerprint".to_string(),
            torrent: TraceTorrent::from(&torrent),
            peer: TracePeer {
                ip: Some(peer.ip),
                port: peer.port,
                progress: peer.progress,
                up_rate_bps: peer.up_rate_bps,
            },
            prior_session: existing.map(Into::into),
            evaluated_session: (&evaluation.session).into(),
            policy_inputs: TracePolicyInputs::from(&config.candidate_policy),
            guardrail_inputs: TraceGuardrailInputs {
                exemption_reason: evaluation
                    .session
                    .last_exemption_reason
                    .as_ref()
                    .map(Into::into),
                allowlisted_peer: matches!(
                    evaluation.session.last_exemption_reason,
                    Some(brrpolice::types::ExemptionReason::AllowlistedPeer)
                ),
                active_ban: matches!(
                    evaluation.session.last_exemption_reason,
                    Some(brrpolice::types::ExemptionReason::AlreadyBanned)
                ),
                reban_cooldown_remaining_ms: None,
                offence_history: TraceOffenceHistory::from(&history),
            },
            decision_output: TraceDecisionOutput::from_evaluation_and_disposition(
                &evaluation,
                &disposition,
            ),
            simulator_hints: TraceSimulatorHints::from_evaluation(
                &evaluation,
                &config.candidate_policy,
            ),
        }
    }

    fn fixture_line(raw: &str) -> String {
        serde_json::to_string(&serde_json::from_str::<serde_json::Value>(raw).unwrap()).unwrap()
    }
}
