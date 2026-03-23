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
use serde::{Deserialize, Serialize};
use serde_json::Value;

use brrpolice::{
    config::{FiltersConfig, PolicyConfig},
    policy::{PolicyEngine, ReplayScoreModel},
    types::{
        BanDisposition, OffenceHistory, OffenceIdentity, PeerContext, PeerObservationId,
        PeerSessionState, PeerSnapshot, TorrentScope,
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

#[derive(Debug, Clone)]
struct SimulatorConfig {
    inputs: Vec<PathBuf>,
    policy: PolicyConfig,
    peer_ip: Option<IpAddr>,
    hydrate_logged_score_state: bool,
    compare_adr_0006: bool,
    corpus_name: Option<String>,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        let policy = PolicyConfig::default();
        Self {
            inputs: Vec::new(),
            policy,
            peer_ip: None,
            hydrate_logged_score_state: true,
            compare_adr_0006: false,
            corpus_name: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct LogFields {
    message: String,
    peer_ip: String,
    peer_port: u16,
    torrent_hash: String,
    torrent_name: Option<String>,
    torrent_tracker: Option<String>,
    torrent_total_size_bytes: Option<u64>,
    observed_at: String,
    progress_delta: f64,
    average_upload_rate_bps: u64,
    observed_duration_seconds: Option<u64>,
    bad_time_seconds: Option<u64>,
    ban_score: Option<f64>,
    ban_score_above_threshold_seconds: Option<u64>,
    sample_score_risk: Option<f64>,
    effective_sample_score_risk: Option<f64>,
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
    peers_seen: u64,
    simulated_bans: u64,
    actual_bans: u64,
    simulated_bans_with_churn: u64,
    churn_samples: u64,
    churn_max_amplifier: f64,
    churn_max_reconnect_count: u32,
}

#[derive(Default)]
struct ReplayState {
    sessions: HashMap<SessionKey, PeerSessionState>,
    offences: HashMap<OffenceKey, OffenceHistory>,
    active_bans: HashMap<ActiveBanKey, SystemTime>,
    peer_reports: HashMap<OffenceKey, PeerReport>,
}

#[derive(Debug, Clone)]
struct PeerReport {
    torrent_hash: String,
    torrent_name: Option<String>,
    torrent_tracker: Option<String>,
    peer_ip: IpAddr,
    last_peer_port: u16,
    first_observed_at: SystemTime,
    last_observed_at: SystemTime,
    simulated_decision: &'static str,
    simulated_ban_events: u32,
    actual_ban_events: u32,
    rate_reference_name: &'static str,
    rate_reference_bps: u64,
    rate_reference_target_bps: u64,
    rate_reference_ratio: f64,
    rate_reference_band: &'static str,
    torrent_total_size_bytes: u64,
    progress_delta: f64,
    progress_delta_bytes: u64,
    required_progress_delta: f64,
    required_progress_bytes: u64,
    progress_deficit_bytes: u64,
    final_score: f64,
    sample_score_risk: f64,
    effective_sample_score_risk: f64,
    churn_reconnect_count: u32,
    churn_amplifier: f64,
    sample_count: u32,
}

#[derive(Debug, Clone, Serialize)]
struct PeerResultRow {
    record_type: &'static str,
    torrent_hash: String,
    torrent_name: Option<String>,
    torrent_tracker: Option<String>,
    peer_ip: String,
    peer_behavior_key: String,
    last_peer_port: u16,
    first_observed_at: String,
    last_observed_at: String,
    simulated_decision: String,
    simulated_ban_events: u32,
    actual_ban_events: u32,
    rate_reference_name: &'static str,
    rate_reference_bps: u64,
    rate_reference_target_bps: u64,
    rate_reference_ratio: f64,
    rate_reference_band: &'static str,
    torrent_total_size_bytes: u64,
    progress_delta: f64,
    progress_delta_bytes: u64,
    required_progress_delta: f64,
    required_progress_bytes: u64,
    progress_deficit_bytes: u64,
    final_score: f64,
    sample_score_risk: f64,
    effective_sample_score_risk: f64,
    churn_reconnect_count: u32,
    churn_amplifier: f64,
    sample_count: u32,
}

#[derive(Debug, Clone, Copy)]
struct CandidateProfile {
    model: ReplayScoreModel,
}

impl CandidateProfile {
    fn key(self) -> &'static str {
        self.model.key()
    }

    fn description(self) -> &'static str {
        self.model.description()
    }
}

#[derive(Debug, Clone, Serialize)]
struct CandidateSummaryRow {
    record_type: &'static str,
    corpus_name: String,
    candidate_key: &'static str,
    candidate_description: &'static str,
    lines_total: u64,
    decision_lines: u64,
    peer_behaviors_seen: usize,
    simulated_bans: u64,
    actual_bans: u64,
    simulated_bans_with_churn: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CandidateBandSummaryRow {
    record_type: &'static str,
    corpus_name: String,
    candidate_key: &'static str,
    rate_reference_band: &'static str,
    peer_behaviors: usize,
    simulated_bans: usize,
    actual_bans: usize,
    decision_changes_vs_baseline: usize,
    bans_lost_vs_baseline: usize,
    bans_gained_vs_baseline: usize,
}

#[derive(Debug, Clone, Serialize)]
struct CandidateDeltaRow {
    record_type: &'static str,
    corpus_name: String,
    baseline_candidate_key: &'static str,
    candidate_key: &'static str,
    candidate_description: &'static str,
    torrent_hash: String,
    torrent_name: Option<String>,
    torrent_tracker: Option<String>,
    peer_ip: String,
    peer_behavior_key: String,
    first_observed_at: String,
    last_observed_at: String,
    rate_reference_band: &'static str,
    torrent_total_size_bytes: u64,
    baseline_decision: String,
    candidate_decision: String,
    decision_changed: bool,
    baseline_ever_banned: bool,
    candidate_ever_banned: bool,
    ban_changed: bool,
    baseline_ban_events: u32,
    candidate_ban_events: u32,
    actual_ban_events: u32,
    baseline_rate_reference_ratio: f64,
    candidate_rate_reference_ratio: f64,
    baseline_progress_delta: f64,
    candidate_progress_delta: f64,
    baseline_required_progress_delta: f64,
    candidate_required_progress_delta: f64,
    baseline_progress_deficit_bytes: u64,
    candidate_progress_deficit_bytes: u64,
    baseline_final_score: f64,
    candidate_final_score: f64,
}

struct CandidateRun {
    profile: CandidateProfile,
    summary: Summary,
    state: ReplayState,
}

pub fn run(args: Vec<String>) -> Result<()> {
    let config = parse_args(args)?;
    if config.compare_adr_0006 {
        let runs = run_candidate_set(&config, &adr_0006_candidate_profiles())?;
        print_comparison(&config, &runs);
    } else {
        let run = run_candidate(
            &config,
            CandidateProfile {
                model: ReplayScoreModel::CurrentComposite,
            },
        )?;
        print_summary(&config, &run.summary, &run.state);
    }
    Ok(())
}

fn run_candidate_set(
    config: &SimulatorConfig,
    profiles: &[CandidateProfile],
) -> Result<Vec<CandidateRun>> {
    profiles
        .iter()
        .copied()
        .map(|profile| run_candidate(config, profile))
        .collect()
}

fn run_candidate(config: &SimulatorConfig, profile: CandidateProfile) -> Result<CandidateRun> {
    let policy = PolicyEngine::new(config.policy.clone(), &FiltersConfig::default());
    let mut state = ReplayState::default();
    let mut summary = Summary::default();

    for input in &config.inputs {
        let file = File::open(input)
            .with_context(|| format!("opening input file `{}`", input.display()))?;
        let reader = BufReader::new(file);
        process_reader(
            &policy,
            profile.model,
            config,
            reader,
            input.display().to_string(),
            &mut state,
            &mut summary,
        )?;
    }

    Ok(CandidateRun {
        profile,
        summary,
        state,
    })
}

fn process_reader<R: BufRead>(
    policy: &PolicyEngine,
    model: ReplayScoreModel,
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

        let Some(fields) = parse_log_fields(&line) else {
            continue;
        };
        process_fields(policy, model, config, fields, state, summary)?;
    }

    Ok(())
}

fn process_fields(
    policy: &PolicyEngine,
    model: ReplayScoreModel,
    config: &SimulatorConfig,
    fields: LogFields,
    state: &mut ReplayState,
    summary: &mut Summary,
) -> Result<()> {
    if fields.message != "peer policy update"
        && fields.message != "peer not bannable yet decision"
        && fields.message != "peer exemption decision"
        && fields.message != "peer ban applied"
        && fields.message != "peer reban cooldown decision"
    {
        return Ok(());
    }
    summary.lines_decision += 1;

    let peer_ip: IpAddr = match fields.peer_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(()),
    };
    if let Some(filter_ip) = config.peer_ip
        && peer_ip != filter_ip
    {
        return Ok(());
    }

    let observed_at =
        parse_rfc3339(&fields.observed_at).with_context(|| "parsing observed_at timestamp")?;
    state
        .active_bans
        .retain(|_, expires_at| *expires_at > observed_at);

    let observation_id = PeerObservationId {
        torrent_hash: fields.torrent_hash.clone(),
        peer_ip,
        peer_port: fields.peer_port,
    };
    let session_key = SessionKey::from_observation_id(&observation_id);
    let existing = state.sessions.get(&session_key).cloned();
    let carryover = if existing.is_none() {
        latest_session_for_torrent_ip(
            &state.sessions,
            &fields.torrent_hash,
            peer_ip,
            observed_at,
            config.policy.decay_window,
        )
    } else {
        None
    };
    if existing.is_none() && carryover.is_none() {
        summary.peers_seen += 1;
    }

    let baseline_progress = existing
        .as_ref()
        .or(carryover.as_ref())
        .map(|session| session.baseline_progress)
        .unwrap_or(0.0);
    let progress = (baseline_progress + fields.progress_delta).clamp(0.0, 1.0);

    let first_seen_at = fields
        .observed_duration_seconds
        .and_then(|seconds| observed_at.checked_sub(Duration::from_secs(seconds)))
        .or_else(|| {
            existing
                .as_ref()
                .or(carryover.as_ref())
                .map(|session| session.first_seen_at)
        })
        .unwrap_or(observed_at);

    let has_active_ban = state.active_bans.contains_key(&ActiveBanKey {
        torrent_hash: fields.torrent_hash.clone(),
        peer_ip,
        peer_port: fields.peer_port,
    });

    let peer_context = PeerContext {
        torrent: TorrentScope {
            hash: fields.torrent_hash.clone(),
            name: fields
                .torrent_name
                .clone()
                .unwrap_or_else(|| fields.torrent_hash.clone()),
            tracker: fields.torrent_tracker.clone(),
            total_size_bytes: fields.torrent_total_size_bytes.unwrap_or(0),
            category: None,
            tags: Vec::new(),
            total_seeders: config.policy.min_total_seeders.max(1),
            in_scope: true,
        },
        peer: PeerSnapshot {
            ip: peer_ip,
            port: fields.peer_port,
            progress,
            up_rate_bps: fields.average_upload_rate_bps,
        },
        first_seen_at,
        observed_at,
        has_active_ban,
    };

    let mut evaluation = policy.evaluate_peer_with_model(
        &peer_context,
        existing.as_ref().or(carryover.as_ref()),
        model,
    );
    if should_hydrate_logged_score_state(config, model) {
        hydrate_evaluation_from_log_fields(&mut evaluation, &fields, config);
    } else if let Some(seconds) = fields.observed_duration_seconds {
        evaluation.session.observed_duration = Duration::from_secs(seconds);
        let exemption_free = evaluation.session.last_exemption_reason.is_none();
        evaluation.is_bannable = exemption_free
            && evaluation.session.observed_duration >= config.policy.score.min_observation_duration
            && evaluation.session.ban_score_above_threshold_duration
                >= config.policy.score.sustain_duration;
    }
    let history = state
        .offences
        .get(&OffenceKey::from_offence_identity(
            &evaluation.session.offence_identity,
        ))
        .cloned()
        .unwrap_or(OffenceHistory {
            offence_count: 0,
            last_ban_expires_at: None,
        });
    let insights = policy.evaluation_insights(&peer_context, &evaluation);
    let report_key = OffenceKey::from_offence_identity(&evaluation.session.offence_identity);
    let mut session_to_store = evaluation.session.clone();
    if evaluation.session.churn_amplifier > 0.0 {
        summary.churn_samples += 1;
        summary.churn_max_amplifier = summary
            .churn_max_amplifier
            .max(evaluation.session.churn_amplifier);
    }
    summary.churn_max_reconnect_count = summary
        .churn_max_reconnect_count
        .max(evaluation.session.churn_reconnect_count);
    let disposition = policy.decide_ban(&peer_context, &evaluation, &history);
    let simulated_decision = match disposition {
        BanDisposition::Ban(decision) => {
            summary.simulated_bans += 1;
            if evaluation.session.churn_amplifier > 0.0 {
                summary.simulated_bans_with_churn += 1;
            }
            let expires_at = observed_at + decision.ttl;
            state.active_bans.insert(
                ActiveBanKey {
                    torrent_hash: fields.torrent_hash.clone(),
                    peer_ip,
                    peer_port: fields.peer_port,
                },
                expires_at,
            );
            state.offences.insert(
                OffenceKey::from_offence_identity(&evaluation.session.offence_identity),
                OffenceHistory {
                    offence_count: decision.offence_number,
                    last_ban_expires_at: Some(expires_at),
                },
            );
            session_to_store = policy.record_ban_decision(&session_to_store, observed_at);
            "ban"
        }
        BanDisposition::Exempt(_) => "exempt",
        BanDisposition::NotBannableYet { .. } => "not_bannable",
        BanDisposition::RebanCooldown { .. } => "reban_cooldown",
        BanDisposition::DuplicateSuppressed => "duplicate_suppressed",
    };

    state.sessions.insert(session_key, session_to_store);
    let report = state
        .peer_reports
        .entry(report_key)
        .or_insert_with(|| PeerReport {
            torrent_hash: fields.torrent_hash.clone(),
            torrent_name: fields.torrent_name.clone(),
            torrent_tracker: fields.torrent_tracker.clone(),
            peer_ip,
            last_peer_port: fields.peer_port,
            first_observed_at: observed_at,
            last_observed_at: observed_at,
            simulated_decision,
            simulated_ban_events: 0,
            actual_ban_events: 0,
            rate_reference_name: insights.rate_reference_name,
            rate_reference_bps: insights.rate_reference_bps,
            rate_reference_target_bps: insights.rate_reference_target_bps,
            rate_reference_ratio: insights.rate_reference_ratio,
            rate_reference_band: insights.rate_reference_band,
            torrent_total_size_bytes: insights.torrent_total_size_bytes,
            progress_delta: evaluation.progress_delta,
            progress_delta_bytes: insights.progress_delta_bytes,
            required_progress_delta: insights.required_progress_delta,
            required_progress_bytes: insights.required_progress_bytes,
            progress_deficit_bytes: insights.progress_deficit_bytes,
            final_score: evaluation.session.ban_score,
            sample_score_risk: evaluation.sample_score_risk,
            effective_sample_score_risk: evaluation.effective_sample_score_risk,
            churn_reconnect_count: evaluation.session.churn_reconnect_count,
            churn_amplifier: evaluation.session.churn_amplifier,
            sample_count: evaluation.session.sample_count,
        });
    report.torrent_name = fields.torrent_name.clone().or(report.torrent_name.clone());
    report.torrent_tracker = fields
        .torrent_tracker
        .clone()
        .or(report.torrent_tracker.clone());
    report.last_peer_port = fields.peer_port;
    report.first_observed_at = report.first_observed_at.min(observed_at);
    report.last_observed_at = report.last_observed_at.max(observed_at);
    report.simulated_decision = simulated_decision;
    if simulated_decision == "ban" {
        report.simulated_ban_events += 1;
    }
    if fields.message == "peer ban applied" {
        summary.actual_bans += 1;
        report.actual_ban_events += 1;
    }
    report.rate_reference_name = insights.rate_reference_name;
    report.rate_reference_bps = insights.rate_reference_bps;
    report.rate_reference_target_bps = insights.rate_reference_target_bps;
    report.rate_reference_ratio = insights.rate_reference_ratio;
    report.rate_reference_band = insights.rate_reference_band;
    report.torrent_total_size_bytes = insights.torrent_total_size_bytes;
    report.progress_delta = evaluation.progress_delta;
    report.progress_delta_bytes = insights.progress_delta_bytes;
    report.required_progress_delta = insights.required_progress_delta;
    report.required_progress_bytes = insights.required_progress_bytes;
    report.progress_deficit_bytes = insights.progress_deficit_bytes;
    report.final_score = evaluation.session.ban_score;
    report.sample_score_risk = evaluation.sample_score_risk;
    report.effective_sample_score_risk = evaluation.effective_sample_score_risk;
    report.churn_reconnect_count = evaluation.session.churn_reconnect_count;
    report.churn_amplifier = evaluation.session.churn_amplifier;
    report.sample_count = evaluation.session.sample_count;
    Ok(())
}

fn latest_session_for_torrent_ip(
    sessions: &HashMap<SessionKey, PeerSessionState>,
    torrent_hash: &str,
    peer_ip: IpAddr,
    observed_at: SystemTime,
    decay_window: Duration,
) -> Option<PeerSessionState> {
    sessions
        .values()
        .filter(|session| {
            session.observation_id.torrent_hash == torrent_hash
                && session.observation_id.peer_ip == peer_ip
                && observed_at >= session.last_seen_at
                && observed_at
                    .duration_since(session.last_seen_at)
                    .unwrap_or_default()
                    <= decay_window
        })
        .max_by_key(|session| session.last_seen_at)
        .cloned()
}

fn should_hydrate_logged_score_state(config: &SimulatorConfig, model: ReplayScoreModel) -> bool {
    config.hydrate_logged_score_state && model == ReplayScoreModel::CurrentComposite
}

fn parse_log_fields(line: &str) -> Option<LogFields> {
    let root: Value = serde_json::from_str(line).ok()?;

    if let Some(inner_message) = root.get("_msg").and_then(Value::as_str) {
        let inner: Value = serde_json::from_str(inner_message).ok()?;
        return extract_log_fields(
            inner.get("fields").and_then(Value::as_object),
            inner
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string),
        );
    }

    extract_log_fields(
        root.get("fields").and_then(Value::as_object),
        root.get("timestamp")
            .and_then(Value::as_str)
            .map(str::to_string),
    )
}

fn extract_log_fields(
    fields: Option<&serde_json::Map<String, Value>>,
    fallback_timestamp: Option<String>,
) -> Option<LogFields> {
    let fields = fields?;
    let message = fields.get("message")?.as_str()?.to_string();
    let peer_ip = fields.get("peer_ip")?.as_str()?.to_string();
    let peer_port = u16::try_from(fields.get("peer_port")?.as_u64()?).ok()?;
    let torrent_hash = fields.get("torrent_hash")?.as_str()?.to_string();
    let torrent_name = fields
        .get("torrent_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let torrent_tracker = fields
        .get("torrent_tracker")
        .and_then(Value::as_str)
        .map(str::to_string);
    let torrent_total_size_bytes = fields
        .get("torrent_total_size_bytes")
        .and_then(Value::as_u64)
        .or_else(|| fields.get("torrent_size_bytes").and_then(Value::as_u64));
    let observed_at = fields
        .get("observed_at")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(fallback_timestamp)?;
    let progress_delta = fields.get("progress_delta")?.as_f64()?;
    let average_upload_rate_bps = fields.get("average_upload_rate_bps")?.as_u64()?;
    let observed_duration_seconds = fields
        .get("observed_duration_seconds")
        .and_then(Value::as_u64);
    let bad_time_seconds = fields.get("bad_time_seconds").and_then(Value::as_u64);
    let ban_score = fields.get("ban_score").and_then(Value::as_f64);
    let ban_score_above_threshold_seconds = fields
        .get("ban_score_above_threshold_seconds")
        .and_then(Value::as_u64);
    let sample_score_risk = fields.get("sample_score_risk").and_then(Value::as_f64);
    let effective_sample_score_risk = fields
        .get("effective_sample_score_risk")
        .and_then(Value::as_f64);

    Some(LogFields {
        message,
        peer_ip,
        peer_port,
        torrent_hash,
        torrent_name,
        torrent_tracker,
        torrent_total_size_bytes,
        observed_at,
        progress_delta,
        average_upload_rate_bps,
        observed_duration_seconds,
        bad_time_seconds,
        ban_score,
        ban_score_above_threshold_seconds,
        sample_score_risk,
        effective_sample_score_risk,
    })
}

fn hydrate_evaluation_from_log_fields(
    evaluation: &mut brrpolice::types::PeerEvaluation,
    fields: &LogFields,
    config: &SimulatorConfig,
) {
    evaluation.progress_delta = fields.progress_delta;
    evaluation.session.rolling_avg_up_rate_bps = fields.average_upload_rate_bps;
    if let Some(seconds) = fields.observed_duration_seconds {
        evaluation.session.observed_duration = Duration::from_secs(seconds);
    }
    if let Some(seconds) = fields.bad_time_seconds {
        evaluation.session.bad_duration = Duration::from_secs(seconds);
    }
    if let Some(score) = fields.ban_score {
        evaluation.session.ban_score = score;
    }
    if let Some(seconds) = fields.ban_score_above_threshold_seconds {
        evaluation.session.ban_score_above_threshold_duration = Duration::from_secs(seconds);
    }
    if let Some(risk) = fields.sample_score_risk {
        evaluation.sample_score_risk = risk;
    }
    if let Some(risk) = fields.effective_sample_score_risk {
        evaluation.effective_sample_score_risk = risk;
    }

    let exemption_free = evaluation.session.last_exemption_reason.is_none();
    evaluation.is_bannable = exemption_free
        && evaluation.session.observed_duration >= config.policy.score.min_observation_duration
        && evaluation.session.ban_score_above_threshold_duration
            >= config.policy.score.sustain_duration;
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
        config.policy.score.target_rate_bps,
        config.policy.score.required_progress_delta,
        config.policy.score.progress_rate_scale_start,
        config.policy.score.progress_rate_scale_end,
        config.policy.score.progress_rate_min_scale,
        config.policy.score.weight_rate,
        config.policy.score.weight_progress,
        config.policy.score.rate_risk_floor,
        config.policy.score.ban_threshold,
        config.policy.score.clear_threshold,
        config.policy.score.sustain_duration.as_secs(),
        config.policy.score.decay_per_second,
        config.policy.score.min_observation_duration.as_secs(),
        config.policy.reban_cooldown.as_secs(),
        config.policy.score.churn.enabled,
        config.policy.score.churn.reconnect_window.as_secs(),
        config.policy.score.churn.min_reconnects,
        config.policy.score.churn.max_amplifier,
        config.policy.score.churn.decay_per_second,
    );
    if let Some(peer_ip) = config.peer_ip {
        println!("peer_filter_ip={peer_ip}");
    }
    println!(
        "lines_total={} decision_lines={} peers_seen={} simulated_bans={} actual_bans={} simulated_bans_with_churn={} churn_samples={} churn_max_amplifier={:.4} churn_max_reconnect_count={}",
        summary.lines_total,
        summary.lines_decision,
        summary.peers_seen,
        summary.simulated_bans,
        summary.actual_bans,
        summary.simulated_bans_with_churn,
        summary.churn_samples,
        summary.churn_max_amplifier,
        summary.churn_max_reconnect_count
    );
    for row in build_peer_result_rows(state) {
        println!(
            "{}",
            serde_json::to_string(&row).expect("peer result row should serialize")
        );
    }
}

fn build_peer_result_rows(state: &ReplayState) -> Vec<PeerResultRow> {
    let mut rows = state
        .peer_reports
        .values()
        .map(|report| PeerResultRow {
            record_type: "peer_result",
            torrent_hash: report.torrent_hash.clone(),
            torrent_name: report.torrent_name.clone(),
            torrent_tracker: report.torrent_tracker.clone(),
            peer_ip: report.peer_ip.to_string(),
            peer_behavior_key: format!("{}+{}", report.torrent_hash, report.peer_ip),
            last_peer_port: report.last_peer_port,
            first_observed_at: humantime::format_rfc3339_millis(report.first_observed_at)
                .to_string(),
            last_observed_at: humantime::format_rfc3339_millis(report.last_observed_at).to_string(),
            simulated_decision: report.simulated_decision.to_string(),
            simulated_ban_events: report.simulated_ban_events,
            actual_ban_events: report.actual_ban_events,
            rate_reference_name: report.rate_reference_name,
            rate_reference_bps: report.rate_reference_bps,
            rate_reference_target_bps: report.rate_reference_target_bps,
            rate_reference_ratio: report.rate_reference_ratio,
            rate_reference_band: report.rate_reference_band,
            torrent_total_size_bytes: report.torrent_total_size_bytes,
            progress_delta: report.progress_delta,
            progress_delta_bytes: report.progress_delta_bytes,
            required_progress_delta: report.required_progress_delta,
            required_progress_bytes: report.required_progress_bytes,
            progress_deficit_bytes: report.progress_deficit_bytes,
            final_score: report.final_score,
            sample_score_risk: report.sample_score_risk,
            effective_sample_score_risk: report.effective_sample_score_risk,
            churn_reconnect_count: report.churn_reconnect_count,
            churn_amplifier: report.churn_amplifier,
            sample_count: report.sample_count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.torrent_hash
            .cmp(&right.torrent_hash)
            .then(left.peer_ip.cmp(&right.peer_ip))
    });
    rows
}

fn adr_0006_candidate_profiles() -> Vec<CandidateProfile> {
    vec![
        CandidateProfile {
            model: ReplayScoreModel::CurrentComposite,
        },
        CandidateProfile {
            model: ReplayScoreModel::RatePrimaryAmplified,
        },
        CandidateProfile {
            model: ReplayScoreModel::RatePrimaryResidencyShoulder,
        },
        CandidateProfile {
            model: ReplayScoreModel::RatePrimaryGatedResidencyShoulder,
        },
        CandidateProfile {
            model: ReplayScoreModel::MarginalBandBounded,
        },
    ]
}

fn print_comparison(config: &SimulatorConfig, runs: &[CandidateRun]) {
    let corpus_name = config.corpus_name.clone().unwrap_or_else(|| {
        config
            .inputs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(",")
    });
    let Some(baseline) = runs
        .iter()
        .find(|run| run.profile.model == ReplayScoreModel::CurrentComposite)
    else {
        return;
    };

    println!("adr-0006 comparison");
    println!("corpus={corpus_name}");
    for run in runs {
        let row = CandidateSummaryRow {
            record_type: "candidate_summary",
            corpus_name: corpus_name.clone(),
            candidate_key: run.profile.key(),
            candidate_description: run.profile.description(),
            lines_total: run.summary.lines_total,
            decision_lines: run.summary.lines_decision,
            peer_behaviors_seen: run.state.peer_reports.len(),
            simulated_bans: run.summary.simulated_bans,
            actual_bans: run.summary.actual_bans,
            simulated_bans_with_churn: run.summary.simulated_bans_with_churn,
        };
        println!(
            "{}",
            serde_json::to_string(&row).expect("candidate summary row should serialize")
        );
    }

    for run in runs
        .iter()
        .filter(|run| run.profile.key() != baseline.profile.key())
    {
        for row in build_candidate_band_summary_rows(&corpus_name, baseline, run) {
            println!(
                "{}",
                serde_json::to_string(&row).expect("candidate band summary row should serialize")
            );
        }
        for row in build_candidate_delta_rows(&corpus_name, baseline, run) {
            println!(
                "{}",
                serde_json::to_string(&row).expect("candidate delta row should serialize")
            );
        }
    }
}

fn build_candidate_band_summary_rows(
    corpus_name: &str,
    baseline: &CandidateRun,
    candidate: &CandidateRun,
) -> Vec<CandidateBandSummaryRow> {
    const BANDS: [&str; 5] = [
        "clearly_bad",
        "low_side_gray",
        "marginal",
        "high_side_gray",
        "clearly_healthy",
    ];

    BANDS
        .iter()
        .map(|band| {
            let baseline_reports = baseline
                .state
                .peer_reports
                .iter()
                .filter(|(_, report)| report.rate_reference_band == *band)
                .collect::<Vec<_>>();
            let candidate_reports = candidate
                .state
                .peer_reports
                .iter()
                .filter(|(_, report)| report.rate_reference_band == *band)
                .collect::<Vec<_>>();
            let peer_behaviors = candidate_reports.len();
            let simulated_bans = candidate_reports
                .iter()
                .filter(|(_, report)| report.simulated_ban_events > 0)
                .count();
            let actual_bans = candidate_reports
                .iter()
                .filter(|(_, report)| report.actual_ban_events > 0)
                .count();
            let decision_changes_vs_baseline = candidate_reports
                .iter()
                .filter(|(key, report)| {
                    baseline
                        .state
                        .peer_reports
                        .get(*key)
                        .map(|baseline_report| {
                            baseline_report.simulated_decision != report.simulated_decision
                        })
                        .unwrap_or(false)
                })
                .count();
            let bans_lost_vs_baseline = baseline_reports
                .iter()
                .filter(|(key, baseline_report)| {
                    baseline_report.simulated_ban_events > 0
                        && candidate
                            .state
                            .peer_reports
                            .get(*key)
                            .map(|candidate_report| candidate_report.simulated_ban_events == 0)
                            .unwrap_or(false)
                })
                .count();
            let bans_gained_vs_baseline = candidate_reports
                .iter()
                .filter(|(key, candidate_report)| {
                    candidate_report.simulated_ban_events > 0
                        && baseline
                            .state
                            .peer_reports
                            .get(*key)
                            .map(|baseline_report| baseline_report.simulated_ban_events == 0)
                            .unwrap_or(true)
                })
                .count();

            CandidateBandSummaryRow {
                record_type: "candidate_band_summary",
                corpus_name: corpus_name.to_string(),
                candidate_key: candidate.profile.key(),
                rate_reference_band: band,
                peer_behaviors,
                simulated_bans,
                actual_bans,
                decision_changes_vs_baseline,
                bans_lost_vs_baseline,
                bans_gained_vs_baseline,
            }
        })
        .collect()
}

fn build_candidate_delta_rows(
    corpus_name: &str,
    baseline: &CandidateRun,
    candidate: &CandidateRun,
) -> Vec<CandidateDeltaRow> {
    let mut rows = candidate
        .state
        .peer_reports
        .iter()
        .filter_map(|(key, candidate_report)| {
            let baseline_report = baseline.state.peer_reports.get(key)?;
            Some(CandidateDeltaRow {
                record_type: "candidate_delta",
                corpus_name: corpus_name.to_string(),
                baseline_candidate_key: baseline.profile.key(),
                candidate_key: candidate.profile.key(),
                candidate_description: candidate.profile.description(),
                torrent_hash: candidate_report.torrent_hash.clone(),
                torrent_name: candidate_report.torrent_name.clone(),
                torrent_tracker: candidate_report.torrent_tracker.clone(),
                peer_ip: candidate_report.peer_ip.to_string(),
                peer_behavior_key: format!(
                    "{}+{}",
                    candidate_report.torrent_hash, candidate_report.peer_ip
                ),
                first_observed_at: humantime::format_rfc3339_millis(
                    candidate_report.first_observed_at,
                )
                .to_string(),
                last_observed_at: humantime::format_rfc3339_millis(
                    candidate_report.last_observed_at,
                )
                .to_string(),
                rate_reference_band: candidate_report.rate_reference_band,
                torrent_total_size_bytes: candidate_report.torrent_total_size_bytes,
                baseline_decision: baseline_report.simulated_decision.to_string(),
                candidate_decision: candidate_report.simulated_decision.to_string(),
                decision_changed: baseline_report.simulated_decision
                    != candidate_report.simulated_decision,
                baseline_ever_banned: baseline_report.simulated_ban_events > 0,
                candidate_ever_banned: candidate_report.simulated_ban_events > 0,
                ban_changed: (baseline_report.simulated_ban_events > 0)
                    != (candidate_report.simulated_ban_events > 0),
                baseline_ban_events: baseline_report.simulated_ban_events,
                candidate_ban_events: candidate_report.simulated_ban_events,
                actual_ban_events: candidate_report.actual_ban_events,
                baseline_rate_reference_ratio: baseline_report.rate_reference_ratio,
                candidate_rate_reference_ratio: candidate_report.rate_reference_ratio,
                baseline_progress_delta: baseline_report.progress_delta,
                candidate_progress_delta: candidate_report.progress_delta,
                baseline_required_progress_delta: baseline_report.required_progress_delta,
                candidate_required_progress_delta: candidate_report.required_progress_delta,
                baseline_progress_deficit_bytes: baseline_report.progress_deficit_bytes,
                candidate_progress_deficit_bytes: candidate_report.progress_deficit_bytes,
                baseline_final_score: baseline_report.final_score,
                candidate_final_score: candidate_report.final_score,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .ban_changed
            .cmp(&left.ban_changed)
            .then(right.decision_changed.cmp(&left.decision_changed))
            .then(left.rate_reference_band.cmp(right.rate_reference_band))
            .then(left.torrent_hash.cmp(&right.torrent_hash))
            .then(left.peer_ip.cmp(&right.peer_ip))
    });
    rows
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
                config.policy.score.target_rate_bps =
                    parse_u64_arg(&mut iter, "--target-rate-bps")?;
            }
            "--required-progress-delta" => {
                config.policy.score.required_progress_delta =
                    parse_f64_arg(&mut iter, "--required-progress-delta")?;
            }
            "--progress-rate-scale-start" => {
                config.policy.score.progress_rate_scale_start =
                    parse_f64_arg(&mut iter, "--progress-rate-scale-start")?;
            }
            "--progress-rate-scale-end" => {
                config.policy.score.progress_rate_scale_end =
                    parse_f64_arg(&mut iter, "--progress-rate-scale-end")?;
            }
            "--progress-rate-min-scale" => {
                config.policy.score.progress_rate_min_scale =
                    parse_f64_arg(&mut iter, "--progress-rate-min-scale")?;
            }
            "--weight-rate" => {
                config.policy.score.weight_rate = parse_f64_arg(&mut iter, "--weight-rate")?;
            }
            "--weight-progress" => {
                config.policy.score.weight_progress =
                    parse_f64_arg(&mut iter, "--weight-progress")?;
            }
            "--rate-risk-floor" => {
                config.policy.score.rate_risk_floor =
                    parse_f64_arg(&mut iter, "--rate-risk-floor")?;
            }
            "--ban-threshold" => {
                config.policy.score.ban_threshold = parse_f64_arg(&mut iter, "--ban-threshold")?;
            }
            "--clear-threshold" => {
                config.policy.score.clear_threshold =
                    parse_f64_arg(&mut iter, "--clear-threshold")?;
            }
            "--sustain-seconds" => {
                config.policy.score.sustain_duration =
                    Duration::from_secs(parse_u64_arg(&mut iter, "--sustain-seconds")?);
            }
            "--decay-per-second" => {
                config.policy.score.decay_per_second =
                    parse_f64_arg(&mut iter, "--decay-per-second")?;
            }
            "--min-observation-seconds" => {
                config.policy.score.min_observation_duration =
                    Duration::from_secs(parse_u64_arg(&mut iter, "--min-observation-seconds")?);
            }
            "--reban-cooldown-seconds" => {
                config.policy.reban_cooldown =
                    Duration::from_secs(parse_u64_arg(&mut iter, "--reban-cooldown-seconds")?);
            }
            "--churn-enabled" => {
                config.policy.score.churn.enabled = true;
            }
            "--churn-disabled" => {
                config.policy.score.churn.enabled = false;
            }
            "--churn-reconnect-window-seconds" => {
                config.policy.score.churn.reconnect_window = Duration::from_secs(parse_u64_arg(
                    &mut iter,
                    "--churn-reconnect-window-seconds",
                )?);
            }
            "--churn-min-reconnects" => {
                config.policy.score.churn.min_reconnects =
                    parse_u32_arg(&mut iter, "--churn-min-reconnects")?;
            }
            "--churn-max-amplifier" => {
                config.policy.score.churn.max_amplifier =
                    parse_f64_arg(&mut iter, "--churn-max-amplifier")?;
            }
            "--churn-decay-per-second" => {
                config.policy.score.churn.decay_per_second =
                    parse_f64_arg(&mut iter, "--churn-decay-per-second")?;
            }
            "--peer-ip" => {
                let value = iter.next().context("expected peer IP after `--peer-ip`")?;
                config.peer_ip = Some(
                    value
                        .parse::<IpAddr>()
                        .with_context(|| format!("invalid peer IP `{value}`"))?,
                );
            }
            "--compare-adr-0006" => {
                config.compare_adr_0006 = true;
                config.hydrate_logged_score_state = false;
            }
            "--corpus-name" => {
                config.corpus_name = Some(
                    iter.next()
                        .context("expected corpus name after `--corpus-name`")?,
                );
            }
            "--recompute-score" => {
                config.hydrate_logged_score_state = false;
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
    if !(0.0..=1.0).contains(&config.policy.score.required_progress_delta) {
        bail!("--required-progress-delta must be between 0.0 and 1.0");
    }
    if config.policy.score.progress_rate_scale_start < 1.0 {
        bail!("--progress-rate-scale-start must be >= 1.0");
    }
    if config.policy.score.progress_rate_scale_end < config.policy.score.progress_rate_scale_start {
        bail!("--progress-rate-scale-end must be >= --progress-rate-scale-start");
    }
    if !(0.0..=1.0).contains(&config.policy.score.progress_rate_min_scale) {
        bail!("--progress-rate-min-scale must be between 0.0 and 1.0");
    }
    if config.policy.score.weight_rate < 0.0 || config.policy.score.weight_progress < 0.0 {
        bail!("weights must be non-negative");
    }
    if !(0.0..=1.0).contains(&config.policy.score.rate_risk_floor) {
        bail!("--rate-risk-floor must be between 0.0 and 1.0");
    }
    if config.policy.score.clear_threshold > config.policy.score.ban_threshold {
        bail!("--clear-threshold must be <= --ban-threshold");
    }
    if config.policy.score.churn.min_reconnects == 0 {
        bail!("--churn-min-reconnects must be >= 1");
    }
    if config.policy.score.churn.max_amplifier < 0.0 {
        bail!("--churn-max-amplifier must be >= 0.0");
    }
    if config.policy.score.churn.decay_per_second < 0.0 {
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
    println!("  score-simulator --input <path> [--input <path> ...] [options]");
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
    println!(
        "  --compare-adr-0006               Replay baseline plus built-in ADR-0006 candidates"
    );
    println!("  --corpus-name <name>             Label used in comparison output");
    println!(
        "  --recompute-score                Recompute score instead of hydrating logged score state"
    );
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::PathBuf};

    use super::{
        Summary, adr_0006_candidate_profiles, build_candidate_band_summary_rows,
        build_candidate_delta_rows, build_peer_result_rows, parse_args, parse_log_fields,
        process_reader, run_candidate_set,
    };
    use brrpolice::policy::{PolicyEngine, ReplayScoreModel};

    #[test]
    fn parses_vmui_wrapped_json_line() {
        let line = r#"{"_msg":"{\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:00:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":42}}"}"#;
        let parsed = parse_log_fields(line).expect("expected parsed fields");
        assert_eq!(parsed.peer_ip, "1.2.3.4");
        assert_eq!(parsed.peer_port, 51413);
        assert_eq!(parsed.observed_duration_seconds, Some(42));
    }

    #[test]
    fn parses_direct_structured_json_line() {
        let line = r#"{"timestamp":"2026-03-12T10:00:00Z","level":"INFO","fields":{"message":"peer ban applied","peer_ip":"1.2.3.4","peer_port":51413,"torrent_hash":"abc","torrent_total_size_bytes":1048576,"observed_at":"2026-03-12T10:00:00Z","progress_delta":0.0,"average_upload_rate_bps":0}}"#;
        let parsed = parse_log_fields(line).expect("expected parsed fields");
        assert_eq!(parsed.message, "peer ban applied");
        assert_eq!(parsed.torrent_hash, "abc");
        assert_eq!(parsed.torrent_total_size_bytes, Some(1_048_576));
    }

    #[test]
    fn parses_local_corpus_torrent_size_alias() {
        let line = r#"{"timestamp":"2026-03-23T04:13:44.986Z","fields":{"message":"peer policy update","peer_ip":"1.2.3.4","peer_port":51413,"torrent_hash":"abc","torrent_size_bytes":2048,"observed_at":"2026-03-23T04:13:44.986Z","progress_delta":0.01,"average_upload_rate_bps":99,"sample_score_risk":0.2,"effective_sample_score_risk":0.3}}"#;
        let parsed = parse_log_fields(line).expect("expected parsed fields");
        assert_eq!(parsed.torrent_total_size_bytes, Some(2_048));
        assert_eq!(parsed.effective_sample_score_risk, Some(0.3));
    }

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
        assert!(config.policy.score.churn.enabled);
        assert_eq!(config.policy.score.churn.reconnect_window.as_secs(), 120);
        assert_eq!(config.policy.score.churn.min_reconnects, 2);
        assert!((config.policy.score.churn.max_amplifier - 0.8).abs() < f64::EPSILON);
        assert!((config.policy.score.churn.decay_per_second - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_args_supports_recompute_score_flag() {
        let args = vec![
            "--input".to_string(),
            "one.jsonl".to_string(),
            "--recompute-score".to_string(),
        ];
        let config = parse_args(args).expect("expected args to parse");
        assert!(!config.hydrate_logged_score_state);
    }

    #[test]
    fn parse_args_supports_adr_comparison_mode() {
        let args = vec![
            "--input".to_string(),
            "one.json".to_string(),
            "--compare-adr-0006".to_string(),
            "--corpus-name".to_string(),
            "holdout".to_string(),
        ];
        let config = parse_args(args).expect("expected args to parse");
        assert!(config.compare_adr_0006);
        assert!(!config.hydrate_logged_score_state);
        assert_eq!(config.corpus_name.as_deref(), Some("holdout"));
    }

    #[test]
    fn replay_harness_aggregates_across_multiple_readers() {
        let config = parse_args(vec!["--input".into(), "dummy".into()]).unwrap();
        let policy = PolicyEngine::new(config.policy.clone(), &Default::default());
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();

        let first = Cursor::new(
            "{\"timestamp\":\"2026-03-12T10:00:00Z\",\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:00:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":300}}\n",
        );
        let second = Cursor::new(
            "{\"timestamp\":\"2026-03-12T10:02:00Z\",\"fields\":{\"message\":\"peer ban applied\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:02:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":420}}\n",
        );

        process_reader(
            &policy,
            ReplayScoreModel::CurrentComposite,
            &config,
            first,
            "first".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();
        process_reader(
            &policy,
            ReplayScoreModel::CurrentComposite,
            &config,
            second,
            "second".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.lines_total, 2);
        assert_eq!(summary.lines_decision, 2);
        assert_eq!(summary.actual_bans, 1);
        assert_eq!(summary.peers_seen, 1);
    }

    #[test]
    fn active_ban_window_suppresses_repeat_bans_for_same_peer() {
        let config = parse_args(vec![
            "--input".into(),
            "dummy".into(),
            "--target-rate-bps".into(),
            "1".into(),
            "--weight-rate".into(),
            "1.0".into(),
            "--weight-progress".into(),
            "0.0".into(),
            "--ban-threshold".into(),
            "0.8".into(),
            "--clear-threshold".into(),
            "0.4".into(),
            "--sustain-seconds".into(),
            "1".into(),
            "--min-observation-seconds".into(),
            "1".into(),
            "--decay-per-second".into(),
            "0.0025".into(),
        ])
        .unwrap();
        let policy = PolicyEngine::new(config.policy.clone(), &Default::default());
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();

        let replay = Cursor::new(concat!(
            "{\"timestamp\":\"2026-03-12T10:00:00Z\",\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:00:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":300}}\n",
            "{\"timestamp\":\"2026-03-12T10:01:00Z\",\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:01:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":360}}\n",
            "{\"timestamp\":\"2026-03-12T10:02:00Z\",\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"observed_at\":\"2026-03-12T10:02:00Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":0,\"observed_duration_seconds\":420}}\n"
        ));

        process_reader(
            &policy,
            ReplayScoreModel::CurrentComposite,
            &config,
            replay,
            "replay".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.simulated_bans, 1);
    }

    #[test]
    fn peer_result_rows_include_rate_band_and_byte_metrics() {
        let config = parse_args(vec![
            "--input".into(),
            "dummy".into(),
            "--target-rate-bps".into(),
            "1000".into(),
        ])
        .unwrap();
        let policy = PolicyEngine::new(config.policy.clone(), &Default::default());
        let mut state = super::ReplayState::default();
        let mut summary = Summary::default();

        let replay = Cursor::new(concat!(
            "{\"timestamp\":\"2026-03-12T10:00:00Z\",\"fields\":{\"message\":\"peer not bannable yet decision\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"torrent_name\":\"Example\",\"torrent_total_size_bytes\":1000000,\"observed_at\":\"2026-03-12T10:00:00Z\",\"progress_delta\":0.01,\"average_upload_rate_bps\":2000,\"observed_duration_seconds\":300}}\n",
            "{\"timestamp\":\"2026-03-12T10:02:00Z\",\"fields\":{\"message\":\"peer ban applied\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"abc\",\"torrent_name\":\"Example\",\"torrent_total_size_bytes\":1000000,\"observed_at\":\"2026-03-12T10:02:00Z\",\"progress_delta\":0.01,\"average_upload_rate_bps\":2000,\"observed_duration_seconds\":420}}\n"
        ));

        process_reader(
            &policy,
            ReplayScoreModel::CurrentComposite,
            &config,
            replay,
            "replay".to_string(),
            &mut state,
            &mut summary,
        )
        .unwrap();

        let rows = build_peer_result_rows(&state);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rate_reference_band, "clearly_healthy");
        assert_eq!(rows[0].torrent_total_size_bytes, 1_000_000);
        assert_eq!(rows[0].progress_delta_bytes, 10_000);
        assert_eq!(rows[0].actual_ban_events, 1);
        assert_eq!(rows[0].peer_behavior_key, "abc+1.2.3.4");
    }

    #[test]
    fn adr_comparison_emits_delta_and_band_summaries() {
        let config = parse_args(vec![
            "--input".into(),
            "dummy".into(),
            "--compare-adr-0006".into(),
        ])
        .unwrap();
        let replay = concat!(
            "{\"timestamp\":\"2026-03-23T04:13:44.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"healthy\",\"torrent_name\":\"Healthy\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:13:44.986Z\",\"progress_delta\":0.0005,\"average_upload_rate_bps\":160000,\"observed_duration_seconds\":300}}\n",
            "{\"timestamp\":\"2026-03-23T04:13:54.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"healthy\",\"torrent_name\":\"Healthy\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:13:54.986Z\",\"progress_delta\":0.0005,\"average_upload_rate_bps\":160000,\"observed_duration_seconds\":310}}\n",
            "{\"timestamp\":\"2026-03-23T04:14:04.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"1.2.3.4\",\"peer_port\":51413,\"torrent_hash\":\"healthy\",\"torrent_name\":\"Healthy\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:14:04.986Z\",\"progress_delta\":0.0005,\"average_upload_rate_bps\":160000,\"observed_duration_seconds\":320}}\n",
            "{\"timestamp\":\"2026-03-23T04:13:44.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"5.6.7.8\",\"peer_port\":60000,\"torrent_hash\":\"marginal\",\"torrent_name\":\"Marginal\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:13:44.986Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":65536,\"observed_duration_seconds\":300}}\n",
            "{\"timestamp\":\"2026-03-23T04:13:54.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"5.6.7.8\",\"peer_port\":60000,\"torrent_hash\":\"marginal\",\"torrent_name\":\"Marginal\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:13:54.986Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":65536,\"observed_duration_seconds\":310}}\n",
            "{\"timestamp\":\"2026-03-23T04:14:04.986Z\",\"fields\":{\"message\":\"peer policy update\",\"peer_ip\":\"5.6.7.8\",\"peer_port\":60000,\"torrent_hash\":\"marginal\",\"torrent_name\":\"Marginal\",\"torrent_size_bytes\":1000000000,\"observed_at\":\"2026-03-23T04:14:04.986Z\",\"progress_delta\":0.0,\"average_upload_rate_bps\":65536,\"observed_duration_seconds\":320}}\n"
        );
        let input = std::env::temp_dir().join(format!(
            "score-simulator-adr-compare-{}.json",
            std::process::id()
        ));
        std::fs::write(&input, replay).expect("write replay");

        let mut compare_config = config.clone();
        compare_config.inputs = vec![input.clone()];
        compare_config.corpus_name = Some("unit".into());
        let runs = run_candidate_set(&compare_config, &adr_0006_candidate_profiles())
            .expect("candidate set");
        let baseline = runs
            .iter()
            .find(|run| run.profile.model == ReplayScoreModel::CurrentComposite)
            .expect("baseline run");
        let candidate = runs
            .iter()
            .find(|run| run.profile.model == ReplayScoreModel::MarginalBandBounded)
            .expect("marginal run");

        let band_rows = build_candidate_band_summary_rows("unit", baseline, candidate);
        let delta_rows = build_candidate_delta_rows("unit", baseline, candidate);

        assert_eq!(band_rows.len(), 5);
        assert!(
            delta_rows
                .iter()
                .any(|row| row.peer_behavior_key == "marginal+5.6.7.8")
        );
        let _ = std::fs::remove_file(input);
    }
}
