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
use serde::Deserialize;

#[derive(Debug, Clone)]
struct SimulatorConfig {
    input: PathBuf,
    target_rate_bps: u64,
    required_progress_delta: f64,
    weight_rate: f64,
    weight_progress: f64,
    ban_threshold: f64,
    clear_threshold: f64,
    sustain_seconds: u64,
    decay_per_second: f64,
    min_observation_seconds: u64,
    peer_ip: Option<IpAddr>,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        Self {
            input: PathBuf::new(),
            target_rate_bps: 65_536,
            required_progress_delta: 0.005,
            weight_rate: 0.7,
            weight_progress: 0.3,
            ban_threshold: 0.8,
            clear_threshold: 0.4,
            sustain_seconds: 60,
            decay_per_second: 0.0025,
            min_observation_seconds: 300,
            peer_ip: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OuterLogLine {
    #[serde(rename = "_msg")]
    msg: String,
}

#[derive(Debug, Deserialize)]
struct InnerLogLine {
    fields: LogFields,
}

#[derive(Debug, Deserialize)]
struct LogFields {
    message: String,
    peer_ip: String,
    peer_port: u16,
    torrent_hash: String,
    observed_at: String,
    progress_delta: f64,
    average_upload_rate_bps: u64,
    observed_duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PeerKey {
    torrent_hash: String,
    peer_ip: IpAddr,
    peer_port: u16,
}

#[derive(Debug, Clone)]
struct PeerState {
    score: f64,
    above_threshold_for: Duration,
    last_observed_at: Option<SystemTime>,
    observed_duration_seconds: u64,
    ban_events: u32,
    first_crossing_at: Option<SystemTime>,
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            score: 0.0,
            above_threshold_for: Duration::ZERO,
            last_observed_at: None,
            observed_duration_seconds: 0,
            ban_events: 0,
            first_crossing_at: None,
        }
    }
}

#[derive(Default)]
struct Summary {
    lines_total: u64,
    lines_decision: u64,
    peers_seen: u64,
    simulated_bans: u64,
    actual_bans: u64,
}

pub fn run(args: Vec<String>) -> Result<()> {
    let config = parse_args(args)?;
    let file = File::open(&config.input)
        .with_context(|| format!("opening input file `{}`", config.input.display()))?;
    let reader = BufReader::new(file);

    let mut states: HashMap<PeerKey, PeerState> = HashMap::new();
    let mut summary = Summary::default();

    for (index, line_result) in reader.lines().enumerate() {
        let line =
            line_result.with_context(|| format!("reading line {} from input file", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        summary.lines_total += 1;

        let outer: OuterLogLine = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let inner: InnerLogLine = match serde_json::from_str(&outer.msg) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let fields = inner.fields;
        if fields.message != "peer not bannable yet decision"
            && fields.message != "peer exemption decision"
            && fields.message != "peer ban applied"
        {
            continue;
        }
        summary.lines_decision += 1;

        let peer_ip: IpAddr = match fields.peer_ip.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        if let Some(filter_ip) = config.peer_ip
            && peer_ip != filter_ip
        {
            continue;
        }

        if fields.message == "peer ban applied" {
            summary.actual_bans += 1;
        }

        let observed_at =
            parse_rfc3339(&fields.observed_at).with_context(|| "parsing observed_at timestamp")?;
        let key = PeerKey {
            torrent_hash: fields.torrent_hash,
            peer_ip,
            peer_port: fields.peer_port,
        };

        let state = states.entry(key).or_default();
        if state.last_observed_at.is_none() {
            summary.peers_seen += 1;
        }

        state.observed_duration_seconds = fields
            .observed_duration_seconds
            .unwrap_or(state.observed_duration_seconds);

        let elapsed = state
            .last_observed_at
            .and_then(|previous| observed_at.duration_since(previous).ok())
            .unwrap_or_default();
        state.last_observed_at = Some(observed_at);

        // Exemptions pause accumulation and apply only decay.
        if fields.message == "peer exemption decision" {
            decay_score(state, elapsed, config.decay_per_second);
            state.above_threshold_for = Duration::ZERO;
            continue;
        }

        let feature_rate =
            normalized_rate_risk(fields.average_upload_rate_bps, config.target_rate_bps);
        let feature_progress =
            normalized_progress_risk(fields.progress_delta, config.required_progress_delta);
        let sample_risk =
            (config.weight_rate * feature_rate) + (config.weight_progress * feature_progress);

        decay_score(state, elapsed, config.decay_per_second);
        state.score = (state.score + sample_risk).clamp(0.0, 5.0);

        if state.observed_duration_seconds < config.min_observation_seconds {
            state.above_threshold_for = Duration::ZERO;
            continue;
        }

        if state.score >= config.ban_threshold {
            state.above_threshold_for += elapsed;
            if state.first_crossing_at.is_none() {
                state.first_crossing_at = Some(observed_at);
            }
            if state.above_threshold_for >= Duration::from_secs(config.sustain_seconds) {
                summary.simulated_bans += 1;
                state.ban_events += 1;
                state.above_threshold_for = Duration::ZERO;
                state.score = config.clear_threshold.min(state.score);
            }
        } else if state.score <= config.clear_threshold {
            state.above_threshold_for = Duration::ZERO;
        }
    }

    print_summary(&config, &summary, &states);
    Ok(())
}

fn normalized_rate_risk(rate_bps: u64, target_bps: u64) -> f64 {
    if target_bps == 0 {
        return 0.0;
    }
    let deficit = target_bps.saturating_sub(rate_bps) as f64;
    (deficit / target_bps as f64).clamp(0.0, 1.0)
}

fn normalized_progress_risk(progress_delta: f64, required_progress_delta: f64) -> f64 {
    if required_progress_delta <= 0.0 {
        return 0.0;
    }
    let deficit = (required_progress_delta - progress_delta).max(0.0);
    (deficit / required_progress_delta).clamp(0.0, 1.0)
}

fn decay_score(state: &mut PeerState, elapsed: Duration, decay_per_second: f64) {
    if elapsed.is_zero() || state.score <= 0.0 || decay_per_second <= 0.0 {
        return;
    }

    let decay = decay_per_second * elapsed.as_secs_f64();
    state.score = (state.score - decay).max(0.0);
}

fn print_summary(
    config: &SimulatorConfig,
    summary: &Summary,
    states: &HashMap<PeerKey, PeerState>,
) {
    println!("score simulator summary");
    println!("input={}", config.input.display());
    println!(
        "config: target_rate_bps={} required_progress_delta={:.6} weights(rate={:.3},progress={:.3}) threshold(ban={:.3},clear={:.3}) sustain_seconds={} decay_per_second={:.6} min_observation_seconds={}",
        config.target_rate_bps,
        config.required_progress_delta,
        config.weight_rate,
        config.weight_progress,
        config.ban_threshold,
        config.clear_threshold,
        config.sustain_seconds,
        config.decay_per_second,
        config.min_observation_seconds
    );
    if let Some(peer_ip) = config.peer_ip {
        println!("peer_filter_ip={peer_ip}");
    }
    println!(
        "lines_total={} decision_lines={} peers_seen={} simulated_bans={} actual_bans={}",
        summary.lines_total,
        summary.lines_decision,
        summary.peers_seen,
        summary.simulated_bans,
        summary.actual_bans
    );

    let mut interesting: Vec<(&PeerKey, &PeerState)> = states
        .iter()
        .filter(|(_, state)| state.ban_events > 0)
        .collect();
    interesting.sort_by_key(|(_, state)| std::cmp::Reverse(state.ban_events));
    for (key, state) in interesting.into_iter().take(20) {
        println!(
            "simulated_ban peer={} port={} torrent_hash={} ban_events={} final_score={:.3}",
            key.peer_ip, key.peer_port, key.torrent_hash, state.ban_events, state.score
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
                config.input = PathBuf::from(value);
            }
            "--target-rate-bps" => {
                config.target_rate_bps = parse_u64_arg(&mut iter, "--target-rate-bps")?;
            }
            "--required-progress-delta" => {
                config.required_progress_delta =
                    parse_f64_arg(&mut iter, "--required-progress-delta")?;
            }
            "--weight-rate" => {
                config.weight_rate = parse_f64_arg(&mut iter, "--weight-rate")?;
            }
            "--weight-progress" => {
                config.weight_progress = parse_f64_arg(&mut iter, "--weight-progress")?;
            }
            "--ban-threshold" => {
                config.ban_threshold = parse_f64_arg(&mut iter, "--ban-threshold")?;
            }
            "--clear-threshold" => {
                config.clear_threshold = parse_f64_arg(&mut iter, "--clear-threshold")?;
            }
            "--sustain-seconds" => {
                config.sustain_seconds = parse_u64_arg(&mut iter, "--sustain-seconds")?;
            }
            "--decay-per-second" => {
                config.decay_per_second = parse_f64_arg(&mut iter, "--decay-per-second")?;
            }
            "--min-observation-seconds" => {
                config.min_observation_seconds =
                    parse_u64_arg(&mut iter, "--min-observation-seconds")?;
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
            other => bail!("unknown argument `{other}`; use `simulate-score --help`"),
        }
    }

    if config.input.as_os_str().is_empty() {
        bail!("missing required `--input` argument");
    }
    if !(0.0..=1.0).contains(&config.required_progress_delta) {
        bail!("--required-progress-delta must be between 0.0 and 1.0");
    }
    if config.weight_rate < 0.0 || config.weight_progress < 0.0 {
        bail!("weights must be non-negative");
    }
    if config.clear_threshold > config.ban_threshold {
        bail!("--clear-threshold must be <= --ban-threshold");
    }

    Ok(config)
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
    println!("  brrpolice simulate-score --input <path> [options]");
    println!();
    println!("Options:");
    println!("  --target-rate-bps <n>            Upload target for rate-risk (default: 65536)");
    println!(
        "  --required-progress-delta <f>    Required progress fraction in window (default: 0.005)"
    );
    println!("  --weight-rate <f>                Weight for rate-risk feature (default: 0.7)");
    println!("  --weight-progress <f>            Weight for progress-risk feature (default: 0.3)");
    println!(
        "  --ban-threshold <f>              Score threshold to qualify for ban (default: 0.8)"
    );
    println!(
        "  --clear-threshold <f>            Clear threshold after cooldown/hysteresis (default: 0.4)"
    );
    println!(
        "  --sustain-seconds <n>            Seconds score must stay above threshold (default: 60)"
    );
    println!("  --decay-per-second <f>           Score decay rate per second (default: 0.0025)");
    println!(
        "  --min-observation-seconds <n>    Minimum observation before scoring can ban (default: 300)"
    );
    println!("  --peer-ip <ip>                   Optional peer IP filter");
}

#[cfg(test)]
mod tests {
    use super::{normalized_progress_risk, normalized_rate_risk};

    #[test]
    fn rate_risk_is_zero_when_peer_meets_target() {
        assert_eq!(normalized_rate_risk(65_536, 65_536), 0.0);
    }

    #[test]
    fn rate_risk_is_capped_at_one() {
        assert_eq!(normalized_rate_risk(0, 65_536), 1.0);
    }

    #[test]
    fn progress_risk_is_zero_when_peer_exceeds_requirement() {
        assert_eq!(normalized_progress_risk(0.01, 0.005), 0.0);
    }

    #[test]
    fn progress_risk_is_capped_at_one() {
        assert_eq!(normalized_progress_risk(0.0, 0.005), 1.0);
    }
}
