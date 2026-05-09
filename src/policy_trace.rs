#![allow(dead_code)]

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{PolicyConfig, ScorePolicyConfig},
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity,
        PeerEvaluation, PeerObservationId, PeerSessionState, TorrentScope,
    },
};

pub const POLICY_TRACE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyTraceRecord {
    pub record_type: PolicyTraceRecordType,
    pub schema_version: u16,
    pub observed_at: String,
    pub service_version: String,
    pub policy_trace_id: String,
    pub config_fingerprint: String,
    pub torrent: TraceTorrent,
    pub peer: TracePeer,
    pub prior_session: Option<TracePeerSessionState>,
    pub evaluated_session: TracePeerSessionState,
    pub policy_inputs: TracePolicyInputs,
    pub guardrail_inputs: TraceGuardrailInputs,
    pub decision_output: TraceDecisionOutput,
    pub simulator_hints: TraceSimulatorHints,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTraceRecordType {
    PeerObservation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceTorrent {
    pub hash: String,
    pub name: Option<String>,
    pub tracker: Option<String>,
    pub total_size_bytes: Option<u64>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub total_seeders: u32,
    pub in_scope: bool,
}

impl From<&TorrentScope> for TraceTorrent {
    fn from(value: &TorrentScope) -> Self {
        Self {
            hash: value.hash.clone(),
            name: Some(value.name.clone()),
            tracker: value.tracker.clone(),
            total_size_bytes: None,
            category: value.category.clone(),
            tags: value.tags.clone(),
            total_seeders: value.total_seeders,
            in_scope: value.in_scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracePeer {
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub progress: f64,
    pub up_rate_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracePeerSessionState {
    pub observation_id: TracePeerObservationIdentity,
    pub offence_identity: TracePeerBehaviourIdentity,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub baseline_progress: f64,
    pub latest_progress: f64,
    pub rolling_avg_up_rate_bps: u64,
    pub observed_duration_ms: u64,
    pub bad_duration_ms: u64,
    pub ban_score: f64,
    pub ban_score_above_threshold_duration_ms: u64,
    pub churn_reconnect_count: u32,
    pub churn_window_started_at: Option<String>,
    pub churn_amplifier: f64,
    pub sample_count: u32,
    pub last_torrent_seeder_count: u32,
    pub last_exemption_reason: Option<TraceExemptionReason>,
    pub bannable_since: Option<String>,
    pub last_ban_decision_at: Option<String>,
}

impl From<&PeerSessionState> for TracePeerSessionState {
    fn from(value: &PeerSessionState) -> Self {
        Self {
            observation_id: (&value.observation_id).into(),
            offence_identity: (&value.offence_identity).into(),
            first_seen_at: trace_timestamp(value.first_seen_at),
            last_seen_at: trace_timestamp(value.last_seen_at),
            baseline_progress: value.baseline_progress,
            latest_progress: value.latest_progress,
            rolling_avg_up_rate_bps: value.rolling_avg_up_rate_bps,
            observed_duration_ms: duration_millis(value.observed_duration),
            bad_duration_ms: duration_millis(value.bad_duration),
            ban_score: value.ban_score,
            ban_score_above_threshold_duration_ms: duration_millis(
                value.ban_score_above_threshold_duration,
            ),
            churn_reconnect_count: value.churn_reconnect_count,
            churn_window_started_at: value.churn_window_started_at.map(trace_timestamp),
            churn_amplifier: value.churn_amplifier,
            sample_count: value.sample_count,
            last_torrent_seeder_count: value.last_torrent_seeder_count,
            last_exemption_reason: value.last_exemption_reason.as_ref().map(Into::into),
            bannable_since: value.bannable_since.map(trace_timestamp),
            last_ban_decision_at: value.last_ban_decision_at.map(trace_timestamp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracePeerObservationIdentity {
    pub torrent_hash: String,
    pub peer_ip: Option<IpAddr>,
    pub peer_port: u16,
}

impl From<&PeerObservationId> for TracePeerObservationIdentity {
    fn from(value: &PeerObservationId) -> Self {
        Self {
            torrent_hash: value.torrent_hash.clone(),
            peer_ip: Some(value.peer_ip),
            peer_port: value.peer_port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracePeerBehaviourIdentity {
    pub torrent_hash: String,
    pub peer_ip: Option<IpAddr>,
}

impl From<&OffenceIdentity> for TracePeerBehaviourIdentity {
    fn from(value: &OffenceIdentity) -> Self {
        Self {
            torrent_hash: value.torrent_hash.clone(),
            peer_ip: Some(value.peer_ip),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TracePolicyInputs {
    pub new_peer_grace_period_ms: u64,
    pub decay_window_ms: u64,
    pub ignore_peer_progress_at_or_above: f64,
    pub min_total_seeders: u32,
    pub reban_cooldown_ms: u64,
    pub score: TraceScorePolicyInputs,
    pub ban_ladder_duration_ms: Vec<u64>,
}

impl From<&PolicyConfig> for TracePolicyInputs {
    fn from(value: &PolicyConfig) -> Self {
        Self {
            new_peer_grace_period_ms: duration_millis(value.new_peer_grace_period),
            decay_window_ms: duration_millis(value.decay_window),
            ignore_peer_progress_at_or_above: value.ignore_peer_progress_at_or_above,
            min_total_seeders: value.min_total_seeders,
            reban_cooldown_ms: duration_millis(value.reban_cooldown),
            score: (&value.score).into(),
            ban_ladder_duration_ms: value
                .ban_ladder
                .durations
                .iter()
                .copied()
                .map(duration_millis)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceScorePolicyInputs {
    pub target_rate_bps: u64,
    pub required_progress_delta: f64,
    pub progress_rate_scale_start: f64,
    pub progress_rate_scale_end: f64,
    pub progress_rate_min_scale: f64,
    pub weight_rate: f64,
    pub weight_progress: f64,
    pub rate_risk_floor: f64,
    pub ban_threshold: f64,
    pub clear_threshold: f64,
    pub sustain_duration_ms: u64,
    pub decay_per_second: f64,
    pub min_observation_duration_ms: u64,
    pub max_score: f64,
    pub churn_enabled: bool,
    pub churn_reconnect_window_ms: u64,
    pub churn_min_reconnects: u32,
    pub churn_max_amplifier: f64,
    pub churn_decay_per_second: f64,
}

impl From<&ScorePolicyConfig> for TraceScorePolicyInputs {
    fn from(value: &ScorePolicyConfig) -> Self {
        Self {
            target_rate_bps: value.target_rate_bps,
            required_progress_delta: value.required_progress_delta,
            progress_rate_scale_start: value.progress_rate_scale_start,
            progress_rate_scale_end: value.progress_rate_scale_end,
            progress_rate_min_scale: value.progress_rate_min_scale,
            weight_rate: value.weight_rate,
            weight_progress: value.weight_progress,
            rate_risk_floor: value.rate_risk_floor,
            ban_threshold: value.ban_threshold,
            clear_threshold: value.clear_threshold,
            sustain_duration_ms: duration_millis(value.sustain_duration),
            decay_per_second: value.decay_per_second,
            min_observation_duration_ms: duration_millis(value.min_observation_duration),
            max_score: value.max_score,
            churn_enabled: value.churn.enabled,
            churn_reconnect_window_ms: duration_millis(value.churn.reconnect_window),
            churn_min_reconnects: value.churn.min_reconnects,
            churn_max_amplifier: value.churn.max_amplifier,
            churn_decay_per_second: value.churn.decay_per_second,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceGuardrailInputs {
    pub exemption_reason: Option<TraceExemptionReason>,
    pub allowlisted_peer: bool,
    pub active_ban: bool,
    pub reban_cooldown_remaining_ms: Option<u64>,
    pub offence_history: TraceOffenceHistory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOffenceHistory {
    pub offence_count: u32,
    pub last_ban_expires_at: Option<String>,
}

impl From<&OffenceHistory> for TraceOffenceHistory {
    fn from(value: &OffenceHistory) -> Self {
        Self {
            offence_count: value.offence_count,
            last_ban_expires_at: value.last_ban_expires_at.map(trace_timestamp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceDecisionOutput {
    pub disposition: TraceBanDisposition,
    pub is_bad_sample: bool,
    pub is_bannable: bool,
    pub progress_delta: f64,
    pub sample_score_risk: f64,
    pub effective_sample_score_risk: f64,
}

impl TraceDecisionOutput {
    pub fn from_evaluation_and_disposition(
        evaluation: &PeerEvaluation,
        disposition: &BanDisposition,
    ) -> Self {
        Self {
            disposition: disposition.into(),
            is_bad_sample: evaluation.is_bad_sample,
            is_bannable: evaluation.is_bannable,
            progress_delta: evaluation.progress_delta,
            sample_score_risk: evaluation.sample_score_risk,
            effective_sample_score_risk: evaluation.effective_sample_score_risk,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceSimulatorHints {
    pub peer_observation_identity: TracePeerObservationIdentity,
    pub peer_behaviour_identity: TracePeerBehaviourIdentity,
    pub sample_duration_ms: u64,
    pub sample_up_rate_bps: u64,
    pub current_rate_band: TraceRateBand,
    pub band_at_ban: Option<TraceRateBand>,
}

impl TraceSimulatorHints {
    pub fn from_evaluation(evaluation: &PeerEvaluation, policy: &PolicyConfig) -> Self {
        let current_rate_band =
            TraceRateBand::from_rate(evaluation.sample_up_rate_bps, policy.score.target_rate_bps);
        let band_at_ban = evaluation.is_bannable.then_some(current_rate_band.clone());

        Self {
            peer_observation_identity: (&evaluation.session.observation_id).into(),
            peer_behaviour_identity: (&evaluation.session.offence_identity).into(),
            sample_duration_ms: duration_millis(evaluation.sample_duration),
            sample_up_rate_bps: evaluation.sample_up_rate_bps,
            current_rate_band,
            band_at_ban,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRateBand {
    pub band: TraceRateBandName,
    pub up_rate_bps: u64,
    pub target_rate_bps: u64,
    pub target_ratio: f64,
}

impl TraceRateBand {
    pub fn from_rate(up_rate_bps: u64, target_rate_bps: u64) -> Self {
        let target_ratio = if target_rate_bps == 0 {
            0.0
        } else {
            up_rate_bps as f64 / target_rate_bps as f64
        };
        let band = if target_ratio >= 1.0 {
            TraceRateBandName::MeetsTarget
        } else if target_ratio >= 0.5 {
            TraceRateBandName::ModerateDeficit
        } else {
            TraceRateBandName::SevereDeficit
        };

        Self {
            band,
            up_rate_bps,
            target_rate_bps,
            target_ratio,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceRateBandName {
    MeetsTarget,
    ModerateDeficit,
    SevereDeficit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason_code", rename_all = "snake_case")]
pub enum TraceExemptionReason {
    TorrentExcluded,
    AllowlistedPeer,
    NearComplete { progress: f64, threshold: f64 },
    NewPeerGracePeriod { age_ms: u64, grace_period_ms: u64 },
    AlreadyBanned,
}

impl From<&ExemptionReason> for TraceExemptionReason {
    fn from(value: &ExemptionReason) -> Self {
        match value {
            ExemptionReason::TorrentExcluded => Self::TorrentExcluded,
            ExemptionReason::AllowlistedPeer => Self::AllowlistedPeer,
            ExemptionReason::NearComplete {
                progress,
                threshold,
            } => Self::NearComplete {
                progress: *progress,
                threshold: *threshold,
            },
            ExemptionReason::NewPeerGracePeriod { age, grace_period } => Self::NewPeerGracePeriod {
                age_ms: duration_millis(*age),
                grace_period_ms: duration_millis(*grace_period),
            },
            ExemptionReason::AlreadyBanned => Self::AlreadyBanned,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum TraceBanDisposition {
    Exempt {
        reason: TraceExemptionReason,
    },
    NotBannableYet {
        observed_duration_ms: u64,
        required_observation_ms: u64,
        bad_duration_ms: u64,
        required_bad_duration_ms: u64,
    },
    RebanCooldown {
        remaining_ms: u64,
    },
    DuplicateSuppressed,
    Ban {
        decision: TraceBanDecision,
    },
}

impl From<&BanDisposition> for TraceBanDisposition {
    fn from(value: &BanDisposition) -> Self {
        match value {
            BanDisposition::Exempt(reason) => Self::Exempt {
                reason: reason.into(),
            },
            BanDisposition::NotBannableYet {
                observed_duration,
                required_observation,
                bad_duration,
                required_bad_duration,
            } => Self::NotBannableYet {
                observed_duration_ms: duration_millis(*observed_duration),
                required_observation_ms: duration_millis(*required_observation),
                bad_duration_ms: duration_millis(*bad_duration),
                required_bad_duration_ms: duration_millis(*required_bad_duration),
            },
            BanDisposition::RebanCooldown { remaining } => Self::RebanCooldown {
                remaining_ms: duration_millis(*remaining),
            },
            BanDisposition::DuplicateSuppressed => Self::DuplicateSuppressed,
            BanDisposition::Ban(decision) => Self::Ban {
                decision: decision.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceBanDecision {
    pub peer_ip: Option<IpAddr>,
    pub peer_port: u16,
    pub offence_number: u32,
    pub ttl_ms: u64,
    pub reason_code: String,
    pub reason_details: String,
}

impl From<&BanDecision> for TraceBanDecision {
    fn from(value: &BanDecision) -> Self {
        Self {
            peer_ip: Some(value.peer_ip),
            peer_port: value.peer_port,
            offence_number: value.offence_number,
            ttl_ms: duration_millis(value.ttl),
            reason_code: value.reason_code.clone(),
            reason_details: value.reason_details.clone(),
        }
    }
}

pub fn trace_timestamp(value: SystemTime) -> String {
    humantime::format_rfc3339_millis(value).to_string()
}

pub fn duration_millis(value: Duration) -> u64 {
    value.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;
    use crate::types::PeerObservationId;

    #[test]
    fn peer_observation_trace_record_round_trips_as_json() {
        let observed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let prior_session = sample_session(observed_at - Duration::from_secs(30));
        let mut evaluated = sample_session(observed_at);
        evaluated.latest_progress = 0.25;
        evaluated.observed_duration = Duration::from_secs(30);
        evaluated.bad_duration = Duration::from_secs(15);
        evaluated.ban_score = 1.7;
        evaluated.ban_score_above_threshold_duration = Duration::from_secs(10);

        let evaluation = PeerEvaluation {
            session: evaluated.clone(),
            progress_delta: 0.01,
            sample_duration: Duration::from_secs(30),
            sample_up_rate_bps: 4096,
            is_bad_sample: true,
            is_bannable: true,
            sample_score_risk: 0.9,
            effective_sample_score_risk: 1.2,
        };
        let disposition = BanDisposition::Ban(BanDecision {
            peer_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            peer_port: 51413,
            offence_number: 2,
            ttl: Duration::from_secs(7_200),
            reason_code: "score_based".to_string(),
            reason_details: "score peer".to_string(),
        });
        let policy = PolicyConfig::default();

        let record = PolicyTraceRecord {
            record_type: PolicyTraceRecordType::PeerObservation,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            observed_at: trace_timestamp(observed_at),
            service_version: "0.1.0-test".to_string(),
            policy_trace_id: "trace-1".to_string(),
            config_fingerprint: "fingerprint".to_string(),
            torrent: TraceTorrent {
                hash: "torrent-hash".to_string(),
                name: Some("ubuntu.iso".to_string()),
                tracker: Some("tracker.example".to_string()),
                total_size_bytes: Some(1_048_576),
                category: Some("linux".to_string()),
                tags: vec!["public".to_string()],
                total_seeders: 4,
                in_scope: true,
            },
            peer: TracePeer {
                ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
                port: 51413,
                progress: 0.25,
                up_rate_bps: 4096,
            },
            prior_session: Some((&prior_session).into()),
            evaluated_session: (&evaluated).into(),
            policy_inputs: (&policy).into(),
            guardrail_inputs: TraceGuardrailInputs {
                exemption_reason: None,
                allowlisted_peer: false,
                active_ban: false,
                reban_cooldown_remaining_ms: None,
                offence_history: TraceOffenceHistory {
                    offence_count: 1,
                    last_ban_expires_at: None,
                },
            },
            decision_output: TraceDecisionOutput::from_evaluation_and_disposition(
                &evaluation,
                &disposition,
            ),
            simulator_hints: TraceSimulatorHints::from_evaluation(&evaluation, &policy),
        };

        let json = serde_json::to_string(&record).unwrap();

        assert!(json.contains(r#""record_type":"peer_observation""#));
        assert!(json.contains(r#""schema_version":1"#));
        assert!(json.contains(r#""observed_duration_ms":30000"#));
        assert!(!json.contains("SystemTime"));
        assert!(!json.contains("Duration"));
        assert_eq!(
            serde_json::from_str::<PolicyTraceRecord>(&json).unwrap(),
            record
        );
    }

    fn sample_session(last_seen_at: std::time::SystemTime) -> PeerSessionState {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        PeerSessionState {
            observation_id: PeerObservationId {
                torrent_hash: "torrent-hash".to_string(),
                peer_ip,
                peer_port: 51413,
            },
            offence_identity: OffenceIdentity {
                torrent_hash: "torrent-hash".to_string(),
                peer_ip,
            },
            first_seen_at: last_seen_at - Duration::from_secs(60),
            last_seen_at,
            baseline_progress: 0.2,
            latest_progress: 0.2,
            rolling_avg_up_rate_bps: 2_048,
            observed_duration: Duration::from_secs(60),
            bad_duration: Duration::from_secs(5),
            ban_score: 0.8,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 1,
            churn_window_started_at: Some(last_seen_at - Duration::from_secs(20)),
            churn_amplifier: 0.25,
            sample_count: 3,
            last_torrent_seeder_count: 4,
            last_exemption_reason: Some(ExemptionReason::NearComplete {
                progress: 0.96,
                threshold: 0.95,
            }),
            bannable_since: None,
            last_ban_decision_at: None,
        }
    }
}
