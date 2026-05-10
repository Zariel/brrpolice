#![allow(dead_code)]

use std::{
    sync::LazyLock,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::{
    config::{PolicyConfig, ScorePolicyConfig},
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity,
        PeerEvaluation, PeerObservationId, PeerSessionState, TorrentScope,
    },
};

pub const POLICY_TRACE_SCHEMA_VERSION: u16 = 1;
pub const POLICY_TRACE_V1_SCHEMA_JSON: &str =
    include_str!("../schemas/policy-trace/v1.schema.json");

static POLICY_TRACE_V1_VALIDATOR: LazyLock<Result<jsonschema::Validator, String>> =
    LazyLock::new(|| {
        let schema: Value = serde_json::from_str(POLICY_TRACE_V1_SCHEMA_JSON)
            .map_err(|error| format!("invalid embedded policy trace schema: {error}"))?;
        jsonschema::draft202012::options()
            .build(&schema)
            .map_err(|error| format!("failed to compile policy trace schema: {error}"))
    });

pub fn validate_policy_trace_v1_value(value: &Value) -> Result<()> {
    let validator = POLICY_TRACE_V1_VALIDATOR
        .as_ref()
        .map_err(|error| anyhow!(error.clone()))?;
    if let Err(error) = validator.validate(value) {
        bail!("policy trace v1 schema validation failed: {error}");
    }
    Ok(())
}

pub fn validate_policy_trace_v1_json(raw: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(raw).context("invalid JSON trace line")?;
    validate_policy_trace_v1_value(&value)?;
    Ok(value)
}

mod generated {
    typify::import_types!(
        schema = "schemas/policy-trace/v1.schema.json",
        derives = [PartialEq],
        replace = {
            IpAddr = std::net::IpAddr,
            U16 = u16,
            U32 = u32,
            U64 = u64,
        }
    );
}

pub use generated::{
    PolicyTraceDroppedRecordType, PolicyTraceDroppedRecords, PolicyTraceRecord,
    PolicyTraceRecordType, TraceBanDecision, TraceBanDisposition, TraceDecisionOutput,
    TraceExemptionReason, TraceGuardrailInputs, TraceOffenceHistory, TracePeer,
    TracePeerBehaviourIdentity, TracePeerObservationIdentity, TracePeerSessionState,
    TracePolicyInputs, TraceRateBand, TraceRateBandName, TraceScorePolicyInputs,
    TraceSimulatorHints, TraceTorrent,
};

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

impl From<&PeerObservationId> for TracePeerObservationIdentity {
    fn from(value: &PeerObservationId) -> Self {
        Self {
            torrent_hash: value.torrent_hash.clone(),
            peer_ip: Some(value.peer_ip),
            peer_port: value.peer_port,
        }
    }
}

impl From<&OffenceIdentity> for TracePeerBehaviourIdentity {
    fn from(value: &OffenceIdentity) -> Self {
        Self {
            torrent_hash: value.torrent_hash.clone(),
            peer_ip: Some(value.peer_ip),
        }
    }
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

impl From<&OffenceHistory> for TraceOffenceHistory {
    fn from(value: &OffenceHistory) -> Self {
        Self {
            offence_count: value.offence_count,
            last_ban_expires_at: value.last_ban_expires_at.map(trace_timestamp),
        }
    }
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

impl From<&ExemptionReason> for TraceExemptionReason {
    fn from(value: &ExemptionReason) -> Self {
        match value {
            ExemptionReason::TorrentExcluded => Self::TorrentExcluded {
                reason_code: generated::TorrentExcludedReasonCode::TorrentExcluded,
            },
            ExemptionReason::AllowlistedPeer => Self::AllowlistedPeer {
                reason_code: generated::AllowlistedPeerReasonCode::AllowlistedPeer,
            },
            ExemptionReason::NearComplete {
                progress,
                threshold,
            } => Self::NearComplete {
                reason_code: generated::NearCompleteReasonCode::NearComplete,
                progress: *progress,
                threshold: *threshold,
            },
            ExemptionReason::NewPeerGracePeriod { age, grace_period } => Self::NewPeerGracePeriod {
                reason_code: generated::NewPeerGracePeriodReasonCode::NewPeerGracePeriod,
                age_ms: duration_millis(*age),
                grace_period_ms: duration_millis(*grace_period),
            },
            ExemptionReason::AlreadyBanned => Self::AlreadyBanned {
                reason_code: generated::AlreadyBannedReasonCode::AlreadyBanned,
            },
        }
    }
}

impl From<&BanDisposition> for TraceBanDisposition {
    fn from(value: &BanDisposition) -> Self {
        match value {
            BanDisposition::Exempt(reason) => Self::Exempt {
                disposition: generated::ExemptDisposition::Exempt,
                reason: reason.into(),
            },
            BanDisposition::NotBannableYet {
                observed_duration,
                required_observation,
                bad_duration,
                required_bad_duration,
            } => Self::NotBannableYet {
                disposition: generated::NotBannableYetDisposition::NotBannableYet,
                observed_duration_ms: duration_millis(*observed_duration),
                required_observation_ms: duration_millis(*required_observation),
                bad_duration_ms: duration_millis(*bad_duration),
                required_bad_duration_ms: duration_millis(*required_bad_duration),
            },
            BanDisposition::RebanCooldown { remaining } => Self::RebanCooldown {
                disposition: generated::RebanCooldownDisposition::RebanCooldown,
                remaining_ms: duration_millis(*remaining),
            },
            BanDisposition::DuplicateSuppressed => Self::DuplicateSuppressed {
                disposition: generated::DuplicateSuppressedDisposition::DuplicateSuppressed,
            },
            BanDisposition::Ban(decision) => Self::Ban {
                disposition: generated::BanDisposition::Ban,
                decision: decision.into(),
            },
        }
    }
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
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(json.contains(r#""record_type":"peer_observation""#));
        assert!(json.contains(r#""schema_version":1"#));
        assert!(json.contains(r#""observed_duration_ms":30000"#));
        assert!(!json.contains("SystemTime"));
        assert!(!json.contains("Duration"));
        validate_policy_trace_v1_value(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyTraceRecord>(&json).unwrap(),
            record
        );
    }

    #[test]
    fn schema_v1_fixtures_are_stable() {
        assert_fixture(
            include_str!("../testdata/policy-trace/v1-exempt-peer.json"),
            "peer_observation",
            "exempt",
        );
        assert_fixture(
            include_str!("../testdata/policy-trace/v1-not-bannable-peer.json"),
            "peer_observation",
            "not_bannable_yet",
        );
        assert_fixture(
            include_str!("../testdata/policy-trace/v1-ban-decision.json"),
            "peer_observation",
            "ban",
        );
    }

    #[test]
    fn schema_v1_replay_corpus_is_valid() {
        for line in include_str!("../testdata/policy-trace/v1-replay-corpus.jsonl").lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            validate_policy_trace_v1_value(&value).unwrap();
        }
    }

    #[test]
    fn dropped_record_notice_validates_against_schema() {
        let notice = PolicyTraceDroppedRecords {
            record_type: PolicyTraceDroppedRecordType::DroppedRecords,
            schema_version: POLICY_TRACE_SCHEMA_VERSION,
            client_id: 7,
            dropped_count: 3,
        };
        let value = serde_json::to_value(notice).unwrap();

        validate_policy_trace_v1_value(&value).unwrap();
        assert_eq!(value["record_type"], "dropped_records");
    }

    #[test]
    fn schema_v1_allows_additive_fields() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/policy-trace/v1-exempt-peer.json"))
                .unwrap();
        value["future_top_level"] = serde_json::json!("allowed");
        value["torrent"]["future_torrent_field"] = serde_json::json!({"nested": true});
        value["decision_output"]["disposition"]["future_disposition_field"] = serde_json::json!(42);

        validate_policy_trace_v1_value(&value).unwrap();
        serde_json::from_value::<PolicyTraceRecord>(value).unwrap();
    }

    fn assert_fixture(raw: &str, record_type: &str, disposition: &str) {
        let expected: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(expected["schema_version"], POLICY_TRACE_SCHEMA_VERSION);
        assert_eq!(expected["record_type"], record_type);
        assert_eq!(
            expected["decision_output"]["disposition"]["disposition"],
            disposition
        );
        validate_policy_trace_v1_value(&expected).unwrap();

        let record: PolicyTraceRecord = serde_json::from_value(expected.clone()).unwrap();
        let actual = serde_json::to_value(record).unwrap();

        assert_eq!(actual, expected);
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
