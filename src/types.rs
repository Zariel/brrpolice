#![allow(dead_code)]

use std::{
    any::Any,
    fmt::Debug,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use anyhow::{Result, bail};

pub const MAX_POLICY_DIAGNOSTICS: usize = 8;
pub const MAX_POLICY_DIAGNOSTIC_NAME_LEN: usize = 48;
pub const MAX_POLICY_DIAGNOSTIC_STRING_LEN: usize = 128;

#[derive(Debug, Clone)]
pub struct TorrentSummary {
    pub hash: String,
    pub name: String,
    pub tracker: Option<String>,
    pub total_seeders: u32,
    pub category: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TorrentScope {
    pub hash: String,
    pub name: String,
    pub tracker: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub total_seeders: u32,
    pub in_scope: bool,
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub ip: IpAddr,
    pub port: u16,
    pub progress: f64,
    pub up_rate_bps: u64,
    pub uploaded_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TorrentPeer {
    pub observation_id: PeerObservationId,
    pub peer: PeerSnapshot,
    pub client_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerObservationId {
    pub torrent_hash: String,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OffenceIdentity {
    pub torrent_hash: String,
    pub peer_ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct PeerContext {
    pub torrent: TorrentScope,
    pub peer: PeerSnapshot,
    pub first_seen_at: SystemTime,
    pub observed_at: SystemTime,
    pub has_active_ban: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerSessionState {
    pub observation_id: PeerObservationId,
    pub offence_identity: OffenceIdentity,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
    pub baseline_progress: f64,
    pub latest_progress: f64,
    pub rolling_avg_up_rate_bps: u64,
    pub observed_duration: Duration,
    pub bad_duration: Duration,
    pub ban_score: f64,
    pub ban_score_above_threshold_duration: Duration,
    pub churn_reconnect_count: u32,
    pub churn_window_started_at: Option<SystemTime>,
    pub churn_amplifier: f64,
    pub sample_count: u32,
    pub last_torrent_seeder_count: u32,
    pub last_exemption_reason: Option<ExemptionReason>,
    pub bannable_since: Option<SystemTime>,
    pub last_ban_decision_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerPolicySessionState {
    pub policy_name: String,
    pub policy_version: String,
    pub observation_id: PeerObservationId,
    pub offence_identity: OffenceIdentity,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
    pub observed_duration: Duration,
    pub bad_duration: Duration,
    pub sample_count: u32,
    pub last_uploaded_bytes: Option<u64>,
    pub last_upload_rate_bps: u64,
    pub state_json: serde_json::Value,
    pub last_exemption_reason: Option<ExemptionReason>,
    pub bannable_since: Option<SystemTime>,
    pub last_ban_decision_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerPolicyEvaluation {
    pub session: PeerPolicySessionState,
    pub sample_duration: Duration,
    pub uploaded_delta_bytes: Option<u64>,
    pub is_bad_sample: bool,
    pub is_bannable: bool,
}

pub trait PolicySessionSnapshot: Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn PolicySessionSnapshot>;
    fn first_seen_at(&self) -> SystemTime;
    fn last_seen_at(&self) -> SystemTime;
}

impl Clone for Box<dyn PolicySessionSnapshot> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait PolicyEvaluation: Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn PolicyEvaluation>;
    fn offence_identity(&self) -> &OffenceIdentity;
    fn is_bad_sample(&self) -> bool;
    fn is_bannable(&self) -> bool;
    fn bad_duration(&self) -> Duration;
    fn avg_upload_rate_bps(&self) -> u64;
    fn progress_delta_per_mille(&self) -> u32;
    fn sample_count(&self) -> u32;
}

impl Clone for Box<dyn PolicyEvaluation> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDiagnosticValue {
    Bool(bool),
    U64(u64),
    I64(i64),
    String(String),
    Duration(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDiagnostic {
    pub name: &'static str,
    pub value: PolicyDiagnosticValue,
}

#[derive(Debug, Clone)]
pub struct PeerPolicyAssessment {
    pub policy_name: &'static str,
    pub evaluation: Box<dyn PolicyEvaluation>,
    pub disposition: BanDisposition,
    pub diagnostics: Vec<PolicyDiagnostic>,
}

impl PeerPolicyAssessment {
    pub fn diagnostic_bool(&self, name: &str) -> Option<bool> {
        self.diagnostics
            .iter()
            .find(|diagnostic| diagnostic.name == name)
            .and_then(|diagnostic| match diagnostic.value {
                PolicyDiagnosticValue::Bool(value) => Some(value),
                _ => None,
            })
    }

    pub fn validate_telemetry(&self) -> Result<()> {
        if self.diagnostics.len() > MAX_POLICY_DIAGNOSTICS {
            bail!(
                "policy `{}` emitted {} diagnostics; maximum is {}",
                self.policy_name,
                self.diagnostics.len(),
                MAX_POLICY_DIAGNOSTICS
            );
        }

        for diagnostic in &self.diagnostics {
            if diagnostic.name.is_empty()
                || diagnostic.name.len() > MAX_POLICY_DIAGNOSTIC_NAME_LEN
                || !diagnostic
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                bail!(
                    "policy `{}` emitted invalid diagnostic name `{}`",
                    self.policy_name,
                    diagnostic.name
                );
            }
            if let PolicyDiagnosticValue::String(value) = &diagnostic.value
                && (value.len() > MAX_POLICY_DIAGNOSTIC_STRING_LEN
                    || value.bytes().any(|byte| byte.is_ascii_control()))
            {
                bail!(
                    "policy `{}` emitted invalid string diagnostic `{}`",
                    self.policy_name,
                    diagnostic.name
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PeerPolicyInput<'a> {
    pub peer: &'a PeerContext,
    pub previous_session: Option<&'a dyn PolicySessionSnapshot>,
    pub offence_history: &'a OffenceHistory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExemptionReason {
    TorrentExcluded,
    AllowlistedPeer,
    NearComplete {
        progress: f64,
        threshold: f64,
    },
    NewPeerGracePeriod {
        age: Duration,
        grace_period: Duration,
    },
    AlreadyBanned,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerEvaluation {
    pub session: PeerSessionState,
    pub progress_delta: f64,
    pub sample_duration: Duration,
    pub sample_up_rate_bps: u64,
    pub is_bad_sample: bool,
    pub is_bannable: bool,
    pub sample_score_risk: f64,
    pub effective_sample_score_risk: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenceHistory {
    pub offence_count: u32,
    pub last_ban_expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanDecision {
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub offence_number: u32,
    pub ttl: Duration,
    pub reason_code: String,
    pub reason_details: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BanDisposition {
    Exempt(ExemptionReason),
    NotBannableYet {
        observed_duration: Duration,
        required_observation: Duration,
        bad_duration: Duration,
        required_bad_duration: Duration,
    },
    RebanCooldown {
        remaining: Duration,
    },
    DuplicateSuppressed,
    Ban(BanDecision),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        BanDisposition, MAX_POLICY_DIAGNOSTICS, OffenceIdentity, PeerPolicyAssessment,
        PolicyDiagnostic, PolicyDiagnosticValue, PolicyEvaluation,
    };

    #[derive(Debug, Clone)]
    struct TestEvaluation {
        offence_identity: OffenceIdentity,
    }

    impl PolicyEvaluation for TestEvaluation {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn clone_box(&self) -> Box<dyn PolicyEvaluation> {
            Box::new(self.clone())
        }

        fn offence_identity(&self) -> &OffenceIdentity {
            &self.offence_identity
        }

        fn is_bad_sample(&self) -> bool {
            false
        }

        fn is_bannable(&self) -> bool {
            false
        }

        fn bad_duration(&self) -> Duration {
            Duration::ZERO
        }

        fn avg_upload_rate_bps(&self) -> u64 {
            0
        }

        fn progress_delta_per_mille(&self) -> u32 {
            0
        }

        fn sample_count(&self) -> u32 {
            0
        }
    }

    fn assessment_with(diagnostics: Vec<PolicyDiagnostic>) -> PeerPolicyAssessment {
        let peer_ip = "10.0.0.1".parse().unwrap();
        PeerPolicyAssessment {
            policy_name: "test_policy",
            evaluation: Box::new(TestEvaluation {
                offence_identity: OffenceIdentity {
                    torrent_hash: "abc123".to_string(),
                    peer_ip,
                },
            }),
            disposition: BanDisposition::DuplicateSuppressed,
            diagnostics,
        }
    }

    #[test]
    fn policy_assessment_rejects_unbounded_diagnostics() {
        let too_many = (0..=MAX_POLICY_DIAGNOSTICS)
            .map(|_| PolicyDiagnostic {
                name: "next",
                value: PolicyDiagnosticValue::Bool(false),
            })
            .collect();
        assert!(assessment_with(too_many).validate_telemetry().is_err());

        assert!(
            assessment_with(vec![PolicyDiagnostic {
                name: "Bad-Name",
                value: PolicyDiagnosticValue::Bool(false),
            }])
            .validate_telemetry()
            .is_err()
        );

        assert!(
            assessment_with(vec![PolicyDiagnostic {
                name: "summary",
                value: PolicyDiagnosticValue::String("x".repeat(129)),
            }])
            .validate_telemetry()
            .is_err()
        );
    }
}
