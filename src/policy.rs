#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use ipnet::IpNet;

use crate::{
    config::{FiltersConfig, PolicyConfig},
    metrics::AppMetrics,
    persistence::{EnforcementWriteResult, PendingBanIntentRecord, Persistence},
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity, PeerContext,
        PeerEvaluation, PeerObservationId, PeerPolicyAssessment, PeerPolicyEvaluation,
        PeerPolicyInput, PeerPolicySessionState, PeerSessionState, PolicyDiagnostic,
        PolicyDiagnosticValue, PolicyEvaluation, PolicySessionSnapshot, TorrentPeer,
        TorrentSummary,
    },
};

#[derive(Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    allowlisted_ips: HashSet<IpAddr>,
    allowlisted_cidrs: Vec<IpNet>,
}

const SCORE_BASED_REASON_CODE: &str = "score_based";
pub const SCORE_POLICY_NAME: &str = "score";
pub const RECEIVE_IDLE_POLICY_NAME: &str = "receive_idle";
const RECEIVE_IDLE_REASON_CODE: &str = "receive_idle";
const POLICY_VERSION: &str = "policy-v1";

#[async_trait::async_trait]
pub trait PolicyDataStore: Send + Sync {
    async fn get_previous_session(
        &self,
        policy_name: &str,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>>;
    async fn load_policy_offence_history(
        &self,
        policy_name: &str,
        identity: &OffenceIdentity,
    ) -> Result<OffenceHistory>;
}

#[async_trait::async_trait]
pub trait PeerPolicy: Send + Sync {
    fn name(&self) -> &'static str;
    fn metric_label(&self) -> &'static str {
        self.name()
    }
    fn reason_metric_label(&self, reason_code: &str) -> &'static str;
    async fn preload_sessions(
        &self,
        persistence: &Persistence,
        torrent_hashes: &[String],
        cache: &mut PolicyCycleCache,
    ) -> Result<()>;
    async fn load_previous_session(
        &self,
        store: &dyn PolicyDataStore,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>>;
    async fn load_offence_history(
        &self,
        store: &dyn PolicyDataStore,
        peer: &PeerContext,
    ) -> Result<OffenceHistory>;
    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment>;
    async fn persist_assessment(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
    ) -> Result<()>;
    async fn record_enforcement(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        enforced_at: SystemTime,
    ) -> Result<EnforcementWriteResult>;
    async fn record_replayed_intent(
        &self,
        persistence: &Persistence,
        intent: &PendingBanIntentRecord,
        decision: &BanDecision,
        recovered_at: SystemTime,
    ) -> Result<EnforcementWriteResult>;
    async fn validate_replay_intent(
        &self,
        _persistence: &Persistence,
        _intent: &PendingBanIntentRecord,
    ) -> Result<()> {
        Ok(())
    }
    fn pending_ban_intent(
        &self,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        torrent: &TorrentSummary,
        observed_at: SystemTime,
    ) -> PendingBanIntentRecord;
    fn record_assessment_metrics(&self, metrics: &AppMetrics, assessment: &PeerPolicyAssessment);
}

#[derive(Debug, Clone)]
struct ScoreSessionSnapshot {
    session: PeerSessionState,
}

impl PolicySessionSnapshot for ScoreSessionSnapshot {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn PolicySessionSnapshot> {
        Box::new(self.clone())
    }

    fn first_seen_at(&self) -> SystemTime {
        self.session.first_seen_at
    }

    fn last_seen_at(&self) -> SystemTime {
        self.session.last_seen_at
    }
}

#[derive(Debug, Clone)]
struct GenericSessionSnapshot {
    session: PeerPolicySessionState,
}

impl PolicySessionSnapshot for GenericSessionSnapshot {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn PolicySessionSnapshot> {
        Box::new(self.clone())
    }

    fn first_seen_at(&self) -> SystemTime {
        self.session.first_seen_at
    }

    fn last_seen_at(&self) -> SystemTime {
        self.session.last_seen_at
    }
}

fn score_session_snapshot(session: PeerSessionState) -> Box<dyn PolicySessionSnapshot> {
    Box::new(ScoreSessionSnapshot { session })
}

fn generic_session_snapshot(session: PeerPolicySessionState) -> Box<dyn PolicySessionSnapshot> {
    Box::new(GenericSessionSnapshot { session })
}

#[derive(Default)]
pub struct PolicyCycleCache {
    sessions_by_observation: HashMap<(String, PeerObservationId), Box<dyn PolicySessionSnapshot>>,
    latest_sessions_by_torrent_ip:
        HashMap<(String, String, IpAddr), Box<dyn PolicySessionSnapshot>>,
    offence_histories: HashMap<(String, OffenceIdentity), OffenceHistory>,
    batch_load_count: usize,
}

impl PolicyCycleCache {
    pub async fn load(
        persistence: &Persistence,
        policies: &[Arc<dyn PeerPolicy>],
        torrent_hashes: &[String],
    ) -> Result<Self> {
        let policy_names = policies
            .iter()
            .map(|policy| policy.name())
            .collect::<Vec<_>>();
        let mut cache = Self::default();

        for policy in policies {
            policy
                .preload_sessions(persistence, torrent_hashes, &mut cache)
                .await?;
            cache.batch_load_count += 1;
        }
        let offence_histories = persistence
            .load_policy_offence_histories_for_policy_torrents(&policy_names, torrent_hashes)
            .await?;
        cache.batch_load_count += 1;

        for record in offence_histories {
            cache
                .offence_histories
                .insert((record.policy_name, record.identity), record.history);
        }

        Ok(cache)
    }

    #[cfg(test)]
    pub fn batch_load_count(&self) -> usize {
        self.batch_load_count
    }

    fn insert_session_snapshot(
        &mut self,
        policy_name: &'static str,
        observation_id: PeerObservationId,
        last_seen_at: SystemTime,
        snapshot: Box<dyn PolicySessionSnapshot>,
    ) {
        self.sessions_by_observation.insert(
            (policy_name.to_string(), observation_id.clone()),
            snapshot.clone(),
        );
        self.latest_sessions_by_torrent_ip
            .entry((
                policy_name.to_string(),
                observation_id.torrent_hash,
                observation_id.peer_ip,
            ))
            .and_modify(|existing| {
                if last_seen_at > existing.last_seen_at() {
                    *existing = snapshot.clone();
                }
            })
            .or_insert(snapshot);
    }
}

#[async_trait::async_trait]
impl PolicyDataStore for PolicyCycleCache {
    async fn get_previous_session(
        &self,
        policy_name: &str,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>> {
        let policy_name = policy_name.to_string();
        let existing = self
            .sessions_by_observation
            .get(&(policy_name.clone(), peer.observation_id.clone()))
            .cloned();
        let carryover = if existing.is_none() {
            self.latest_sessions_by_torrent_ip
                .get(&(
                    policy_name,
                    peer.observation_id.torrent_hash.clone(),
                    peer.observation_id.peer_ip,
                ))
                .filter(|session| {
                    session_carryover_allowed(session.last_seen_at(), observed_at, decay_window)
                })
                .cloned()
        } else {
            None
        };
        Ok(existing.or(carryover))
    }

    async fn load_policy_offence_history(
        &self,
        policy_name: &str,
        identity: &OffenceIdentity,
    ) -> Result<OffenceHistory> {
        Ok(self
            .offence_histories
            .get(&(policy_name.to_string(), identity.clone()))
            .cloned()
            .unwrap_or(OffenceHistory {
                offence_count: 0,
                last_ban_expires_at: None,
            }))
    }
}

#[derive(Debug, Clone)]
struct ScoreAssessmentEvaluation {
    evaluation: PeerEvaluation,
}

impl PolicyEvaluation for ScoreAssessmentEvaluation {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn PolicyEvaluation> {
        Box::new(self.clone())
    }

    fn offence_identity(&self) -> &OffenceIdentity {
        &self.evaluation.session.offence_identity
    }

    fn is_bad_sample(&self) -> bool {
        self.evaluation.is_bad_sample
    }

    fn is_bannable(&self) -> bool {
        self.evaluation.is_bannable
    }

    fn bad_duration(&self) -> Duration {
        self.evaluation.session.bad_duration
    }

    fn avg_upload_rate_bps(&self) -> u64 {
        self.evaluation.session.rolling_avg_up_rate_bps
    }

    fn progress_delta_per_mille(&self) -> u32 {
        progress_delta_per_mille(self.evaluation.progress_delta)
    }

    fn sample_count(&self) -> u32 {
        self.evaluation.session.sample_count
    }
}

#[derive(Debug, Clone)]
struct GenericAssessmentEvaluation {
    evaluation: PeerPolicyEvaluation,
}

impl PolicyEvaluation for GenericAssessmentEvaluation {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn PolicyEvaluation> {
        Box::new(self.clone())
    }

    fn offence_identity(&self) -> &OffenceIdentity {
        &self.evaluation.session.offence_identity
    }

    fn is_bad_sample(&self) -> bool {
        self.evaluation.is_bad_sample
    }

    fn is_bannable(&self) -> bool {
        self.evaluation.is_bannable
    }

    fn bad_duration(&self) -> Duration {
        self.evaluation.session.bad_duration
    }

    fn avg_upload_rate_bps(&self) -> u64 {
        self.evaluation.session.last_upload_rate_bps
    }

    fn progress_delta_per_mille(&self) -> u32 {
        0
    }

    fn sample_count(&self) -> u32 {
        self.evaluation.session.sample_count
    }
}

fn score_evaluation(assessment: &PeerPolicyAssessment) -> Result<&PeerEvaluation> {
    assessment
        .evaluation
        .as_any()
        .downcast_ref::<ScoreAssessmentEvaluation>()
        .map(|state| &state.evaluation)
        .ok_or_else(|| anyhow::anyhow!("score assessment carried non-score state"))
}

fn generic_evaluation(assessment: &PeerPolicyAssessment) -> Result<&PeerPolicyEvaluation> {
    assessment
        .evaluation
        .as_any()
        .downcast_ref::<GenericAssessmentEvaluation>()
        .map(|state| &state.evaluation)
        .ok_or_else(|| anyhow::anyhow!("receive-idle assessment carried non-generic state"))
}

fn score_previous_session(
    previous: Option<&dyn PolicySessionSnapshot>,
) -> Result<Option<&PeerSessionState>> {
    previous
        .map(|session| {
            session
                .as_any()
                .downcast_ref::<ScoreSessionSnapshot>()
                .map(|session| &session.session)
                .ok_or_else(|| anyhow::anyhow!("score assessment carried non-score session"))
        })
        .transpose()
}

fn generic_previous_session(
    previous: Option<&dyn PolicySessionSnapshot>,
) -> Result<Option<&PeerPolicySessionState>> {
    previous
        .map(|session| {
            let session = session
                .as_any()
                .downcast_ref::<GenericSessionSnapshot>()
                .ok_or_else(|| {
                    anyhow::anyhow!("receive-idle assessment carried non-generic session")
                })?;
            validate_receive_idle_session_payload(&session.session)?;
            Ok(&session.session)
        })
        .transpose()
}

#[derive(Clone)]
struct ScorePeerPolicy {
    engine: PolicyEngine,
}

#[derive(Clone)]
struct ReceiveIdlePeerPolicy {
    engine: PolicyEngine,
}

#[async_trait::async_trait]
impl PeerPolicy for ScorePeerPolicy {
    fn name(&self) -> &'static str {
        SCORE_POLICY_NAME
    }

    fn reason_metric_label(&self, reason_code: &str) -> &'static str {
        if reason_code == SCORE_BASED_REASON_CODE {
            SCORE_BASED_REASON_CODE
        } else {
            "other"
        }
    }

    async fn preload_sessions(
        &self,
        persistence: &Persistence,
        torrent_hashes: &[String],
        cache: &mut PolicyCycleCache,
    ) -> Result<()> {
        let sessions = persistence
            .load_peer_sessions_for_torrent_hashes(torrent_hashes)
            .await?;
        for session in sessions {
            cache.insert_session_snapshot(
                self.name(),
                session.observation_id.clone(),
                session.last_seen_at,
                score_session_snapshot(session),
            );
        }
        Ok(())
    }

    async fn load_previous_session(
        &self,
        store: &dyn PolicyDataStore,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>> {
        store
            .get_previous_session(self.name(), peer, observed_at, decay_window)
            .await
    }

    async fn load_offence_history(
        &self,
        store: &dyn PolicyDataStore,
        peer: &PeerContext,
    ) -> Result<OffenceHistory> {
        let identity = self.engine.offence_identity(peer);
        store
            .load_policy_offence_history(self.name(), &identity)
            .await
    }

    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment> {
        let previous = score_previous_session(input.previous_session)?;
        let evaluation = self.engine.evaluate_peer(input.peer, previous);
        let disposition = self
            .engine
            .decide_ban(input.peer, &evaluation, input.offence_history);
        let diagnostics = vec![
            PolicyDiagnostic {
                name: "score",
                value: PolicyDiagnosticValue::String(format!(
                    "{:.4}",
                    evaluation.session.ban_score
                )),
            },
            PolicyDiagnostic {
                name: "score_bad_seconds",
                value: PolicyDiagnosticValue::Duration(
                    evaluation.session.ban_score_above_threshold_duration,
                ),
            },
            PolicyDiagnostic {
                name: "sample_risk",
                value: PolicyDiagnosticValue::String(format!(
                    "{:.4}",
                    evaluation.sample_score_risk
                )),
            },
            PolicyDiagnostic {
                name: "threshold_met",
                value: PolicyDiagnosticValue::Bool(
                    evaluation.session.ban_score >= self.engine.config.score.ban_threshold,
                ),
            },
        ];
        Ok(PeerPolicyAssessment {
            policy_name: self.name(),
            evaluation: Box::new(ScoreAssessmentEvaluation { evaluation }),
            disposition,
            diagnostics,
        })
    }

    async fn persist_assessment(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
    ) -> Result<()> {
        let evaluation = score_evaluation(assessment)?;
        persistence
            .upsert_peer_session(&evaluation.session, POLICY_VERSION)
            .await
    }

    async fn record_enforcement(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        enforced_at: SystemTime,
    ) -> Result<EnforcementWriteResult> {
        let evaluation = score_evaluation(assessment)?;
        persistence
            .record_ban_enforcement(evaluation, decision, enforced_at)
            .await
    }

    async fn record_replayed_intent(
        &self,
        persistence: &Persistence,
        intent: &PendingBanIntentRecord,
        decision: &BanDecision,
        recovered_at: SystemTime,
    ) -> Result<EnforcementWriteResult> {
        let observation_id = PeerObservationId {
            torrent_hash: intent.torrent_hash.clone(),
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
        };
        let existing_session = persistence.get_peer_session(&observation_id).await?;
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
            churn_amplifier: 0.0,
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
            effective_sample_score_risk: 0.0,
        };
        persistence
            .record_ban_enforcement(&evaluation, decision, recovered_at)
            .await
    }

    fn pending_ban_intent(
        &self,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        torrent: &TorrentSummary,
        observed_at: SystemTime,
    ) -> PendingBanIntentRecord {
        PendingBanIntentRecord {
            torrent_hash: torrent.hash.clone(),
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            policy_name: self.name().to_string(),
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

    fn record_assessment_metrics(&self, metrics: &AppMetrics, assessment: &PeerPolicyAssessment) {
        metrics.record_peer_evaluated(self.metric_label(), assessment.evaluation.is_bad_sample());
        metrics.record_policy_evaluation(self.metric_label(), assessment.evaluation.is_bannable());
        let Ok(evaluation) = score_evaluation(assessment) else {
            return;
        };
        metrics.record_score_evaluation(
            evaluation.session.ban_score,
            evaluation.sample_score_risk,
            evaluation.session.ban_score_above_threshold_duration,
            evaluation.is_bannable,
        );
    }
}

#[async_trait::async_trait]
impl PeerPolicy for ReceiveIdlePeerPolicy {
    fn name(&self) -> &'static str {
        RECEIVE_IDLE_POLICY_NAME
    }

    fn reason_metric_label(&self, reason_code: &str) -> &'static str {
        if reason_code == RECEIVE_IDLE_REASON_CODE {
            RECEIVE_IDLE_REASON_CODE
        } else {
            "other"
        }
    }

    async fn preload_sessions(
        &self,
        persistence: &Persistence,
        torrent_hashes: &[String],
        cache: &mut PolicyCycleCache,
    ) -> Result<()> {
        let sessions = persistence
            .load_peer_policy_sessions_for_policy_torrents(&[self.name()], torrent_hashes)
            .await?;
        for session in sessions {
            cache.insert_session_snapshot(
                self.name(),
                session.observation_id.clone(),
                session.last_seen_at,
                generic_session_snapshot(session),
            );
        }
        Ok(())
    }

    async fn load_previous_session(
        &self,
        store: &dyn PolicyDataStore,
        peer: &TorrentPeer,
        observed_at: SystemTime,
        decay_window: Duration,
    ) -> Result<Option<Box<dyn PolicySessionSnapshot>>> {
        store
            .get_previous_session(self.name(), peer, observed_at, decay_window)
            .await
    }

    async fn load_offence_history(
        &self,
        store: &dyn PolicyDataStore,
        peer: &PeerContext,
    ) -> Result<OffenceHistory> {
        let identity = self.engine.offence_identity(peer);
        store
            .load_policy_offence_history(self.name(), &identity)
            .await
    }

    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment> {
        let previous = generic_previous_session(input.previous_session)?;
        let evaluation = self.engine.evaluate_receive_idle_peer(input.peer, previous);
        let disposition =
            self.engine
                .decide_receive_idle_ban(input.peer, &evaluation, input.offence_history);
        let diagnostics = vec![
            PolicyDiagnostic {
                name: "idle_seconds",
                value: PolicyDiagnosticValue::Duration(evaluation.session.bad_duration),
            },
            PolicyDiagnostic {
                name: "uploaded_delta_bytes",
                value: PolicyDiagnosticValue::String(
                    evaluation
                        .uploaded_delta_bytes
                        .map(|delta| delta.to_string())
                        .unwrap_or_else(|| "missing".to_string()),
                ),
            },
            PolicyDiagnostic {
                name: "current_upload_rate_bps",
                value: PolicyDiagnosticValue::U64(evaluation.session.last_upload_rate_bps),
            },
            PolicyDiagnostic {
                name: "threshold_met",
                value: PolicyDiagnosticValue::Bool(evaluation.is_bad_sample),
            },
        ];
        Ok(PeerPolicyAssessment {
            policy_name: self.name(),
            evaluation: Box::new(GenericAssessmentEvaluation { evaluation }),
            disposition,
            diagnostics,
        })
    }

    async fn persist_assessment(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
    ) -> Result<()> {
        let evaluation = generic_evaluation(assessment)?;
        validate_receive_idle_session_payload(&evaluation.session)?;
        persistence
            .upsert_peer_policy_session(&evaluation.session, POLICY_VERSION)
            .await
    }

    async fn record_enforcement(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        enforced_at: SystemTime,
    ) -> Result<EnforcementWriteResult> {
        let evaluation = generic_evaluation(assessment)?;
        persistence
            .record_policy_ban_enforcement(evaluation, decision, enforced_at)
            .await
    }

    async fn record_replayed_intent(
        &self,
        persistence: &Persistence,
        intent: &PendingBanIntentRecord,
        decision: &BanDecision,
        recovered_at: SystemTime,
    ) -> Result<EnforcementWriteResult> {
        let observation_id = PeerObservationId {
            torrent_hash: intent.torrent_hash.clone(),
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
        };
        let existing_session = persistence
            .get_peer_policy_session(self.name(), &observation_id)
            .await?;
        if let Some(session) = existing_session.as_ref() {
            validate_receive_idle_session_payload(session)?;
        }
        let session = existing_session.unwrap_or(PeerPolicySessionState {
            policy_name: self.name().to_string(),
            policy_version: POLICY_VERSION.to_string(),
            observation_id: observation_id.clone(),
            offence_identity: OffenceIdentity {
                torrent_hash: intent.torrent_hash.clone(),
                peer_ip: intent.peer_ip,
            },
            first_seen_at: intent.observed_at,
            last_seen_at: intent.observed_at,
            observed_duration: intent.bad_duration,
            bad_duration: intent.bad_duration,
            sample_count: 1,
            last_uploaded_bytes: None,
            last_upload_rate_bps: intent.avg_up_rate_bps,
            state_json: serde_json::json!({}),
            last_exemption_reason: None,
            bannable_since: Some(intent.observed_at),
            last_ban_decision_at: None,
        });
        let evaluation = PeerPolicyEvaluation {
            session,
            sample_duration: intent.bad_duration,
            uploaded_delta_bytes: Some(0),
            is_bad_sample: true,
            is_bannable: true,
        };
        persistence
            .record_policy_ban_enforcement(&evaluation, decision, recovered_at)
            .await
    }

    async fn validate_replay_intent(
        &self,
        persistence: &Persistence,
        intent: &PendingBanIntentRecord,
    ) -> Result<()> {
        let observation_id = PeerObservationId {
            torrent_hash: intent.torrent_hash.clone(),
            peer_ip: intent.peer_ip,
            peer_port: intent.peer_port,
        };
        if let Some(session) = persistence
            .get_peer_policy_session(self.name(), &observation_id)
            .await?
        {
            validate_receive_idle_session_payload(&session)?;
        }
        Ok(())
    }

    fn pending_ban_intent(
        &self,
        assessment: &PeerPolicyAssessment,
        decision: &BanDecision,
        torrent: &TorrentSummary,
        observed_at: SystemTime,
    ) -> PendingBanIntentRecord {
        PendingBanIntentRecord {
            torrent_hash: torrent.hash.clone(),
            peer_ip: decision.peer_ip,
            peer_port: decision.peer_port,
            policy_name: self.name().to_string(),
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

    fn record_assessment_metrics(&self, metrics: &AppMetrics, assessment: &PeerPolicyAssessment) {
        metrics.record_peer_evaluated(self.metric_label(), assessment.evaluation.is_bad_sample());
        metrics.record_policy_evaluation(self.metric_label(), assessment.evaluation.is_bannable());
    }
}

impl PolicyEngine {
    pub fn new(mut config: PolicyConfig, filters: &FiltersConfig) -> Self {
        config.apply_legacy_score_aliases();
        let allowlisted_ips = filters
            .allowlist_peer_ips
            .iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
            .collect();
        let allowlisted_cidrs = filters
            .allowlist_peer_cidrs
            .iter()
            .filter_map(|value| value.parse::<IpNet>().ok())
            .collect();

        Self {
            config,
            allowlisted_ips,
            allowlisted_cidrs,
        }
    }

    pub fn peer_observation_id(&self, peer: &PeerContext) -> PeerObservationId {
        PeerObservationId {
            torrent_hash: peer.torrent.hash.clone(),
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
        }
    }

    pub fn enabled_peer_policies(&self) -> Vec<Arc<dyn PeerPolicy>> {
        let mut policies: Vec<Arc<dyn PeerPolicy>> = Vec::new();
        if self.config.score.enabled {
            policies.push(Arc::new(ScorePeerPolicy {
                engine: self.clone(),
            }));
        }
        if self.config.receive_idle.enabled {
            policies.push(Arc::new(ReceiveIdlePeerPolicy {
                engine: self.clone(),
            }));
        }
        policies
    }

    pub fn replay_peer_policies(&self) -> Vec<Arc<dyn PeerPolicy>> {
        vec![
            Arc::new(ScorePeerPolicy {
                engine: self.clone(),
            }),
            Arc::new(ReceiveIdlePeerPolicy {
                engine: self.clone(),
            }),
        ]
    }

    pub fn offence_identity(&self, peer: &PeerContext) -> OffenceIdentity {
        OffenceIdentity {
            torrent_hash: peer.torrent.hash.clone(),
            peer_ip: peer.peer.ip,
        }
    }

    pub fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        if !peer.torrent.in_scope {
            return Some(ExemptionReason::TorrentExcluded);
        }

        if self.is_allowlisted(peer.peer.ip) {
            return Some(ExemptionReason::AllowlistedPeer);
        }

        if peer.peer.progress >= self.config.ignore_peer_progress_at_or_above {
            return Some(ExemptionReason::NearComplete {
                progress: peer.peer.progress,
                threshold: self.config.ignore_peer_progress_at_or_above,
            });
        }

        if self.is_within_grace_period(peer.first_seen_at, peer.observed_at) {
            return Some(ExemptionReason::NewPeerGracePeriod {
                age: peer
                    .observed_at
                    .duration_since(peer.first_seen_at)
                    .unwrap_or_default(),
                grace_period: self.config.new_peer_grace_period,
            });
        }

        if peer.has_active_ban {
            return Some(ExemptionReason::AlreadyBanned);
        }

        None
    }

    pub fn ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        self.score_ban_ttl_for_offence(offence_number)
    }

    fn score_ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        ban_ttl_from_ladder(&self.config.score.ban_ladder.durations, offence_number)
    }

    fn receive_idle_ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        ban_ttl_from_ladder(
            &self.config.receive_idle.ban_ladder.durations,
            offence_number,
        )
    }

    pub fn begin_session(
        &self,
        peer: &PeerContext,
        carryover: Option<&PeerSessionState>,
    ) -> PeerSessionState {
        let observation_id = self.peer_observation_id(peer);
        let offence_identity = self.offence_identity(peer);
        let mut session = PeerSessionState {
            observation_id: observation_id.clone(),
            offence_identity: offence_identity.clone(),
            first_seen_at: peer.first_seen_at,
            last_seen_at: peer.observed_at,
            baseline_progress: peer.peer.progress,
            latest_progress: peer.peer.progress,
            rolling_avg_up_rate_bps: peer.peer.up_rate_bps,
            observed_duration: peer
                .observed_at
                .duration_since(peer.first_seen_at)
                .unwrap_or_default(),
            bad_duration: Duration::ZERO,
            ban_score: 0.0,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_amplifier: 0.0,
            sample_count: 1,
            last_torrent_seeder_count: peer.torrent.total_seeders,
            last_exemption_reason: self.classify_exemption(peer),
            bannable_since: None,
            last_ban_decision_at: None,
        };

        if let Some(previous) = carryover.filter(|previous| {
            self.can_carry_over(previous, &observation_id, &offence_identity, peer)
        }) {
            let gap = peer
                .observed_at
                .duration_since(previous.last_seen_at)
                .unwrap_or_default();
            // Carry-over preserves identity across reconnects on a new peer port so we
            // don't reset behaviour history when a client churns endpoints.
            session.first_seen_at = previous.first_seen_at;
            session.baseline_progress = previous.baseline_progress.min(peer.peer.progress);
            session.rolling_avg_up_rate_bps = previous.rolling_avg_up_rate_bps;
            session.observed_duration = previous.observed_duration;
            session.bad_duration = self.decay_bad_duration(previous.bad_duration, gap);
            session.ban_score = self.decay_score(previous.ban_score, gap);
            session.ban_score_above_threshold_duration =
                if session.ban_score >= self.config.score.ban_threshold {
                    previous
                        .ban_score_above_threshold_duration
                        .saturating_sub(gap)
                } else {
                    Duration::ZERO
                };
            let reconnect = previous.observation_id != observation_id;
            let (churn_reconnect_count, churn_window_started_at, churn_amplifier) = self
                .update_churn_state(
                    previous,
                    peer.observed_at,
                    gap,
                    reconnect,
                    false,
                    session.last_exemption_reason.is_none(),
                );
            session.churn_reconnect_count = churn_reconnect_count;
            session.churn_window_started_at = churn_window_started_at;
            session.churn_amplifier = churn_amplifier;
            session.sample_count = previous.sample_count + 1;
            session.last_exemption_reason = self.classify_exemption(peer);
            session.bannable_since = previous.bannable_since;
            session.last_ban_decision_at = previous.last_ban_decision_at;
        }

        session
    }

    pub fn evaluate_peer(
        &self,
        peer: &PeerContext,
        existing: Option<&PeerSessionState>,
    ) -> PeerEvaluation {
        if existing.is_none() {
            let mut session = self.begin_session(peer, None);
            let sample_duration = peer
                .observed_at
                .duration_since(peer.first_seen_at)
                .unwrap_or_default();
            let observed_duration = session.observed_duration;
            let progress_delta = (peer.peer.progress - session.baseline_progress).max(0.0);
            let required_progress_delta =
                self.required_progress_delta(observed_duration, peer.peer.up_rate_bps);
            let exemption = session.last_exemption_reason.clone();
            let score_sample_active = self.score_sample_is_upload_active(peer);
            let score_sample_eligible = exemption.is_none() && score_sample_active;
            let is_bad_sample = score_sample_eligible
                && peer.peer.up_rate_bps < self.config.score.target_rate_bps
                && progress_delta < required_progress_delta;
            if is_bad_sample {
                session.bad_duration = sample_duration;
            }
            let sample_score_risk = if score_sample_eligible {
                self.sample_score_risk(
                    peer.peer.up_rate_bps,
                    progress_delta,
                    required_progress_delta,
                )
            } else {
                0.0
            };
            let effective_sample_score_risk =
                self.effective_sample_score_risk(sample_score_risk, session.churn_amplifier);
            if !score_sample_eligible {
                session.ban_score_above_threshold_duration = Duration::ZERO;
            } else {
                session.ban_score = (session.ban_score + effective_sample_score_risk)
                    .clamp(0.0, self.config.score.max_score);
                if session.ban_score >= self.config.score.ban_threshold {
                    session.ban_score_above_threshold_duration = sample_duration;
                }
            }
            session.churn_amplifier = 0.0;

            let is_bannable = self.is_bannable(&session, score_sample_eligible);
            if is_bannable {
                session.bannable_since = Some(peer.observed_at);
            }

            return PeerEvaluation {
                session,
                progress_delta,
                sample_duration,
                sample_up_rate_bps: peer.peer.up_rate_bps,
                is_bad_sample,
                is_bannable,
                sample_score_risk,
                effective_sample_score_risk,
            };
        }

        let previous = existing
            .cloned()
            .unwrap_or_else(|| self.begin_session(peer, None));

        let sample_duration = peer
            .observed_at
            .duration_since(previous.last_seen_at)
            .unwrap_or_default();
        let observed_duration = previous.observed_duration + sample_duration;
        let baseline_progress = self.advance_progress_baseline(
            previous.baseline_progress,
            previous.latest_progress,
            sample_duration,
        );
        let progress_delta = (peer.peer.progress - baseline_progress).max(0.0);
        let required_progress_delta =
            self.required_progress_delta(observed_duration, peer.peer.up_rate_bps);
        let exemption = self.classify_exemption(peer);
        let score_sample_active = self.score_sample_is_upload_active(peer);
        let score_sample_eligible = exemption.is_none() && score_sample_active;
        let is_bad_sample = score_sample_eligible
            && peer.peer.up_rate_bps < self.config.score.target_rate_bps
            && progress_delta < required_progress_delta;
        let reconnect = previous.observation_id != self.peer_observation_id(peer);
        let bad_duration = if is_bad_sample {
            previous.bad_duration + sample_duration
        } else {
            self.decay_bad_duration(previous.bad_duration, sample_duration)
        };
        let mut ban_score = self.decay_score(previous.ban_score, sample_duration);
        let mut ban_score_above_threshold_duration = previous.ban_score_above_threshold_duration;
        let sample_score_risk = if score_sample_eligible {
            self.sample_score_risk(
                peer.peer.up_rate_bps,
                progress_delta,
                required_progress_delta,
            )
        } else {
            0.0
        };
        let (churn_reconnect_count, churn_window_started_at, churn_amplifier) = self
            .update_churn_state(
                &previous,
                peer.observed_at,
                sample_duration,
                reconnect,
                is_bad_sample,
                score_sample_eligible,
            );
        let effective_sample_score_risk =
            self.effective_sample_score_risk(sample_score_risk, churn_amplifier);
        if !score_sample_eligible {
            ban_score_above_threshold_duration = Duration::ZERO;
        } else {
            ban_score =
                (ban_score + effective_sample_score_risk).clamp(0.0, self.config.score.max_score);
            if ban_score >= self.config.score.ban_threshold {
                ban_score_above_threshold_duration += sample_duration;
            } else if ban_score <= self.config.score.clear_threshold {
                ban_score_above_threshold_duration = Duration::ZERO;
            }
        }

        let is_bannable = self.is_bannable_with_metrics(
            observed_duration,
            ban_score_above_threshold_duration,
            score_sample_eligible,
        );
        let bannable_since = if is_bannable {
            previous.bannable_since.or(Some(peer.observed_at))
        } else {
            None
        };
        let last_ban_decision_at = if is_bannable {
            previous.last_ban_decision_at
        } else {
            None
        };

        let session = PeerSessionState {
            observation_id: self.peer_observation_id(peer),
            offence_identity: self.offence_identity(peer),
            first_seen_at: previous.first_seen_at,
            last_seen_at: peer.observed_at,
            baseline_progress,
            latest_progress: peer.peer.progress,
            rolling_avg_up_rate_bps: self.weighted_rate(
                previous.rolling_avg_up_rate_bps,
                previous.observed_duration,
                peer.peer.up_rate_bps,
                sample_duration,
            ),
            observed_duration,
            bad_duration,
            ban_score,
            ban_score_above_threshold_duration,
            churn_reconnect_count,
            churn_window_started_at,
            churn_amplifier,
            sample_count: previous.sample_count + 1,
            last_torrent_seeder_count: peer.torrent.total_seeders,
            last_exemption_reason: exemption.clone(),
            bannable_since,
            last_ban_decision_at,
        };

        PeerEvaluation {
            session,
            progress_delta,
            sample_duration,
            sample_up_rate_bps: peer.peer.up_rate_bps,
            is_bad_sample,
            is_bannable,
            sample_score_risk,
            effective_sample_score_risk,
        }
    }

    pub fn decide_ban(
        &self,
        peer: &PeerContext,
        evaluation: &PeerEvaluation,
        history: &OffenceHistory,
    ) -> BanDisposition {
        if let Some(exemption) = evaluation.session.last_exemption_reason.clone() {
            return BanDisposition::Exempt(exemption);
        }

        if !evaluation.is_bannable {
            return BanDisposition::NotBannableYet {
                observed_duration: evaluation.session.observed_duration,
                required_observation: self.config.score.min_observation_duration,
                bad_duration: evaluation.session.ban_score_above_threshold_duration,
                required_bad_duration: self.config.score.sustain_duration,
            };
        }

        if let Some(remaining) =
            self.remaining_reban_cooldown(history.last_ban_expires_at, peer.observed_at)
        {
            return BanDisposition::RebanCooldown { remaining };
        }

        if evaluation.session.last_ban_decision_at.is_some() {
            return BanDisposition::DuplicateSuppressed;
        }

        let offence_number = history.offence_count + 1;
        let reason_code = SCORE_BASED_REASON_CODE.to_string();
        let required_progress_delta = self.required_progress_delta(
            evaluation.session.observed_duration,
            evaluation.session.rolling_avg_up_rate_bps,
        );
        let rate_risk = normalized_rate_risk(
            evaluation.sample_up_rate_bps,
            self.config.score.target_rate_bps,
        );
        let progress_risk =
            normalized_progress_risk(evaluation.progress_delta, required_progress_delta);
        let factors = self.reason_factors(rate_risk, progress_risk, evaluation);
        let reason_details = format!(
            "score peer: factors={} score={:.4} sample_risk={:.4} effective_sample_risk={:.4} rate_risk={:.4} progress_risk={:.4} avg_up_rate_bps={} progress_delta={:.4} required_progress_delta={:.4} score_above_seconds={} observed_seconds={} reconnects={} churn_amplifier={:.4} samples={}",
            factors,
            evaluation.session.ban_score,
            evaluation.sample_score_risk,
            evaluation.effective_sample_score_risk,
            rate_risk,
            progress_risk,
            evaluation.session.rolling_avg_up_rate_bps,
            evaluation.progress_delta,
            required_progress_delta,
            evaluation
                .session
                .ban_score_above_threshold_duration
                .as_secs(),
            evaluation.session.observed_duration.as_secs(),
            evaluation.session.churn_reconnect_count,
            evaluation.session.churn_amplifier,
            evaluation.session.sample_count
        );

        BanDisposition::Ban(BanDecision {
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
            offence_number,
            ttl: self.ban_ttl_for_offence(offence_number),
            reason_code,
            reason_details,
        })
    }

    pub fn record_ban_decision(
        &self,
        session: &PeerSessionState,
        decided_at: SystemTime,
    ) -> PeerSessionState {
        let mut updated = session.clone();
        updated.last_ban_decision_at = Some(decided_at);
        updated
    }

    pub fn begin_receive_idle_session(
        &self,
        peer: &PeerContext,
        carryover: Option<&PeerPolicySessionState>,
    ) -> PeerPolicySessionState {
        let observation_id = self.peer_observation_id(peer);
        let offence_identity = self.offence_identity(peer);
        let mut session = PeerPolicySessionState {
            policy_name: RECEIVE_IDLE_POLICY_NAME.to_string(),
            policy_version: POLICY_VERSION.to_string(),
            observation_id: observation_id.clone(),
            offence_identity: offence_identity.clone(),
            first_seen_at: peer.first_seen_at,
            last_seen_at: peer.observed_at,
            observed_duration: peer
                .observed_at
                .duration_since(peer.first_seen_at)
                .unwrap_or_default(),
            bad_duration: Duration::ZERO,
            sample_count: 1,
            last_uploaded_bytes: peer.peer.uploaded_bytes,
            last_upload_rate_bps: peer.peer.up_rate_bps,
            state_json: serde_json::json!({}),
            last_exemption_reason: self.classify_exemption(peer),
            bannable_since: None,
            last_ban_decision_at: None,
        };

        if let Some(previous) = carryover.filter(|previous| {
            previous.policy_name == RECEIVE_IDLE_POLICY_NAME
                && (self.can_continue_policy_session(
                    previous,
                    &observation_id,
                    &offence_identity,
                    peer,
                ) || self.can_carry_over_policy(
                    previous,
                    &observation_id,
                    &offence_identity,
                    peer,
                ))
        }) {
            let sample_duration = peer
                .observed_at
                .duration_since(previous.last_seen_at)
                .unwrap_or_default();
            session.first_seen_at = previous.first_seen_at;
            session.observed_duration = previous.observed_duration + sample_duration;
            session.bad_duration = previous.bad_duration;
            session.sample_count = previous.sample_count + 1;
            session.bannable_since = previous.bannable_since;
            session.last_ban_decision_at = previous.last_ban_decision_at;
        }

        session
    }

    pub fn evaluate_receive_idle_peer(
        &self,
        peer: &PeerContext,
        existing: Option<&PeerPolicySessionState>,
    ) -> PeerPolicyEvaluation {
        let observation_id = self.peer_observation_id(peer);
        let offence_identity = self.offence_identity(peer);
        let previous = existing
            .filter(|previous| {
                previous.policy_name == RECEIVE_IDLE_POLICY_NAME
                    && (self.can_continue_receive_idle_session(
                        previous,
                        &observation_id,
                        &offence_identity,
                        peer,
                    ) || self.can_carry_over_receive_idle_session(
                        previous,
                        &observation_id,
                        &offence_identity,
                        peer,
                    ))
            })
            .cloned();
        let mut session = self.begin_receive_idle_session(peer, previous.as_ref());
        let sample_duration = previous
            .as_ref()
            .map(|previous| {
                peer.observed_at
                    .duration_since(previous.last_seen_at)
                    .unwrap_or_default()
            })
            .unwrap_or_else(|| {
                peer.observed_at
                    .duration_since(peer.first_seen_at)
                    .unwrap_or_default()
            });
        let uploaded_delta_bytes = previous.as_ref().and_then(|previous| {
            match (previous.last_uploaded_bytes, peer.peer.uploaded_bytes) {
                (Some(previous_uploaded), Some(current_uploaded))
                    if current_uploaded >= previous_uploaded =>
                {
                    Some(current_uploaded - previous_uploaded)
                }
                _ => None,
            }
        });
        let exemption = self.classify_exemption(peer);
        let is_bad_sample = self.config.receive_idle.enabled
            && exemption.is_none()
            && peer.peer.up_rate_bps <= self.config.receive_idle.max_upload_rate_bps
            && uploaded_delta_bytes
                .is_some_and(|delta| delta <= self.config.receive_idle.max_uploaded_delta_bytes);

        session.last_seen_at = peer.observed_at;
        session.last_uploaded_bytes = peer.peer.uploaded_bytes;
        session.last_upload_rate_bps = peer.peer.up_rate_bps;
        session.last_exemption_reason = exemption;
        session.bad_duration = if is_bad_sample {
            session.bad_duration + sample_duration
        } else {
            Duration::ZERO
        };

        let is_bannable = self.config.receive_idle.enabled
            && session.last_exemption_reason.is_none()
            && session.observed_duration >= self.config.receive_idle.min_observation_duration
            && session.bad_duration >= self.config.receive_idle.sustain_duration;
        session.bannable_since = if is_bannable {
            session.bannable_since.or(Some(peer.observed_at))
        } else {
            None
        };
        if !is_bannable {
            session.last_ban_decision_at = None;
        }

        PeerPolicyEvaluation {
            session,
            sample_duration,
            uploaded_delta_bytes,
            is_bad_sample,
            is_bannable,
        }
    }

    pub fn decide_receive_idle_ban(
        &self,
        peer: &PeerContext,
        evaluation: &PeerPolicyEvaluation,
        history: &OffenceHistory,
    ) -> BanDisposition {
        if let Some(exemption) = evaluation.session.last_exemption_reason.clone() {
            return BanDisposition::Exempt(exemption);
        }

        if !evaluation.is_bannable {
            return BanDisposition::NotBannableYet {
                observed_duration: evaluation.session.observed_duration,
                required_observation: self.config.receive_idle.min_observation_duration,
                bad_duration: evaluation.session.bad_duration,
                required_bad_duration: self.config.receive_idle.sustain_duration,
            };
        }

        if let Some(remaining) = self
            .remaining_receive_idle_reban_cooldown(history.last_ban_expires_at, peer.observed_at)
        {
            return BanDisposition::RebanCooldown { remaining };
        }

        if evaluation.session.last_ban_decision_at.is_some() {
            return BanDisposition::DuplicateSuppressed;
        }

        let offence_number = history.offence_count + 1;
        let ttl = self.receive_idle_ban_ttl_for_offence(offence_number);
        let reason_details = format!(
            "receive idle peer: idle_seconds={} observed_seconds={} up_rate_bps={} uploaded_delta_bytes={} samples={} selected_ttl_seconds={}",
            evaluation.session.bad_duration.as_secs(),
            evaluation.session.observed_duration.as_secs(),
            peer.peer.up_rate_bps,
            evaluation
                .uploaded_delta_bytes
                .map(|delta| delta.to_string())
                .unwrap_or_else(|| "missing".to_string()),
            evaluation.session.sample_count,
            ttl.as_secs(),
        );

        BanDisposition::Ban(BanDecision {
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
            offence_number,
            ttl,
            reason_code: RECEIVE_IDLE_REASON_CODE.to_string(),
            reason_details,
        })
    }

    pub fn evaluate(&self) -> Vec<BanDecision> {
        Vec::new()
    }

    fn is_allowlisted(&self, ip: IpAddr) -> bool {
        self.allowlisted_ips.contains(&ip)
            || self.allowlisted_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }

    fn is_within_grace_period(&self, first_seen_at: SystemTime, observed_at: SystemTime) -> bool {
        observed_at
            .duration_since(first_seen_at)
            .unwrap_or_default()
            < self.config.new_peer_grace_period
    }

    fn can_carry_over(
        &self,
        previous: &PeerSessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        previous.observation_id != *observation_id
            && previous.observation_id.torrent_hash == observation_id.torrent_hash
            && previous.offence_identity == *offence_identity
            && peer.observed_at >= previous.last_seen_at
            && peer
                .observed_at
                .duration_since(previous.last_seen_at)
                .unwrap_or_default()
                <= self.config.decay_window
    }

    fn can_carry_over_policy(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        previous.observation_id != *observation_id
            && previous.observation_id.torrent_hash == observation_id.torrent_hash
            && previous.offence_identity == *offence_identity
            && peer.observed_at >= previous.last_seen_at
            && peer
                .observed_at
                .duration_since(previous.last_seen_at)
                .unwrap_or_default()
                <= self.config.decay_window
    }

    fn can_carry_over_receive_idle_session(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        self.can_carry_over_policy(previous, observation_id, offence_identity, peer)
            && self.policy_session_gap(previous, peer) <= self.config.receive_idle.sustain_duration
    }

    fn can_continue_policy_session(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        previous.observation_id == *observation_id
            && previous.offence_identity == *offence_identity
            && peer.observed_at >= previous.last_seen_at
    }

    fn can_continue_receive_idle_session(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        self.can_continue_policy_session(previous, observation_id, offence_identity, peer)
            && self.policy_session_gap(previous, peer) <= self.config.receive_idle.sustain_duration
    }

    fn policy_session_gap(
        &self,
        previous: &PeerPolicySessionState,
        peer: &PeerContext,
    ) -> Duration {
        peer.observed_at
            .duration_since(previous.last_seen_at)
            .unwrap_or_default()
    }

    fn decay_bad_duration(&self, bad_duration: Duration, elapsed: Duration) -> Duration {
        if bad_duration.is_zero() || elapsed.is_zero() {
            return bad_duration;
        }

        // bad_duration decays on inactivity so stale poor behaviour does not keep a peer
        // bannable forever; sustain_duration controls how quickly we forget it.
        let decay_ratio = self.config.score.sustain_duration.as_secs_f64()
            / self.config.decay_window.as_secs_f64();
        let decay = elapsed.mul_f64(decay_ratio);
        bad_duration.saturating_sub(decay)
    }

    fn decay_score(&self, score: f64, elapsed: Duration) -> f64 {
        self.decay_value(score, elapsed, self.config.score.decay_per_second)
    }

    fn decay_value(&self, value: f64, elapsed: Duration, decay_per_second: f64) -> f64 {
        if elapsed.is_zero() || value <= 0.0 || decay_per_second <= 0.0 {
            return value;
        }
        let decay = decay_per_second * elapsed.as_secs_f64();
        (value - decay).max(0.0)
    }

    fn update_churn_state(
        &self,
        previous: &PeerSessionState,
        observed_at: SystemTime,
        elapsed: Duration,
        reconnect: bool,
        is_bad_sample: bool,
        exemption_free: bool,
    ) -> (u32, Option<SystemTime>, f64) {
        if !self.config.score.churn.enabled {
            return (0, None, 0.0);
        }

        let churn = &self.config.score.churn;
        let mut reconnect_count = previous.churn_reconnect_count;
        let mut window_started_at = previous.churn_window_started_at;
        let mut amplifier =
            self.decay_value(previous.churn_amplifier, elapsed, churn.decay_per_second);

        if let Some(started_at) = window_started_at
            && observed_at.duration_since(started_at).unwrap_or_default() > churn.reconnect_window
        {
            reconnect_count = 0;
            window_started_at = None;
        }

        if reconnect {
            match window_started_at {
                Some(started_at)
                    if observed_at.duration_since(started_at).unwrap_or_default()
                        <= churn.reconnect_window =>
                {
                    reconnect_count = reconnect_count.saturating_add(1);
                }
                _ => {
                    reconnect_count = 1;
                    window_started_at = Some(observed_at);
                }
            }
        }

        if !exemption_free {
            return (reconnect_count, window_started_at, 0.0);
        }

        // Churn only amplifies already-bad samples. Reconnects by themselves are common for
        // healthy peers and should not become an independent ban engine.
        if is_bad_sample && reconnect_count >= churn.min_reconnects {
            let reconnect_excess = reconnect_count - churn.min_reconnects + 1;
            let reconnect_factor =
                (reconnect_excess as f64 / churn.min_reconnects as f64).clamp(0.0, 1.0);
            let increment = churn.max_amplifier * reconnect_factor;
            amplifier = (amplifier + increment).clamp(0.0, churn.max_amplifier);
        }

        (reconnect_count, window_started_at, amplifier)
    }

    fn required_progress_delta(&self, observed_duration: Duration, up_rate_bps: u64) -> f64 {
        if observed_duration.is_zero() || self.config.score.required_progress_delta <= 0.0 {
            return 0.0;
        }

        let sustain_secs = self.config.score.sustain_duration.as_secs_f64();
        if sustain_secs <= 0.0 {
            return self.config.score.required_progress_delta
                * self.progress_rate_scale(up_rate_bps);
        }

        let observed_secs = observed_duration.as_secs_f64();
        let ramp = (observed_secs / sustain_secs).clamp(0.0, 1.0);
        self.config.score.required_progress_delta * ramp * self.progress_rate_scale(up_rate_bps)
    }

    fn progress_rate_scale(&self, up_rate_bps: u64) -> f64 {
        let target_rate_bps = self.config.score.target_rate_bps;
        if target_rate_bps == 0 {
            return 1.0;
        }

        let ratio = up_rate_bps as f64 / target_rate_bps as f64;
        let start = self.config.score.progress_rate_scale_start;
        let end = self.config.score.progress_rate_scale_end;
        let min_scale = self.config.score.progress_rate_min_scale;

        if ratio <= start {
            return 1.0;
        }
        if ratio >= end || end <= start {
            return min_scale;
        }

        let progress = ((ratio - start) / (end - start)).clamp(0.0, 1.0);
        1.0 - ((1.0 - min_scale) * progress)
    }

    fn advance_progress_baseline(
        &self,
        baseline_progress: f64,
        latest_progress: f64,
        elapsed: Duration,
    ) -> f64 {
        if elapsed.is_zero() || latest_progress <= baseline_progress {
            return baseline_progress.min(latest_progress);
        }

        // Move the baseline toward latest progress over sustain_duration. This prevents
        // one early burst of progress from permanently masking later stagnation.
        let sustain_secs = self.config.score.sustain_duration.as_secs_f64();
        if sustain_secs <= 0.0 {
            return latest_progress;
        }

        let elapsed_secs = elapsed.as_secs_f64();
        let shift = (elapsed_secs / sustain_secs).clamp(0.0, 1.0);
        (baseline_progress + ((latest_progress - baseline_progress) * shift)).clamp(0.0, 1.0)
    }

    fn weighted_rate(
        &self,
        previous_rate: u64,
        previous_duration: Duration,
        sample_rate: u64,
        sample_duration: Duration,
    ) -> u64 {
        if sample_duration.is_zero() {
            return previous_rate.max(sample_rate);
        }
        if previous_duration.is_zero() {
            return sample_rate;
        }

        let previous_weight = previous_duration.as_secs_f64();
        let sample_weight = sample_duration.as_secs_f64();
        ((((previous_rate as f64) * previous_weight) + ((sample_rate as f64) * sample_weight))
            / (previous_weight + sample_weight))
            .round() as u64
    }

    fn is_bannable(&self, session: &PeerSessionState, exemption_free: bool) -> bool {
        self.is_bannable_with_metrics(
            session.observed_duration,
            session.ban_score_above_threshold_duration,
            exemption_free,
        )
    }

    fn is_bannable_with_metrics(
        &self,
        observed_duration: Duration,
        score_above_threshold_duration: Duration,
        exemption_free: bool,
    ) -> bool {
        if !exemption_free {
            return false;
        }
        observed_duration >= self.config.score.min_observation_duration
            && score_above_threshold_duration >= self.config.score.sustain_duration
    }

    fn sample_score_risk(
        &self,
        up_rate_bps: u64,
        progress_delta: f64,
        required_progress_delta: f64,
    ) -> f64 {
        let rate_risk = normalized_rate_risk(up_rate_bps, self.config.score.target_rate_bps);
        let progress_risk = normalized_progress_risk(progress_delta, required_progress_delta);
        let weight_total = self.config.score.weight_rate + self.config.score.weight_progress;
        if weight_total <= 0.0 {
            return 0.0;
        }

        let weighted_risk = ((self.config.score.weight_rate * rate_risk)
            + (self.config.score.weight_progress * progress_risk))
            / weight_total;
        let floor_risk = (self.config.score.rate_risk_floor * rate_risk).clamp(0.0, 1.0);

        weighted_risk.max(floor_risk)
    }

    fn effective_sample_score_risk(&self, sample_score_risk: f64, churn_amplifier: f64) -> f64 {
        if sample_score_risk <= 0.0 {
            return 0.0;
        }

        sample_score_risk * (1.0 + churn_amplifier.max(0.0))
    }

    fn score_sample_is_upload_active(&self, peer: &PeerContext) -> bool {
        peer.peer.up_rate_bps > 0
    }

    fn remaining_reban_cooldown(
        &self,
        last_ban_expires_at: Option<SystemTime>,
        observed_at: SystemTime,
    ) -> Option<Duration> {
        remaining_reban_cooldown(
            last_ban_expires_at,
            observed_at,
            self.config.score.reban_cooldown,
        )
    }

    fn remaining_receive_idle_reban_cooldown(
        &self,
        last_ban_expires_at: Option<SystemTime>,
        observed_at: SystemTime,
    ) -> Option<Duration> {
        remaining_reban_cooldown(
            last_ban_expires_at,
            observed_at,
            self.config.receive_idle.reban_cooldown,
        )
    }

    fn reason_factors(
        &self,
        rate_risk: f64,
        progress_risk: f64,
        evaluation: &PeerEvaluation,
    ) -> String {
        let mut factors = Vec::new();

        if rate_risk >= 0.75 {
            factors.push("severe_rate_deficit");
        } else if rate_risk >= 0.5 {
            factors.push("rate_deficit");
        }

        if progress_risk >= 0.75 {
            factors.push("severe_progress_deficit");
        } else if progress_risk >= 0.5 {
            factors.push("progress_deficit");
        }

        if self.config.score.churn.enabled
            && evaluation.session.churn_reconnect_count >= self.config.score.churn.min_reconnects
            && evaluation.session.churn_amplifier > 0.0
        {
            factors.push("reconnect_churn");
        }

        if factors.is_empty() {
            factors.push("composite_risk");
        }

        factors.join(",")
    }
}

fn session_carryover_allowed(
    last_seen_at: SystemTime,
    observed_at: SystemTime,
    decay_window: Duration,
) -> bool {
    observed_at >= last_seen_at
        && observed_at.duration_since(last_seen_at).unwrap_or_default() <= decay_window
}

fn progress_delta_per_mille(progress_delta: f64) -> u32 {
    if !progress_delta.is_finite() || progress_delta <= 0.0 {
        return 0;
    }

    (progress_delta * 1000.0)
        .round()
        .clamp(0.0, u32::MAX as f64) as u32
}

fn ban_ttl_from_ladder(durations: &[Duration], offence_number: u32) -> Duration {
    let index = offence_number.saturating_sub(1) as usize;
    durations
        .get(index)
        .copied()
        .unwrap_or_else(|| *durations.last().expect("ban ladder validated"))
}

fn remaining_reban_cooldown(
    last_ban_expires_at: Option<SystemTime>,
    observed_at: SystemTime,
    cooldown: Duration,
) -> Option<Duration> {
    let expiry = last_ban_expires_at?;
    let elapsed = observed_at.duration_since(expiry).unwrap_or_default();
    if elapsed >= cooldown {
        return None;
    }

    Some(cooldown - elapsed)
}

fn validate_receive_idle_session_payload(session: &PeerPolicySessionState) -> Result<()> {
    if session.policy_name != RECEIVE_IDLE_POLICY_NAME {
        return Err(anyhow::anyhow!(
            "receive-idle policy received `{}` session",
            session.policy_name
        ));
    }
    if session.policy_version != POLICY_VERSION {
        return Err(anyhow::anyhow!(
            "unsupported receive-idle policy session version `{}`",
            session.policy_version
        ));
    }
    if !session.state_json.is_object() {
        return Err(anyhow::anyhow!(
            "receive-idle policy session state_json must be an object"
        ));
    }

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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, SystemTime},
    };

    use proptest::prelude::*;

    use crate::{
        config::{
            BanLadderConfig, ChurnPolicyConfig, FiltersConfig, PolicyConfig, ScorePolicyConfig,
        },
        types::{
            BanDisposition, ExemptionReason, OffenceHistory, PeerContext, PeerPolicyInput,
            PeerSessionState, PeerSnapshot, TorrentScope,
        },
    };

    use super::{
        GenericSessionSnapshot, PeerPolicy, PolicyEngine, RECEIVE_IDLE_POLICY_NAME,
        ReceiveIdlePeerPolicy, SCORE_POLICY_NAME, ScorePeerPolicy,
    };

    proptest! {
        #[test]
        fn normalized_rate_risk_is_bounded_and_monotonic(
            target in 1_u64..1_000_000_u64,
            slower in 0_u64..1_000_000_u64,
            faster in 0_u64..1_000_000_u64,
        ) {
            let slow = slower.min(faster);
            let fast = slower.max(faster);
            let slow_risk = super::normalized_rate_risk(slow, target);
            let fast_risk = super::normalized_rate_risk(fast, target);

            prop_assert!((0.0..=1.0).contains(&slow_risk));
            prop_assert!((0.0..=1.0).contains(&fast_risk));
            prop_assert!(slow_risk >= fast_risk);
        }

        #[test]
        fn normalized_progress_risk_is_bounded_and_monotonic(
            required in 0.000_1_f64..0.25_f64,
            lower_progress in 0.0_f64..0.25_f64,
            higher_progress in 0.0_f64..0.25_f64,
        ) {
            let low = lower_progress.min(higher_progress);
            let high = lower_progress.max(higher_progress);
            let low_risk = super::normalized_progress_risk(low, required);
            let high_risk = super::normalized_progress_risk(high, required);

            prop_assert!((0.0..=1.0).contains(&low_risk));
            prop_assert!((0.0..=1.0).contains(&high_risk));
            prop_assert!(low_risk >= high_risk);
        }

        #[test]
        fn score_state_stays_within_bounds_under_random_observations(
            steps in prop::collection::vec((1_u64..60_u64, 0_u64..200_000_u64, 0.0_f64..0.03_f64), 1..64),
        ) {
            let config = PolicyConfig {
                new_peer_grace_period: Duration::from_secs(1),
                decay_window: Duration::from_secs(3600),
                score: ScorePolicyConfig {
                    min_observation_duration: Duration::from_secs(1),
                    sustain_duration: Duration::from_secs(1),
                    ..ScorePolicyConfig::default()
                },
                ..PolicyConfig::default()
            };
            let engine = PolicyEngine::new(config.clone(), &FiltersConfig::default());

            let mut elapsed = 120_u64;
            let mut progress = 0.10_f64;
            let mut session = None;

            for (sample_secs, up_rate_bps, progress_delta) in steps {
                elapsed += sample_secs;
                progress = (progress + progress_delta).min(0.90);
                let peer = seeded_peer(elapsed, progress, up_rate_bps);
                let evaluation = engine.evaluate_peer(&peer, session.as_ref());

                prop_assert!((0.0..=config.score.max_score).contains(&evaluation.session.ban_score));
                prop_assert!(evaluation.session.ban_score_above_threshold_duration <= evaluation.session.observed_duration);
                prop_assert!(evaluation.session.bad_duration <= evaluation.session.observed_duration);

                session = Some(evaluation.session);
            }
        }
    }

    #[test]
    fn uses_torrent_ip_port_for_observation_identity_and_torrent_ip_for_offence_identity() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let peer = test_peer();

        let observation = engine.peer_observation_id(&peer);
        let offence = engine.offence_identity(&peer);

        assert_eq!(observation.torrent_hash, "abc123");
        assert_eq!(observation.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
        assert_eq!(observation.peer_port, 51413);
        assert_eq!(offence.torrent_hash, "abc123");
        assert_eq!(offence.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
    }

    #[test]
    fn constructs_enabled_policy_list_from_config() {
        let default_engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let default_names = default_engine
            .enabled_peer_policies()
            .into_iter()
            .map(|policy| policy.name())
            .collect::<Vec<_>>();
        assert_eq!(
            default_names,
            vec![SCORE_POLICY_NAME, RECEIVE_IDLE_POLICY_NAME]
        );

        let receive_idle_only = PolicyEngine::new(
            PolicyConfig {
                score: ScorePolicyConfig {
                    enabled: false,
                    ..ScorePolicyConfig::default()
                },
                ..PolicyConfig::default()
            },
            &FiltersConfig::default(),
        );
        let enabled_names = receive_idle_only
            .enabled_peer_policies()
            .into_iter()
            .map(|policy| policy.name())
            .collect::<Vec<_>>();
        assert_eq!(enabled_names, vec![RECEIVE_IDLE_POLICY_NAME]);

        let replay_names = receive_idle_only
            .replay_peer_policies()
            .into_iter()
            .map(|policy| policy.name())
            .collect::<Vec<_>>();
        assert_eq!(
            replay_names,
            vec![SCORE_POLICY_NAME, RECEIVE_IDLE_POLICY_NAME]
        );
    }

    #[test]
    fn classifies_allowlisted_peer_exemption() {
        let filters = FiltersConfig {
            allowlist_peer_ips: vec!["10.0.0.10".to_string()],
            ..FiltersConfig::default()
        };
        let engine = PolicyEngine::new(PolicyConfig::default(), &filters);

        assert_eq!(
            engine.classify_exemption(&test_peer()),
            Some(ExemptionReason::AllowlistedPeer)
        );
    }

    #[test]
    fn classifies_near_complete_exemption() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let mut peer = test_peer();
        peer.peer.progress = 0.99;
        peer.first_seen_at = SystemTime::UNIX_EPOCH;
        peer.observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);

        assert_eq!(
            engine.classify_exemption(&peer),
            Some(ExemptionReason::NearComplete {
                progress: 0.99,
                threshold: 0.95,
            })
        );
    }

    #[test]
    fn classifies_grace_period_exemption() {
        let engine = PolicyEngine::new(
            PolicyConfig {
                new_peer_grace_period: Duration::from_secs(300),
                ..PolicyConfig::default()
            },
            &FiltersConfig::default(),
        );

        match engine.classify_exemption(&test_peer()) {
            Some(ExemptionReason::NewPeerGracePeriod { grace_period, .. }) => {
                assert_eq!(grace_period, Duration::from_secs(300));
            }
            other => panic!("expected grace period exemption, got {other:?}"),
        }
    }

    #[test]
    fn classifies_active_ban_exemption_after_grace_period() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let mut peer = test_peer();
        peer.first_seen_at = SystemTime::UNIX_EPOCH;
        peer.observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);
        peer.has_active_ban = true;

        assert_eq!(
            engine.classify_exemption(&peer),
            Some(ExemptionReason::AlreadyBanned)
        );
    }

    fn score_policy_for_tests(
        min_observation_secs: u64,
        sustain_secs: u64,
        required_progress_delta: f64,
    ) -> ScorePolicyConfig {
        ScorePolicyConfig {
            target_rate_bps: 1_000,
            required_progress_delta,
            weight_rate: 0.7,
            weight_progress: 0.3,
            rate_risk_floor: 0.4,
            ban_threshold: 0.5,
            clear_threshold: 0.25,
            sustain_duration: Duration::from_secs(sustain_secs),
            decay_per_second: 0.0,
            min_observation_duration: Duration::from_secs(min_observation_secs),
            max_score: 5.0,
            ..ScorePolicyConfig::default()
        }
    }

    fn churn_enabled_score_policy_for_tests() -> ScorePolicyConfig {
        let mut score = score_policy_for_tests(60, 120, 0.01);
        score.ban_threshold = 10.0;
        score.clear_threshold = 5.0;
        score.max_score = 20.0;
        score.churn = ChurnPolicyConfig {
            enabled: true,
            reconnect_window: Duration::from_secs(600),
            min_reconnects: 2,
            max_amplifier: 0.6,
            decay_per_second: 0.0,
        };
        score
    }

    #[test]
    fn progress_rate_scale_relaxes_required_progress_for_high_rate_peers() {
        let config = PolicyConfig {
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.02,
                progress_rate_scale_start: 2.0,
                progress_rate_scale_end: 4.0,
                progress_rate_min_scale: 0.25,
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let baseline = engine.required_progress_delta(Duration::from_secs(120), 1_000);
        let scaled = engine.required_progress_delta(Duration::from_secs(120), 4_000);

        assert_eq!(baseline, 0.02);
        assert_eq!(scaled, 0.005);
    }

    #[test]
    fn accumulates_bad_time_until_peer_is_bannable() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(300, 180, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let initial = seeded_peer(0, 0.10, 500);
        let mut session = engine.begin_session(&initial, None);

        for offset in [120, 240] {
            let evaluation =
                engine.evaluate_peer(&seeded_peer(offset, 0.1005, 500), Some(&session));
            assert!(evaluation.is_bad_sample);
            assert!(!evaluation.is_bannable);
            session = evaluation.session;
        }

        let evaluation = engine.evaluate_peer(&seeded_peer(360, 0.1010, 500), Some(&session));
        assert!(evaluation.is_bad_sample);
        assert!(evaluation.is_bannable);
        assert_eq!(
            evaluation.session.observed_duration,
            Duration::from_secs(360)
        );
        assert_eq!(evaluation.session.bad_duration, Duration::from_secs(360));
    }

    #[test]
    fn decays_bad_time_when_peer_improves() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(60, 300, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let mut session = PeerSessionState {
            observation_id: PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default())
                .peer_observation_id(&seeded_peer(0, 0.10, 500)),
            offence_identity: engine.offence_identity(&seeded_peer(0, 0.10, 500)),
            first_seen_at: SystemTime::UNIX_EPOCH,
            last_seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(300),
            baseline_progress: 0.10,
            latest_progress: 0.10,
            rolling_avg_up_rate_bps: 500,
            observed_duration: Duration::from_secs(300),
            bad_duration: Duration::from_secs(300),
            ban_score: 0.0,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_amplifier: 0.0,
            sample_count: 3,
            last_torrent_seeder_count: 5,
            last_exemption_reason: None,
            bannable_since: None,
            last_ban_decision_at: None,
        };

        let evaluation = engine.evaluate_peer(&seeded_peer(420, 0.13, 2_000), Some(&session));
        assert!(!evaluation.is_bad_sample);
        assert!(!evaluation.is_bannable);
        assert_eq!(evaluation.session.bad_duration, Duration::from_secs(240));
        session = evaluation.session;

        let second = engine.evaluate_peer(&seeded_peer(720, 0.20, 2_000), Some(&session));
        assert_eq!(second.session.bad_duration, Duration::from_secs(90));
    }

    #[test]
    fn carries_over_state_across_reconnect_on_new_port() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(60, 300, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let mut peer = seeded_peer(120, 0.10, 500);
        let previous = PeerSessionState {
            observation_id: engine.peer_observation_id(&peer),
            offence_identity: engine.offence_identity(&peer),
            first_seen_at: SystemTime::UNIX_EPOCH,
            last_seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(120),
            baseline_progress: 0.10,
            latest_progress: 0.12,
            rolling_avg_up_rate_bps: 400,
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
            bannable_since: None,
            last_ban_decision_at: None,
        };

        peer.peer.port = 51414;
        peer.observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(240);

        let resumed = engine.begin_session(&peer, Some(&previous));
        assert_eq!(resumed.observation_id.peer_port, 51414);
        assert_eq!(resumed.offence_identity, previous.offence_identity);
        assert_eq!(resumed.observed_duration, Duration::from_secs(120));
        assert_eq!(resumed.bad_duration, Duration::from_secs(60));
        assert_eq!(resumed.sample_count, 3);
        assert_eq!(resumed.first_seen_at, previous.first_seen_at);
    }

    #[test]
    fn does_not_mark_exempt_samples_as_bad() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(300),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let initial = test_peer();
        let session = engine.begin_session(&initial, None);

        let evaluation = engine.evaluate_peer(&test_peer(), Some(&session));
        assert!(!evaluation.is_bad_sample);
        assert!(!evaluation.is_bannable);
        assert!(matches!(
            evaluation.session.last_exemption_reason,
            Some(ExemptionReason::NewPeerGracePeriod { .. })
        ));
    }

    #[test]
    fn score_policy_ignores_receive_idle_zero_upload_samples() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(60, 30, 0.01),
            receive_idle: crate::config::ReceiveIdlePolicyConfig {
                max_upload_rate_bps: 0,
                ..crate::config::ReceiveIdlePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let mut previous = engine
            .evaluate_peer(&seeded_peer(120, 0.10, 500), None)
            .session;
        previous.ban_score = 3.0;
        previous.ban_score_above_threshold_duration = Duration::from_secs(120);

        let evaluation = engine.evaluate_peer(&seeded_peer(180, 0.10, 0), Some(&previous));

        assert!(!evaluation.is_bad_sample);
        assert!(!evaluation.is_bannable);
        assert_eq!(evaluation.sample_score_risk, 0.0);
        assert_eq!(
            evaluation.session.ban_score_above_threshold_duration,
            Duration::ZERO
        );
    }

    #[test]
    fn supports_first_evaluation_without_seeded_session() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(60, 30, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let evaluation = engine.evaluate_peer(&seeded_peer(120, 0.10, 500), None);
        assert_eq!(evaluation.session.sample_count, 1);
        assert_eq!(
            evaluation.session.observed_duration,
            Duration::from_secs(60)
        );
        assert_eq!(evaluation.session.bad_duration, Duration::from_secs(60));
        assert!(evaluation.is_bad_sample);
        assert!(evaluation.is_bannable);
    }

    #[test]
    fn evaluates_progress_against_ban_window_not_single_sample_only() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(60, 120, 0.02),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let initial = seeded_peer(60, 0.10, 500);
        let first = engine.evaluate_peer(
            &seeded_peer(120, 0.111, 500),
            Some(&engine.begin_session(&initial, None)),
        );
        assert!(!first.is_bad_sample);

        let second = engine.evaluate_peer(&seeded_peer(180, 0.127, 500), Some(&first.session));
        assert!(
            !second.is_bad_sample,
            "window progress should be sufficient even with small latest sample delta"
        );
    }

    #[test]
    fn continuous_bad_samples_reach_bad_for_duration_without_hidden_decay() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(300, 300, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let initial = seeded_peer(60, 0.10, 500);
        let mut session = engine.begin_session(&initial, None);
        let mut final_eval = None;
        for observed_secs in [120, 180, 240, 300, 360] {
            let evaluation =
                engine.evaluate_peer(&seeded_peer(observed_secs, 0.10, 500), Some(&session));
            assert!(evaluation.is_bad_sample);
            session = evaluation.session.clone();
            final_eval = Some(evaluation);
        }

        let evaluation = final_eval.expect("expected final evaluation");
        assert_eq!(
            evaluation.session.observed_duration,
            Duration::from_secs(300)
        );
        assert_eq!(evaluation.session.bad_duration, Duration::from_secs(300));
        assert!(evaluation.is_bannable);
    }

    #[test]
    fn returns_not_bannable_until_thresholds_are_met() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(600, 300, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let evaluation = engine.evaluate_peer(&seeded_peer(120, 0.10, 500), None);

        assert_eq!(
            engine.decide_ban(&seeded_peer(120, 0.10, 500), &evaluation, &empty_history()),
            BanDisposition::NotBannableYet {
                observed_duration: Duration::from_secs(60),
                required_observation: Duration::from_secs(600),
                bad_duration: Duration::from_secs(60),
                required_bad_duration: Duration::from_secs(300),
            }
        );
    }

    #[test]
    fn returns_reban_cooldown_when_previous_ban_expired_recently() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            reban_cooldown: Duration::from_secs(300),
            score: score_policy_for_tests(60, 30, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);

        assert_eq!(
            engine.decide_ban(
                &peer,
                &evaluation,
                &OffenceHistory {
                    offence_count: 1,
                    last_ban_expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(120)),
                }
            ),
            BanDisposition::RebanCooldown {
                remaining: Duration::from_secs(240),
            }
        );
    }

    #[test]
    fn selects_ban_ladder_ttl_from_prior_offence_count() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(60, 30, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);

        match engine.decide_ban(
            &peer,
            &evaluation,
            &OffenceHistory {
                offence_count: 2,
                last_ban_expires_at: None,
            },
        ) {
            BanDisposition::Ban(decision) => {
                assert_eq!(decision.offence_number, 3);
                assert_eq!(decision.ttl, Duration::from_secs(24 * 60 * 60));
                assert_eq!(decision.peer_ip, peer.peer.ip);
                assert_eq!(decision.peer_port, peer.peer.port);
                assert_eq!(decision.reason_code, "score_based");
                assert!(decision.reason_details.contains("score peer"));
            }
            other => panic!("expected ban decision, got {other:?}"),
        }
    }

    #[test]
    fn selects_first_ban_ladder_rung_for_first_offence() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(60, 30, 0.01),
            ban_ladder: BanLadderConfig {
                durations: vec![Duration::from_secs(300), Duration::from_secs(600)],
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);

        match engine.decide_ban(&peer, &evaluation, &empty_history()) {
            BanDisposition::Ban(decision) => {
                assert_eq!(decision.offence_number, 1);
                assert_eq!(decision.ttl, Duration::from_secs(300));
            }
            other => panic!("expected ban decision, got {other:?}"),
        }
    }

    #[test]
    fn caps_ban_ladder_at_last_rung_for_high_offence_counts() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(60, 30, 0.01),
            ban_ladder: BanLadderConfig {
                durations: vec![Duration::from_secs(300), Duration::from_secs(600)],
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);

        match engine.decide_ban(
            &peer,
            &evaluation,
            &OffenceHistory {
                offence_count: 8,
                last_ban_expires_at: None,
            },
        ) {
            BanDisposition::Ban(decision) => {
                assert_eq!(decision.offence_number, 9);
                assert_eq!(decision.ttl, Duration::from_secs(600));
            }
            other => panic!("expected ban decision, got {other:?}"),
        }
    }

    #[test]
    fn returns_exemption_before_ban_decision() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(300),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = test_peer();
        let evaluation = engine.evaluate_peer(&peer, None);

        assert!(matches!(
            engine.decide_ban(&peer, &evaluation, &empty_history()),
            BanDisposition::Exempt(ExemptionReason::NewPeerGracePeriod { .. })
        ));
    }

    #[test]
    fn suppresses_duplicate_ban_decisions_for_same_bannable_episode() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(60, 30, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);
        let first_session = match engine.decide_ban(&peer, &evaluation, &empty_history()) {
            BanDisposition::Ban(_) => {
                engine.record_ban_decision(&evaluation.session, peer.observed_at)
            }
            other => panic!("expected ban decision, got {other:?}"),
        };

        let next_peer = seeded_peer(240, 0.10, 500);
        let next_evaluation = engine.evaluate_peer(&next_peer, Some(&first_session));
        assert_eq!(
            engine.decide_ban(&next_peer, &next_evaluation, &empty_history()),
            BanDisposition::DuplicateSuppressed
        );
    }

    #[test]
    fn allows_new_ban_after_peer_leaves_bannable_state() {
        let mut score = score_policy_for_tests(60, 30, 0.01);
        score.decay_per_second = 0.01;
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(60),
            reban_cooldown: Duration::from_secs(30),
            score,
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let peer = seeded_peer(180, 0.10, 500);
        let evaluation = engine.evaluate_peer(&peer, None);
        let banned_session = engine.record_ban_decision(&evaluation.session, peer.observed_at);

        let recovered_peer = seeded_peer(420, 0.20, 5_000);
        let recovered = engine.evaluate_peer(&recovered_peer, Some(&banned_session));
        assert!(matches!(
            engine.decide_ban(&recovered_peer, &recovered, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));
        assert_eq!(recovered.session.last_ban_decision_at, None);

        let relapsed_peer = seeded_peer(540, 0.20, 500);
        let relapsed = engine.evaluate_peer(&relapsed_peer, Some(&recovered.session));
        assert!(matches!(
            engine.decide_ban(
                &relapsed_peer,
                &relapsed,
                &OffenceHistory {
                    offence_count: 1,
                    last_ban_expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(300)),
                }
            ),
            BanDisposition::Ban(_)
        ));
    }

    #[test]
    fn simulation_slow_non_progressing_peer_escalates_to_ban() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(180, 120, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let mut session = None;
        let mut final_disposition = None;
        for (observed_secs, progress) in [(60, 0.10), (120, 0.1005), (180, 0.1010), (240, 0.1015)] {
            let peer = seeded_peer(observed_secs, progress, 500);
            let evaluation = engine.evaluate_peer(&peer, session.as_ref());
            final_disposition = Some(engine.decide_ban(&peer, &evaluation, &empty_history()));
            session = Some(evaluation.session);
        }

        assert!(matches!(final_disposition, Some(BanDisposition::Ban(_))));
    }

    #[test]
    fn simulation_reconnect_churn_preserves_progress_toward_ban() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: score_policy_for_tests(180, 120, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = seeded_peer(120, 0.10, 500);
        let first_eval = engine.evaluate_peer(&first, None);
        assert!(matches!(
            engine.decide_ban(&first, &first_eval, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));

        let mut reconnected = seeded_peer(240, 0.1005, 500);
        reconnected.peer.port = 51414;
        let second_eval = engine.evaluate_peer(&reconnected, Some(&first_eval.session));

        assert_eq!(second_eval.session.observation_id.peer_port, 51414);
        assert_eq!(
            second_eval.session.first_seen_at,
            first_eval.session.first_seen_at
        );
        assert!(matches!(
            engine.decide_ban(&reconnected, &second_eval, &empty_history()),
            BanDisposition::Ban(_)
        ));
    }

    #[test]
    fn churn_amplifier_accumulates_on_repeated_bad_reconnects() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: churn_enabled_score_policy_for_tests(),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

        let mut second_peer = seeded_peer(180, 0.10, 1);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(second.is_bad_sample);
        assert_eq!(second.session.churn_reconnect_count, 1);
        assert!((second.session.churn_amplifier - 0.0).abs() < 0.0001);
        assert!((second.effective_sample_score_risk - second.sample_score_risk).abs() < 0.0001);

        let mut third_peer = seeded_peer(240, 0.10, 1);
        third_peer.peer.port = 51415;
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));
        assert!(third.is_bad_sample);
        assert_eq!(third.session.churn_reconnect_count, 2);
        assert!((third.session.churn_amplifier - 0.3).abs() < 0.0001);
        assert!(
            (third.effective_sample_score_risk - (third.sample_score_risk * 1.3)).abs() < 0.0001
        );

        let mut fourth_peer = seeded_peer(300, 0.10, 1);
        fourth_peer.peer.port = 51416;
        let fourth = engine.evaluate_peer(&fourth_peer, Some(&third.session));
        assert!(fourth.is_bad_sample);
        assert_eq!(fourth.session.churn_reconnect_count, 3);
        assert!((fourth.session.churn_amplifier - 0.6).abs() < 0.0001);
        assert!(
            (fourth.effective_sample_score_risk - (fourth.sample_score_risk * 1.6)).abs() < 0.0001
        );
    }

    #[test]
    fn churn_amplifier_does_not_accumulate_for_healthy_reconnects() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score: churn_enabled_score_policy_for_tests(),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 10_000), None);
        assert!(!first.is_bad_sample);

        let mut second_peer = seeded_peer(180, 0.12, 10_000);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(!second.is_bad_sample);
        assert_eq!(second.session.churn_reconnect_count, 1);
        assert!((second.session.churn_amplifier - 0.0).abs() < 0.0001);

        let mut third_peer = seeded_peer(240, 0.14, 10_000);
        third_peer.peer.port = 51415;
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));
        assert!(!third.is_bad_sample);
        assert_eq!(third.session.churn_reconnect_count, 2);
        assert!((third.session.churn_amplifier - 0.0).abs() < 0.0001);
    }

    #[test]
    fn churn_amplifier_does_not_ban_borderline_peer_on_its_own() {
        let mut score = score_policy_for_tests(60, 120, 0.01);
        score.weight_rate = 0.0;
        score.weight_progress = 1.0;
        score.ban_threshold = 1.6;
        score.clear_threshold = 0.8;
        score.decay_per_second = 0.0;
        score.churn = ChurnPolicyConfig {
            enabled: true,
            reconnect_window: Duration::from_secs(600),
            min_reconnects: 1,
            max_amplifier: 1.0,
            decay_per_second: 0.0,
        };
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score,
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let previous = PeerSessionState {
            observation_id: engine.peer_observation_id(&seeded_peer(120, 0.10, 900)),
            offence_identity: engine.offence_identity(&seeded_peer(120, 0.10, 900)),
            first_seen_at: SystemTime::UNIX_EPOCH,
            last_seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(120),
            baseline_progress: 0.10,
            latest_progress: 0.10,
            rolling_avg_up_rate_bps: 900,
            observed_duration: Duration::from_secs(120),
            bad_duration: Duration::from_secs(120),
            ban_score: 1.1,
            ban_score_above_threshold_duration: Duration::ZERO,
            churn_reconnect_count: 0,
            churn_window_started_at: None,
            churn_amplifier: 0.0,
            sample_count: 2,
            last_torrent_seeder_count: 5,
            last_exemption_reason: None,
            bannable_since: None,
            last_ban_decision_at: None,
        };

        let mut peer = seeded_peer(180, 0.108, 900);
        peer.peer.port = 51414;
        let evaluation = engine.evaluate_peer(&peer, Some(&previous));

        assert!(evaluation.is_bad_sample);
        assert!((evaluation.sample_score_risk - 0.2).abs() < 0.0001);
        assert!((evaluation.session.churn_amplifier - 1.0).abs() < 0.0001);
        assert!((evaluation.effective_sample_score_risk - 0.4).abs() < 0.0001);
        assert!((evaluation.session.ban_score - 1.5).abs() < 0.0001);
        assert!(!evaluation.is_bannable);
    }

    #[test]
    fn churn_amplifier_is_capped_at_max_amplifier() {
        let mut score = churn_enabled_score_policy_for_tests();
        score.churn.min_reconnects = 1;
        score.churn.max_amplifier = 0.5;
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score,
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

        let mut second_peer = seeded_peer(180, 0.10, 1);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!((second.session.churn_amplifier - 0.5).abs() < 0.0001);

        let mut third_peer = seeded_peer(240, 0.10, 1);
        third_peer.peer.port = 51415;
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));
        assert!((third.session.churn_amplifier - 0.5).abs() < 0.0001);
    }

    #[test]
    fn churn_amplifier_resets_when_sample_becomes_exempt() {
        let mut score = churn_enabled_score_policy_for_tests();
        score.churn.min_reconnects = 1;
        score.churn.max_amplifier = 0.5;
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            score,
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

        let mut second_peer = seeded_peer(180, 0.10, 1);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(second.session.churn_amplifier > 0.0);

        let mut exempt_peer = seeded_peer(240, 0.99, 1);
        exempt_peer.peer.port = 51415;
        let exempt = engine.evaluate_peer(&exempt_peer, Some(&second.session));

        assert!(matches!(
            exempt.session.last_exemption_reason,
            Some(ExemptionReason::NearComplete { .. })
        ));
        assert!((exempt.session.churn_amplifier - 0.0).abs() < 0.0001);
    }

    #[test]
    fn simulation_healthy_recovery_clears_bannable_state() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            decay_window: Duration::from_secs(600),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let peer = seeded_peer(240, 0.1015, 500);
        let initial = engine.evaluate_peer(&peer, None);
        let banned_session = engine.record_ban_decision(&initial.session, peer.observed_at);

        let recovered_peer = seeded_peer(1140, 0.20, 5_000);
        let recovered = engine.evaluate_peer(&recovered_peer, Some(&banned_session));

        assert!(!recovered.is_bad_sample);
        assert!(!recovered.is_bannable);
        assert!(recovered.session.bad_duration < banned_session.bad_duration);
        assert_eq!(recovered.session.bannable_since, None);
        assert_eq!(recovered.session.last_ban_decision_at, None);
    }

    #[test]
    fn simulation_exemption_matrix_returns_expected_dispositions() {
        let cases = vec![
            (
                "near_complete",
                FiltersConfig::default(),
                seeded_peer(360, 0.99, 500),
                ExemptionReason::NearComplete {
                    progress: 0.99,
                    threshold: 0.95,
                },
            ),
            (
                "allowlisted",
                {
                    FiltersConfig {
                        allowlist_peer_ips: vec!["10.0.0.10".to_string()],
                        ..FiltersConfig::default()
                    }
                },
                seeded_peer(360, 0.10, 500),
                ExemptionReason::AllowlistedPeer,
            ),
        ];

        for (name, filters, peer, expected) in cases {
            let engine = PolicyEngine::new(PolicyConfig::default(), &filters);
            let evaluation = engine.evaluate_peer(&peer, None);
            match engine.decide_ban(&peer, &evaluation, &empty_history()) {
                BanDisposition::Exempt(reason) => assert_eq!(reason, expected, "{name}"),
                other => panic!("expected exemption for {name}, got {other:?}"),
            }
        }
    }

    #[test]
    fn receive_idle_bans_after_sustained_zero_upload_progress() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first_peer = seeded_peer_with_uploaded(180, 0);
        let first = engine.evaluate_receive_idle_peer(&first_peer, None);
        assert!(!first.is_bad_sample);
        assert!(!first.is_bannable);

        let second_peer = seeded_peer_with_uploaded(240, 0);
        let second = engine.evaluate_receive_idle_peer(&second_peer, Some(&first.session));
        assert!(second.is_bad_sample);
        assert!(second.is_bannable);

        match engine.decide_receive_idle_ban(&second_peer, &second, &empty_history()) {
            BanDisposition::Ban(decision) => {
                assert_eq!(decision.reason_code, "receive_idle");
                assert_eq!(decision.ttl, Duration::from_secs(600));
                assert!(decision.reason_details.contains("uploaded_delta_bytes=0"));
            }
            other => panic!("expected receive idle ban, got {other:?}"),
        }
    }

    #[test]
    fn receive_idle_accumulates_across_same_port_polls() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first = engine.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
        let second = engine
            .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(210, 0), Some(&first.session));
        assert!(second.is_bad_sample);
        assert_eq!(second.session.bad_duration, Duration::from_secs(30));
        assert!(!second.is_bannable);

        let third_peer = seeded_peer_with_uploaded(240, 0);
        let third = engine.evaluate_receive_idle_peer(&third_peer, Some(&second.session));
        assert!(third.is_bad_sample);
        assert_eq!(third.session.bad_duration, Duration::from_secs(60));
        assert!(third.is_bannable);

        match engine.decide_receive_idle_ban(&third_peer, &third, &empty_history()) {
            BanDisposition::Ban(decision) => assert_eq!(decision.reason_code, "receive_idle"),
            other => panic!("expected receive idle ban, got {other:?}"),
        }
    }

    #[test]
    fn receive_idle_rejects_incompatible_session_payload_version() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first = engine.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
        let mut previous = first.session.clone();
        previous.policy_version = "policy-v2".to_string();

        let policy = ReceiveIdlePeerPolicy { engine };
        let history = empty_history();
        let peer = seeded_peer_with_uploaded(210, 0);
        let previous = GenericSessionSnapshot { session: previous };
        let error = policy
            .assess_peer(PeerPolicyInput {
                peer: &peer,
                previous_session: Some(&previous),
                offence_history: &history,
            })
            .unwrap_err();

        assert!(error.to_string().contains("unsupported receive-idle"));
    }

    #[test]
    fn score_adapter_preserves_engine_decision_and_state_summary() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: score_policy_for_tests(60, 30, 0.01),
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());
        let policy = ScorePeerPolicy {
            engine: engine.clone(),
        };
        let peer = seeded_peer(180, 0.10, 500);
        let history = OffenceHistory {
            offence_count: 2,
            last_ban_expires_at: None,
        };
        let direct_evaluation = engine.evaluate_peer(&peer, None);
        let direct_disposition = engine.decide_ban(&peer, &direct_evaluation, &history);
        let adapter_assessment = policy
            .assess_peer(PeerPolicyInput {
                peer: &peer,
                previous_session: None,
                offence_history: &history,
            })
            .unwrap();

        assert_eq!(adapter_assessment.disposition, direct_disposition);
        assert_eq!(
            adapter_assessment.evaluation.offence_identity(),
            &direct_evaluation.session.offence_identity
        );
        assert_eq!(
            adapter_assessment.evaluation.bad_duration(),
            direct_evaluation.session.bad_duration
        );
        assert_eq!(
            adapter_assessment.evaluation.avg_upload_rate_bps(),
            direct_evaluation.session.rolling_avg_up_rate_bps
        );
        assert_eq!(
            adapter_assessment.evaluation.is_bannable(),
            direct_evaluation.is_bannable
        );
        assert_eq!(
            adapter_assessment.diagnostic_bool("threshold_met"),
            Some(true)
        );
    }

    #[test]
    fn score_adapter_rejects_incompatible_session_snapshot() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let policy = ScorePeerPolicy {
            engine: engine.clone(),
        };
        let peer = seeded_peer(180, 0.10, 500);
        let previous = engine.begin_receive_idle_session(&peer, None);
        let previous = GenericSessionSnapshot { session: previous };
        let history = empty_history();
        let error = policy
            .assess_peer(PeerPolicyInput {
                peer: &peer,
                previous_session: Some(&previous),
                offence_history: &history,
            })
            .unwrap_err();

        assert!(error.to_string().contains("non-score session"));
    }

    #[test]
    fn receive_idle_adapter_preserves_engine_decision_and_state_summary() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let policy = ReceiveIdlePeerPolicy {
            engine: engine.clone(),
        };
        let first_peer = seeded_peer_with_uploaded(180, 0);
        let first = engine.evaluate_receive_idle_peer(&first_peer, None);
        let second_peer = seeded_peer_with_uploaded(240, 0);
        let history = empty_history();
        let direct_evaluation =
            engine.evaluate_receive_idle_peer(&second_peer, Some(&first.session));
        let direct_disposition =
            engine.decide_receive_idle_ban(&second_peer, &direct_evaluation, &history);
        let previous = GenericSessionSnapshot {
            session: first.session,
        };
        let adapter_assessment = policy
            .assess_peer(PeerPolicyInput {
                peer: &second_peer,
                previous_session: Some(&previous),
                offence_history: &history,
            })
            .unwrap();

        assert_eq!(adapter_assessment.disposition, direct_disposition);
        assert_eq!(
            adapter_assessment.evaluation.offence_identity(),
            &direct_evaluation.session.offence_identity
        );
        assert_eq!(
            adapter_assessment.evaluation.bad_duration(),
            direct_evaluation.session.bad_duration
        );
        assert_eq!(
            adapter_assessment.evaluation.avg_upload_rate_bps(),
            direct_evaluation.session.last_upload_rate_bps
        );
        assert_eq!(
            adapter_assessment.evaluation.is_bannable(),
            direct_evaluation.is_bannable
        );
        assert_eq!(
            adapter_assessment.diagnostic_bool("threshold_met"),
            Some(true)
        );
    }

    #[test]
    fn receive_idle_does_not_count_absent_gap_as_idle_time() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first = engine.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
        let second = engine
            .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(210, 0), Some(&first.session));
        assert_eq!(second.session.bad_duration, Duration::from_secs(30));

        let returned_peer = seeded_peer_with_uploaded(600, 0);
        let returned = engine.evaluate_receive_idle_peer(&returned_peer, Some(&second.session));

        assert!(!returned.is_bad_sample);
        assert_eq!(returned.session.bad_duration, Duration::ZERO);
        assert!(!returned.is_bannable);
    }

    #[test]
    fn receive_idle_resets_on_uploaded_byte_progress() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first = engine.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
        let second = engine
            .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(240, 0), Some(&first.session));
        assert!(second.is_bad_sample);

        let third = engine
            .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(300, 1), Some(&second.session));
        assert!(!third.is_bad_sample);
        assert_eq!(third.session.bad_duration, Duration::ZERO);
        assert!(!third.is_bannable);
    }

    #[test]
    fn receive_idle_missing_uploaded_bytes_is_not_bannable() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let mut first_peer = seeded_peer_with_uploaded(180, 0);
        first_peer.peer.uploaded_bytes = None;
        let first = engine.evaluate_receive_idle_peer(&first_peer, None);

        let mut second_peer = seeded_peer_with_uploaded(240, 0);
        second_peer.peer.uploaded_bytes = None;
        let second = engine.evaluate_receive_idle_peer(&second_peer, Some(&first.session));

        assert_eq!(second.uploaded_delta_bytes, None);
        assert!(!second.is_bad_sample);
        assert!(!second.is_bannable);
    }

    #[test]
    fn receive_idle_uses_policy_specific_reban_cooldown() {
        let engine = PolicyEngine::new(receive_idle_test_config(), &FiltersConfig::default());
        let first = engine.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
        let peer = seeded_peer_with_uploaded(240, 0);
        let evaluation = engine.evaluate_receive_idle_peer(&peer, Some(&first.session));
        let history = OffenceHistory {
            offence_count: 1,
            last_ban_expires_at: Some(peer.observed_at - Duration::from_secs(300)),
        };

        match engine.decide_receive_idle_ban(&peer, &evaluation, &history) {
            BanDisposition::RebanCooldown { remaining } => {
                assert_eq!(remaining, Duration::from_secs(300));
            }
            other => panic!("expected reban cooldown, got {other:?}"),
        }
    }

    fn test_peer() -> PeerContext {
        seeded_peer(120, 0.25, 1024)
    }

    fn receive_idle_test_config() -> PolicyConfig {
        PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            receive_idle: crate::config::ReceiveIdlePolicyConfig {
                enabled: true,
                min_observation_duration: Duration::from_secs(60),
                sustain_duration: Duration::from_secs(60),
                max_upload_rate_bps: 0,
                max_uploaded_delta_bytes: 0,
                reban_cooldown: Duration::from_secs(600),
                ban_ladder: BanLadderConfig {
                    durations: vec![Duration::from_secs(600), Duration::from_secs(1800)],
                },
            },
            ..PolicyConfig::default()
        }
    }

    fn empty_history() -> OffenceHistory {
        OffenceHistory {
            offence_count: 0,
            last_ban_expires_at: None,
        }
    }

    fn seeded_peer(observed_secs: u64, progress: f64, up_rate_bps: u64) -> PeerContext {
        PeerContext {
            torrent: TorrentScope {
                hash: "abc123".to_string(),
                name: "torrent-abc123".to_string(),
                tracker: None,
                category: Some("tv".to_string()),
                tags: vec!["seed".to_string()],
                total_seeders: 5,
                in_scope: true,
            },
            peer: PeerSnapshot {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                port: 51413,
                progress,
                up_rate_bps,
                uploaded_bytes: Some(0),
            },
            first_seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(observed_secs),
            has_active_ban: false,
        }
    }

    fn seeded_peer_with_uploaded(observed_secs: u64, uploaded_bytes: u64) -> PeerContext {
        let mut peer = seeded_peer(observed_secs, 0.25, 0);
        peer.peer.uploaded_bytes = Some(uploaded_bytes);
        peer
    }

    #[test]
    fn score_mode_bans_after_sustained_high_score() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.01,
                weight_rate: 0.7,
                weight_progress: 0.3,
                rate_risk_floor: 0.0,
                ban_threshold: 0.8,
                clear_threshold: 0.4,
                sustain_duration: Duration::from_secs(120),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(120),
                max_score: 5.0,
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first_peer = seeded_peer(120, 0.10, 1);
        let first = engine.evaluate_peer(&first_peer, None);
        assert!(matches!(
            engine.decide_ban(&first_peer, &first, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));

        let second_peer = seeded_peer(180, 0.10, 1);
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        match engine.decide_ban(&second_peer, &second, &empty_history()) {
            BanDisposition::Ban(decision) => {
                assert_eq!(decision.reason_code, "score_based");
                assert!(decision.reason_details.contains("score peer"));
            }
            other => panic!("expected ban decision, got {other:?}"),
        }
    }

    #[test]
    fn score_mode_does_not_ban_when_progress_risk_is_low() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.005,
                weight_rate: 0.0,
                weight_progress: 1.0,
                rate_risk_floor: 0.0,
                ban_threshold: 0.8,
                clear_threshold: 0.4,
                sustain_duration: Duration::from_secs(120),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(120),
                max_score: 5.0,
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(60, 0.10, 1), None);
        let second = engine.evaluate_peer(&seeded_peer(120, 0.106, 1), Some(&first.session));
        let third_peer = seeded_peer(180, 0.112, 1);
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));

        assert!(third.session.ban_score < 0.1);
        assert!(matches!(
            engine.decide_ban(&third_peer, &third, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));
    }

    #[test]
    fn score_mode_rate_risk_floor_blocks_full_compensation() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.005,
                weight_rate: 0.0,
                weight_progress: 1.0,
                rate_risk_floor: 0.6,
                ban_threshold: 1.0,
                clear_threshold: 0.4,
                sustain_duration: Duration::from_secs(120),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(120),
                max_score: 5.0,
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first_peer = seeded_peer(61, 0.10, 1);
        let first = engine.evaluate_peer(&first_peer, None);
        assert!((first.sample_score_risk - 1.0).abs() < 0.0001);

        let second_peer = seeded_peer(121, 0.106, 1);
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(second.sample_score_risk > 0.59);
        assert!(second.sample_score_risk < 0.6);

        let third_peer = seeded_peer(181, 0.112, 1);
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));
        match engine.decide_ban(&third_peer, &third, &empty_history()) {
            BanDisposition::Ban(decision) => assert_eq!(decision.reason_code, "score_based"),
            other => panic!("expected score-based ban, got {other:?}"),
        }
    }

    #[test]
    fn score_mode_avoids_progress_only_ban_for_high_rate_peer_when_scaled() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.01,
                progress_rate_scale_start: 2.0,
                progress_rate_scale_end: 4.0,
                progress_rate_min_scale: 0.25,
                weight_rate: 0.0,
                weight_progress: 1.0,
                rate_risk_floor: 0.0,
                ban_threshold: 0.8,
                clear_threshold: 0.4,
                sustain_duration: Duration::from_secs(120),
                decay_per_second: 0.0,
                min_observation_duration: Duration::from_secs(120),
                max_score: 5.0,
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let first = engine.evaluate_peer(&seeded_peer(60, 0.10, 4_000), None);
        let second = engine.evaluate_peer(&seeded_peer(120, 0.104, 4_000), Some(&first.session));
        let third_peer = seeded_peer(180, 0.108, 4_000);
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));

        assert!(third.sample_score_risk.abs() < f64::EPSILON);
        assert!(matches!(
            engine.decide_ban(&third_peer, &third, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));
    }
}
