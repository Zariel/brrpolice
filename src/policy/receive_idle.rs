use super::*;

const RECEIVE_IDLE_REASON_CODE: &str = "receive_idle";
pub const RECEIVE_IDLE_POLICY_NAME: &str = "receive_idle";

#[derive(Clone)]
pub(super) struct ReceiveIdlePolicy {
    pub(super) context: PolicyContext,
    pub(super) config: ReceiveIdlePolicyConfig,
}

#[derive(Debug, Clone)]
pub(super) struct ReceiveIdleSessionSnapshot {
    pub(super) session: PeerPolicySessionState,
}

impl PolicySessionSnapshot for ReceiveIdleSessionSnapshot {
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

fn receive_idle_session_snapshot(
    session: PeerPolicySessionState,
) -> Box<dyn PolicySessionSnapshot> {
    Box::new(ReceiveIdleSessionSnapshot { session })
}

#[derive(Debug, Clone)]
struct ReceiveIdleAssessmentEvaluation {
    evaluation: PeerPolicyEvaluation,
}

impl PolicyEvaluation for ReceiveIdleAssessmentEvaluation {
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

fn receive_idle_evaluation(assessment: &PeerPolicyAssessment) -> Result<&PeerPolicyEvaluation> {
    assessment
        .evaluation
        .as_any()
        .downcast_ref::<ReceiveIdleAssessmentEvaluation>()
        .map(|state| &state.evaluation)
        .ok_or_else(|| anyhow::anyhow!("receive-idle assessment carried non-receive-idle state"))
}

fn receive_idle_previous_session(
    previous: Option<&dyn PolicySessionSnapshot>,
) -> Result<Option<&PeerPolicySessionState>> {
    previous
        .map(|session| {
            let session = session
                .as_any()
                .downcast_ref::<ReceiveIdleSessionSnapshot>()
                .ok_or_else(|| {
                    anyhow::anyhow!("receive-idle assessment carried non-receive-idle session")
                })?;
            validate_receive_idle_session_payload(&session.session)?;
            Ok(&session.session)
        })
        .transpose()
}

#[async_trait::async_trait]
impl PeerPolicy for ReceiveIdlePolicy {
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

    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment> {
        let previous = receive_idle_previous_session(input.previous_session)?;
        let evaluation = self.evaluate_receive_idle_peer(input.peer, previous);
        let disposition =
            self.decide_receive_idle_ban(input.peer, &evaluation, input.offence_history);
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
            evaluation: Box::new(ReceiveIdleAssessmentEvaluation { evaluation }),
            disposition,
            diagnostics,
        })
    }
}

#[async_trait::async_trait]
impl PeerPolicyStorage for ReceiveIdlePolicy {
    fn session_preload_kind(&self) -> PolicySessionPreloadKind {
        PolicySessionPreloadKind::PeerPolicySessions
    }

    fn cache_peer_policy_session(
        &self,
        session: PeerPolicySessionState,
        cache: &mut PolicyCycleCache,
    ) -> Result<()> {
        cache.insert_session_snapshot(
            self.name(),
            session.observation_id.clone(),
            session.last_seen_at,
            receive_idle_session_snapshot(session),
        );
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
        let identity = self.offence_identity(peer);
        store
            .load_policy_offence_history(self.name(), &identity)
            .await
    }

    async fn persist_assessment(
        &self,
        persistence: &Persistence,
        assessment: &PeerPolicyAssessment,
    ) -> Result<()> {
        let evaluation = receive_idle_evaluation(assessment)?;
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
        let evaluation = receive_idle_evaluation(assessment)?;
        persistence
            .record_policy_ban_enforcement(evaluation, decision, enforced_at)
            .await
    }
}

#[async_trait::async_trait]
impl PeerPolicyReplay for ReceiveIdlePolicy {
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
}

impl ReceiveIdlePolicy {
    pub fn peer_observation_id(&self, peer: &PeerContext) -> PeerObservationId {
        self.context.peer_observation_id(peer)
    }

    pub fn offence_identity(&self, peer: &PeerContext) -> OffenceIdentity {
        self.context.offence_identity(peer)
    }

    pub fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        self.context.classify_exemption(peer)
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
        let is_bad_sample = self.config.enabled
            && exemption.is_none()
            && peer.peer.up_rate_bps <= self.config.max_upload_rate_bps
            && uploaded_delta_bytes
                .is_some_and(|delta| delta <= self.config.max_uploaded_delta_bytes);

        session.last_seen_at = peer.observed_at;
        session.last_uploaded_bytes = peer.peer.uploaded_bytes;
        session.last_upload_rate_bps = peer.peer.up_rate_bps;
        session.last_exemption_reason = exemption;
        session.bad_duration = if is_bad_sample {
            session.bad_duration + sample_duration
        } else {
            Duration::ZERO
        };

        let is_bannable = self.config.enabled
            && session.last_exemption_reason.is_none()
            && session.observed_duration >= self.config.min_observation_duration
            && session.bad_duration >= self.config.sustain_duration;
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
                required_observation: self.config.min_observation_duration,
                bad_duration: evaluation.session.bad_duration,
                required_bad_duration: self.config.sustain_duration,
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

    fn receive_idle_ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        ban_ttl_from_ladder(&self.config.ban_ladder.durations, offence_number)
    }

    fn can_carry_over_policy(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        self.context.can_carry_over_session(
            &previous.observation_id,
            &previous.offence_identity,
            previous.last_seen_at,
            observation_id,
            offence_identity,
            peer,
        )
    }

    fn can_carry_over_receive_idle_session(
        &self,
        previous: &PeerPolicySessionState,
        observation_id: &PeerObservationId,
        offence_identity: &OffenceIdentity,
        peer: &PeerContext,
    ) -> bool {
        self.can_carry_over_policy(previous, observation_id, offence_identity, peer)
            && self.policy_session_gap(previous, peer) <= self.config.sustain_duration
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
            && self.policy_session_gap(previous, peer) <= self.config.sustain_duration
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

    fn remaining_receive_idle_reban_cooldown(
        &self,
        last_ban_expires_at: Option<SystemTime>,
        observed_at: SystemTime,
    ) -> Option<Duration> {
        remaining_reban_cooldown(last_ban_expires_at, observed_at, self.config.reban_cooldown)
    }
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
