use super::*;

const SCORE_BASED_REASON_CODE: &str = "score_based";
pub const SCORE_POLICY_NAME: &str = "score";

#[derive(Clone)]
pub(super) struct ScorePolicy {
    pub(super) context: PolicyContext,
    pub(super) config: ScorePolicyConfig,
}

#[derive(Debug, Clone)]
pub(super) struct ScoreSessionSnapshot {
    pub(super) session: PeerSessionState,
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

fn score_session_snapshot(session: PeerSessionState) -> Box<dyn PolicySessionSnapshot> {
    Box::new(ScoreSessionSnapshot { session })
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

fn score_evaluation(assessment: &PeerPolicyAssessment) -> Result<&PeerEvaluation> {
    assessment
        .evaluation
        .as_any()
        .downcast_ref::<ScoreAssessmentEvaluation>()
        .map(|state| &state.evaluation)
        .ok_or_else(|| anyhow::anyhow!("score assessment carried non-score state"))
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

pub(super) fn normalized_rate_risk(rate_bps: u64, target_bps: u64) -> f64 {
    if target_bps == 0 {
        return 0.0;
    }
    let deficit = target_bps.saturating_sub(rate_bps) as f64;
    (deficit / target_bps as f64).clamp(0.0, 1.0)
}

pub(super) fn normalized_progress_risk(progress_delta: f64, required_progress_delta: f64) -> f64 {
    if required_progress_delta <= 0.0 {
        return 0.0;
    }
    let deficit = (required_progress_delta - progress_delta).max(0.0);
    (deficit / required_progress_delta).clamp(0.0, 1.0)
}

#[async_trait::async_trait]
impl PeerPolicy for ScorePolicy {
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

    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment> {
        let previous = score_previous_session(input.previous_session)?;
        let evaluation = self.evaluate_peer(input.peer, previous);
        let disposition = self.decide_ban(input.peer, &evaluation, input.offence_history);
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
                    evaluation.session.ban_score >= self.config.ban_threshold,
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

    fn record_policy_specific_metrics(
        &self,
        metrics: &AppMetrics,
        assessment: &PeerPolicyAssessment,
    ) {
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
impl PeerPolicyStorage for ScorePolicy {
    fn session_preload_kind(&self) -> PolicySessionPreloadKind {
        PolicySessionPreloadKind::LegacyScore
    }

    async fn preload_legacy_sessions(
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
}

#[async_trait::async_trait]
impl PeerPolicyReplay for ScorePolicy {
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
}

impl ScorePolicy {
    pub fn peer_observation_id(&self, peer: &PeerContext) -> PeerObservationId {
        self.context.peer_observation_id(peer)
    }

    pub fn offence_identity(&self, peer: &PeerContext) -> OffenceIdentity {
        self.context.offence_identity(peer)
    }

    pub fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        self.context.classify_exemption(peer)
    }

    pub fn ban_ttl_for_offence(&self, offence_number: u32) -> Duration {
        ban_ttl_from_ladder(&self.config.ban_ladder.durations, offence_number)
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
                if session.ban_score >= self.config.ban_threshold {
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
                && peer.peer.up_rate_bps < self.config.target_rate_bps
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
                    .clamp(0.0, self.config.max_score);
                if session.ban_score >= self.config.ban_threshold {
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
            && peer.peer.up_rate_bps < self.config.target_rate_bps
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
            ban_score = (ban_score + effective_sample_score_risk).clamp(0.0, self.config.max_score);
            if ban_score >= self.config.ban_threshold {
                ban_score_above_threshold_duration += sample_duration;
            } else if ban_score <= self.config.clear_threshold {
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
                required_observation: self.config.min_observation_duration,
                bad_duration: evaluation.session.ban_score_above_threshold_duration,
                required_bad_duration: self.config.sustain_duration,
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
        let rate_risk =
            normalized_rate_risk(evaluation.sample_up_rate_bps, self.config.target_rate_bps);
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

    fn can_carry_over(
        &self,
        previous: &PeerSessionState,
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

    fn decay_bad_duration(&self, bad_duration: Duration, elapsed: Duration) -> Duration {
        if bad_duration.is_zero() || elapsed.is_zero() {
            return bad_duration;
        }

        // bad_duration decays on inactivity so stale poor behaviour does not keep a peer
        // bannable forever; sustain_duration controls how quickly we forget it.
        let decay_ratio =
            self.config.sustain_duration.as_secs_f64() / self.context.decay_window.as_secs_f64();
        let decay = elapsed.mul_f64(decay_ratio);
        bad_duration.saturating_sub(decay)
    }

    fn decay_score(&self, score: f64, elapsed: Duration) -> f64 {
        self.decay_value(score, elapsed, self.config.decay_per_second)
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
        if !self.config.churn.enabled {
            return (0, None, 0.0);
        }

        let churn = &self.config.churn;
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

    pub(super) fn required_progress_delta(
        &self,
        observed_duration: Duration,
        up_rate_bps: u64,
    ) -> f64 {
        if observed_duration.is_zero() || self.config.required_progress_delta <= 0.0 {
            return 0.0;
        }

        let sustain_secs = self.config.sustain_duration.as_secs_f64();
        if sustain_secs <= 0.0 {
            return self.config.required_progress_delta * self.progress_rate_scale(up_rate_bps);
        }

        let observed_secs = observed_duration.as_secs_f64();
        let ramp = (observed_secs / sustain_secs).clamp(0.0, 1.0);
        self.config.required_progress_delta * ramp * self.progress_rate_scale(up_rate_bps)
    }

    fn progress_rate_scale(&self, up_rate_bps: u64) -> f64 {
        let target_rate_bps = self.config.target_rate_bps;
        if target_rate_bps == 0 {
            return 1.0;
        }

        let ratio = up_rate_bps as f64 / target_rate_bps as f64;
        let start = self.config.progress_rate_scale_start;
        let end = self.config.progress_rate_scale_end;
        let min_scale = self.config.progress_rate_min_scale;

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
        let sustain_secs = self.config.sustain_duration.as_secs_f64();
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
        observed_duration >= self.config.min_observation_duration
            && score_above_threshold_duration >= self.config.sustain_duration
    }

    fn sample_score_risk(
        &self,
        up_rate_bps: u64,
        progress_delta: f64,
        required_progress_delta: f64,
    ) -> f64 {
        let rate_risk = normalized_rate_risk(up_rate_bps, self.config.target_rate_bps);
        let progress_risk = normalized_progress_risk(progress_delta, required_progress_delta);
        let weight_total = self.config.weight_rate + self.config.weight_progress;
        if weight_total <= 0.0 {
            return 0.0;
        }

        let weighted_risk = ((self.config.weight_rate * rate_risk)
            + (self.config.weight_progress * progress_risk))
            / weight_total;
        let floor_risk = (self.config.rate_risk_floor * rate_risk).clamp(0.0, 1.0);

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
        remaining_reban_cooldown(last_ban_expires_at, observed_at, self.config.reban_cooldown)
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

        if self.config.churn.enabled
            && evaluation.session.churn_reconnect_count >= self.config.churn.min_reconnects
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
