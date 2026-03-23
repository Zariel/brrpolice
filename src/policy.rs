#![allow(dead_code)]

use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use ipnet::IpNet;

use crate::{
    config::{FiltersConfig, PolicyConfig},
    types::{
        BanDecision, BanDisposition, ExemptionReason, OffenceHistory, OffenceIdentity, PeerContext,
        PeerEvaluation, PeerObservationId, PeerSessionState,
    },
};

#[derive(Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    allowlisted_ips: HashSet<IpAddr>,
    allowlisted_cidrs: Vec<IpNet>,
}

const SCORE_BASED_REASON_CODE: &str = "score_based";
const RATE_REFERENCE_NAME: &str = "rolling_avg_upload_rate_bps";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayScoreModel {
    CurrentComposite,
    RatePrimaryAmplified,
    RatePrimaryResidencyShoulder,
    RatePrimaryGatedResidencyShoulder,
    MarginalBandBounded,
}

impl ReplayScoreModel {
    pub fn key(self) -> &'static str {
        match self {
            Self::CurrentComposite => "current_composite",
            Self::RatePrimaryAmplified => "rate_primary_amplified",
            Self::RatePrimaryResidencyShoulder => "rate_primary_residency_shoulder",
            Self::RatePrimaryGatedResidencyShoulder => "rate_primary_gated_residency_shoulder",
            Self::MarginalBandBounded => "marginal_band_bounded",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::CurrentComposite => "Current weighted composite score model.",
            Self::RatePrimaryAmplified => {
                "Rate-primary risk with bounded progress amplification that cannot create bans on its own."
            }
            Self::RatePrimaryResidencyShoulder => {
                "Rate-primary risk with an above-target shoulder and residency pressure for long-lived peers."
            }
            Self::RatePrimaryGatedResidencyShoulder => {
                "Rate-primary risk with a narrow above-target shoulder gated to low-completion peers."
            }
            Self::MarginalBandBounded => {
                "Rate-primary model where progress inefficiency only contributes inside the marginal rate band."
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationInsights {
    pub rate_reference_name: &'static str,
    pub rate_reference_bps: u64,
    pub rate_reference_target_bps: u64,
    pub rate_reference_ratio: f64,
    pub rate_reference_band: &'static str,
    pub required_progress_delta: f64,
    pub torrent_total_size_bytes: u64,
    pub progress_delta_bytes: u64,
    pub required_progress_bytes: u64,
    pub progress_deficit_bytes: u64,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig, filters: &FiltersConfig) -> Self {
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
        let index = offence_number.saturating_sub(1) as usize;
        self.config
            .ban_ladder
            .durations
            .get(index)
            .copied()
            .unwrap_or_else(|| {
                *self
                    .config
                    .ban_ladder
                    .durations
                    .last()
                    .expect("ban ladder validated")
            })
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
        self.evaluate_peer_with_model(peer, existing, ReplayScoreModel::CurrentComposite)
    }

    pub fn evaluate_peer_with_model(
        &self,
        peer: &PeerContext,
        existing: Option<&PeerSessionState>,
        model: ReplayScoreModel,
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
                self.required_progress_delta(observed_duration, session.rolling_avg_up_rate_bps);
            let exemption = session.last_exemption_reason.clone();
            let is_bad_sample = exemption.is_none()
                && session.rolling_avg_up_rate_bps < self.config.score.target_rate_bps
                && progress_delta < required_progress_delta;
            if is_bad_sample {
                session.bad_duration = sample_duration;
            }
            let sample_score_risk = if exemption.is_some() {
                0.0
            } else {
                self.sample_score_risk(
                    model,
                    session.rolling_avg_up_rate_bps,
                    peer.peer.up_rate_bps,
                    peer.peer.progress,
                    progress_delta,
                    required_progress_delta,
                )
            };
            let effective_sample_score_risk =
                self.effective_sample_score_risk(sample_score_risk, session.churn_amplifier);
            if exemption.is_some() {
                session.ban_score_above_threshold_duration = Duration::ZERO;
            } else {
                session.ban_score = (session.ban_score + effective_sample_score_risk)
                    .clamp(0.0, self.config.score.max_score);
                if session.ban_score >= self.config.score.ban_threshold {
                    session.ban_score_above_threshold_duration = sample_duration;
                }
            }
            session.churn_amplifier = 0.0;

            let is_bannable = self.is_bannable(&session, exemption.is_none());
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
        let rolling_avg_up_rate_bps = self.weighted_rate(
            previous.rolling_avg_up_rate_bps,
            previous.observed_duration,
            peer.peer.up_rate_bps,
            sample_duration,
        );
        let baseline_progress = self.advance_progress_baseline(
            previous.baseline_progress,
            previous.latest_progress,
            sample_duration,
        );
        let progress_delta = (peer.peer.progress - baseline_progress).max(0.0);
        let required_progress_delta =
            self.required_progress_delta(observed_duration, rolling_avg_up_rate_bps);
        let exemption = self.classify_exemption(peer);
        let is_bad_sample = exemption.is_none()
            && rolling_avg_up_rate_bps < self.config.score.target_rate_bps
            && progress_delta < required_progress_delta;
        let reconnect = previous.observation_id != self.peer_observation_id(peer);
        let bad_duration = if is_bad_sample {
            previous.bad_duration + sample_duration
        } else {
            self.decay_bad_duration(previous.bad_duration, sample_duration)
        };
        let mut ban_score = self.decay_score(previous.ban_score, sample_duration);
        let mut ban_score_above_threshold_duration = previous.ban_score_above_threshold_duration;
        let sample_score_risk = if exemption.is_none() {
            self.sample_score_risk(
                model,
                rolling_avg_up_rate_bps,
                peer.peer.up_rate_bps,
                peer.peer.progress,
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
                exemption.is_none(),
            );
        let effective_sample_score_risk =
            self.effective_sample_score_risk(sample_score_risk, churn_amplifier);
        if exemption.is_some() {
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
            exemption.is_none(),
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
            rolling_avg_up_rate_bps,
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

    pub fn evaluate(&self) -> Vec<BanDecision> {
        Vec::new()
    }

    pub fn evaluation_insights(
        &self,
        peer: &PeerContext,
        evaluation: &PeerEvaluation,
    ) -> EvaluationInsights {
        let rate_reference_bps = evaluation.session.rolling_avg_up_rate_bps;
        let rate_reference_target_bps = self.config.score.target_rate_bps;
        let rate_reference_ratio =
            Self::rate_reference_ratio(rate_reference_bps, rate_reference_target_bps);
        let required_progress_delta =
            self.required_progress_delta(evaluation.session.observed_duration, rate_reference_bps);
        let torrent_total_size_bytes = peer.torrent.total_size_bytes;
        let progress_delta_bytes =
            progress_fraction_to_bytes(torrent_total_size_bytes, evaluation.progress_delta);
        let required_progress_bytes =
            progress_fraction_to_bytes(torrent_total_size_bytes, required_progress_delta);

        EvaluationInsights {
            rate_reference_name: RATE_REFERENCE_NAME,
            rate_reference_bps,
            rate_reference_target_bps,
            rate_reference_ratio,
            rate_reference_band: Self::rate_reference_band(rate_reference_ratio),
            required_progress_delta,
            torrent_total_size_bytes,
            progress_delta_bytes,
            required_progress_bytes,
            progress_deficit_bytes: required_progress_bytes.saturating_sub(progress_delta_bytes),
        }
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

    fn rate_reference_ratio(rate_reference_bps: u64, target_rate_bps: u64) -> f64 {
        if target_rate_bps == 0 {
            return 0.0;
        }

        rate_reference_bps as f64 / target_rate_bps as f64
    }

    fn rate_reference_band(rate_reference_ratio: f64) -> &'static str {
        if rate_reference_ratio < 0.5 {
            "clearly_bad"
        } else if rate_reference_ratio < 0.75 {
            "low_side_gray"
        } else if rate_reference_ratio <= 1.25 {
            "marginal"
        } else if rate_reference_ratio < 2.0 {
            "high_side_gray"
        } else {
            "clearly_healthy"
        }
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
        model: ReplayScoreModel,
        rate_reference_bps: u64,
        sample_up_rate_bps: u64,
        current_progress: f64,
        progress_delta: f64,
        required_progress_delta: f64,
    ) -> f64 {
        let rate_ratio =
            Self::rate_reference_ratio(rate_reference_bps, self.config.score.target_rate_bps);
        let progress_risk = normalized_progress_risk(progress_delta, required_progress_delta);
        let rate_risk = match model {
            ReplayScoreModel::CurrentComposite => {
                normalized_rate_risk(sample_up_rate_bps, self.config.score.target_rate_bps)
            }
            ReplayScoreModel::RatePrimaryAmplified => {
                normalized_rate_risk(rate_reference_bps, self.config.score.target_rate_bps)
            }
            ReplayScoreModel::RatePrimaryResidencyShoulder => {
                replay_rate_primary_base_risk(rate_ratio, 1.0, 1.5, 0.15)
            }
            ReplayScoreModel::RatePrimaryGatedResidencyShoulder => {
                normalized_rate_risk(rate_reference_bps, self.config.score.target_rate_bps)
            }
            ReplayScoreModel::MarginalBandBounded => {
                normalized_rate_risk(rate_reference_bps, self.config.score.target_rate_bps)
            }
        };

        match model {
            ReplayScoreModel::CurrentComposite => {
                let weight_total =
                    self.config.score.weight_rate + self.config.score.weight_progress;
                if weight_total <= 0.0 {
                    return 0.0;
                }

                let weighted_risk = ((self.config.score.weight_rate * rate_risk)
                    + (self.config.score.weight_progress * progress_risk))
                    / weight_total;
                let floor_risk = (self.config.score.rate_risk_floor * rate_risk).clamp(0.0, 1.0);

                weighted_risk.max(floor_risk)
            }
            ReplayScoreModel::RatePrimaryAmplified => {
                let healthy_taper = smooth_rolloff(rate_ratio, 1.0, 1.25);
                let amplification = 1.0 + (0.75 * progress_risk * healthy_taper);
                (rate_risk * amplification).clamp(0.0, 1.0)
            }
            ReplayScoreModel::RatePrimaryResidencyShoulder => {
                let healthy_taper = smooth_rolloff(rate_ratio, 1.0, 1.5);
                let residency_pressure = replay_residency_pressure(current_progress, progress_risk);
                let amplification = 1.0 + (1.4 * residency_pressure * healthy_taper);
                (rate_risk * amplification).clamp(0.0, 1.0)
            }
            ReplayScoreModel::RatePrimaryGatedResidencyShoulder => {
                let below_target_taper = smooth_rolloff(rate_ratio, 1.0, 1.25);
                let base_amplified =
                    rate_risk * (1.0 + (0.75 * progress_risk * below_target_taper));
                let above_target_taper = above_target_shoulder_taper(rate_ratio, 1.0, 1.15);
                let low_completion_gate = smooth_rolloff(current_progress, 0.20, 0.60);
                let residency_pressure = replay_residency_pressure(current_progress, progress_risk);
                let shoulder_risk =
                    0.18 * above_target_taper * low_completion_gate * residency_pressure;

                (base_amplified + shoulder_risk).clamp(0.0, 1.0)
            }
            ReplayScoreModel::MarginalBandBounded => {
                if !(0.75..=1.25).contains(&rate_ratio) {
                    return rate_risk;
                }

                (rate_risk + (0.6 * progress_risk)).clamp(0.0, 1.0)
            }
        }
    }

    fn effective_sample_score_risk(&self, sample_score_risk: f64, churn_amplifier: f64) -> f64 {
        if sample_score_risk <= 0.0 {
            return 0.0;
        }

        sample_score_risk * (1.0 + churn_amplifier.max(0.0))
    }

    fn remaining_reban_cooldown(
        &self,
        last_ban_expires_at: Option<SystemTime>,
        observed_at: SystemTime,
    ) -> Option<Duration> {
        let expiry = last_ban_expires_at?;
        let elapsed = observed_at.duration_since(expiry).unwrap_or_default();
        if elapsed >= self.config.reban_cooldown {
            return None;
        }

        Some(self.config.reban_cooldown - elapsed)
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

fn progress_fraction_to_bytes(total_size_bytes: u64, progress_fraction: f64) -> u64 {
    if total_size_bytes == 0 || !progress_fraction.is_finite() || progress_fraction <= 0.0 {
        return 0;
    }

    ((total_size_bytes as f64) * progress_fraction.clamp(0.0, 1.0)).round() as u64
}

fn replay_rate_primary_base_risk(
    rate_ratio: f64,
    shoulder_start: f64,
    shoulder_end: f64,
    shoulder_floor: f64,
) -> f64 {
    if !rate_ratio.is_finite() {
        return 0.0;
    }
    if rate_ratio <= shoulder_start {
        let below_target_risk = (1.0 - rate_ratio).clamp(0.0, 1.0);
        return (shoulder_floor + ((1.0 - shoulder_floor) * below_target_risk)).clamp(0.0, 1.0);
    }

    (shoulder_floor * smooth_rolloff(rate_ratio, shoulder_start, shoulder_end)).clamp(0.0, 1.0)
}

fn replay_residency_pressure(current_progress: f64, progress_risk: f64) -> f64 {
    let current_progress = current_progress.clamp(0.0, 1.0);
    let remaining_fraction = 1.0 - current_progress;
    let weighted = (0.55 * progress_risk) + (0.75 * remaining_fraction);
    weighted.clamp(0.0, 1.0)
}

fn above_target_shoulder_taper(value: f64, start: f64, end: f64) -> f64 {
    if !value.is_finite() || value <= start {
        return 0.0;
    }

    smooth_rolloff(value, start, end)
}

fn smooth_rolloff(value: f64, start: f64, end: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    if value <= start {
        return 1.0;
    }
    if value >= end || end <= start {
        return 0.0;
    }

    let progress = ((value - start) / (end - start)).clamp(0.0, 1.0);
    let smoothstep = progress * progress * (3.0 - (2.0 * progress));
    1.0 - smoothstep
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
            BanDisposition, ExemptionReason, OffenceHistory, PeerContext, PeerSessionState,
            PeerSnapshot, TorrentScope,
        },
    };

    use super::PolicyEngine;

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
    fn smooth_rolloff_is_full_before_start_and_zero_after_end() {
        assert_eq!(super::smooth_rolloff(0.9, 1.0, 1.5), 1.0);
        assert_eq!(super::smooth_rolloff(1.0, 1.0, 1.5), 1.0);
        assert_eq!(super::smooth_rolloff(1.5, 1.0, 1.5), 0.0);
        assert_eq!(super::smooth_rolloff(1.6, 1.0, 1.5), 0.0);
    }

    #[test]
    fn smooth_rolloff_transitions_smoothly_inside_window() {
        let early = super::smooth_rolloff(1.1, 1.0, 1.5);
        let mid = super::smooth_rolloff(1.25, 1.0, 1.5);
        let late = super::smooth_rolloff(1.4, 1.0, 1.5);

        assert!(early < 1.0 && early > mid);
        assert!((mid - 0.5).abs() < 0.0001);
        assert!(late < mid && late > 0.0);
    }

    #[test]
    fn replay_rate_primary_base_risk_keeps_a_small_above_target_shoulder() {
        let below = super::replay_rate_primary_base_risk(0.9, 1.0, 1.5, 0.15);
        let at_target = super::replay_rate_primary_base_risk(1.0, 1.0, 1.5, 0.15);
        let slightly_above = super::replay_rate_primary_base_risk(1.1, 1.0, 1.5, 0.15);
        let clearly_healthy = super::replay_rate_primary_base_risk(1.6, 1.0, 1.5, 0.15);

        assert!(below > at_target);
        assert!(at_target > slightly_above);
        assert!(slightly_above > 0.0);
        assert_eq!(clearly_healthy, 0.0);
    }

    #[test]
    fn replay_residency_pressure_rewards_high_completion_and_penalizes_low_completion() {
        let near_done = super::replay_residency_pressure(0.92, 0.2);
        let early = super::replay_residency_pressure(0.08, 0.2);
        let inefficient_early = super::replay_residency_pressure(0.08, 1.0);

        assert!(near_done < early);
        assert!(inefficient_early > early);
        assert!(inefficient_early <= 1.0);
    }

    #[test]
    fn gated_residency_shoulder_only_activates_for_low_completion_peers() {
        let low_completion_gate = super::smooth_rolloff(0.10, 0.20, 0.60);
        let mid_completion_gate = super::smooth_rolloff(0.40, 0.20, 0.60);
        let high_completion_gate = super::smooth_rolloff(0.75, 0.20, 0.60);

        assert!(low_completion_gate > mid_completion_gate);
        assert!(mid_completion_gate > 0.0);
        assert_eq!(high_completion_gate, 0.0);
    }

    #[test]
    fn above_target_shoulder_taper_is_zero_until_rate_exceeds_target() {
        assert_eq!(super::above_target_shoulder_taper(0.95, 1.0, 1.15), 0.0);
        assert_eq!(super::above_target_shoulder_taper(1.0, 1.0, 1.15), 0.0);
        assert!(super::above_target_shoulder_taper(1.05, 1.0, 1.15) > 0.0);
        assert_eq!(super::above_target_shoulder_taper(1.2, 1.0, 1.15), 0.0);
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

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 0), None);

        let mut second_peer = seeded_peer(180, 0.10, 0);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(second.is_bad_sample);
        assert_eq!(second.session.churn_reconnect_count, 1);
        assert!((second.session.churn_amplifier - 0.0).abs() < 0.0001);
        assert!((second.effective_sample_score_risk - second.sample_score_risk).abs() < 0.0001);

        let mut third_peer = seeded_peer(240, 0.10, 0);
        third_peer.peer.port = 51415;
        let third = engine.evaluate_peer(&third_peer, Some(&second.session));
        assert!(third.is_bad_sample);
        assert_eq!(third.session.churn_reconnect_count, 2);
        assert!((third.session.churn_amplifier - 0.3).abs() < 0.0001);
        assert!(
            (third.effective_sample_score_risk - (third.sample_score_risk * 1.3)).abs() < 0.0001
        );

        let mut fourth_peer = seeded_peer(300, 0.10, 0);
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

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 0), None);

        let mut second_peer = seeded_peer(180, 0.10, 0);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!((second.session.churn_amplifier - 0.5).abs() < 0.0001);

        let mut third_peer = seeded_peer(240, 0.10, 0);
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

        let first = engine.evaluate_peer(&seeded_peer(120, 0.10, 0), None);

        let mut second_peer = seeded_peer(180, 0.10, 0);
        second_peer.peer.port = 51414;
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!(second.session.churn_amplifier > 0.0);

        let mut exempt_peer = seeded_peer(240, 0.99, 0);
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

    fn test_peer() -> PeerContext {
        seeded_peer(120, 0.25, 1024)
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
                total_size_bytes: 1_000_000,
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
            },
            first_seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(observed_secs),
            has_active_ban: false,
        }
    }

    #[test]
    fn evaluation_insights_report_rate_band_and_byte_metrics() {
        let config = PolicyConfig {
            score: ScorePolicyConfig {
                target_rate_bps: 1_000,
                required_progress_delta: 0.02,
                sustain_duration: Duration::from_secs(120),
                ..ScorePolicyConfig::default()
            },
            ..PolicyConfig::default()
        };
        let engine = PolicyEngine::new(config, &FiltersConfig::default());

        let peer = seeded_peer(180, 0.11, 2_000);
        let evaluation = engine.evaluate_peer(&peer, None);
        let insights = engine.evaluation_insights(&peer, &evaluation);

        assert_eq!(insights.rate_reference_name, "rolling_avg_upload_rate_bps");
        assert_eq!(insights.rate_reference_band, "clearly_healthy");
        assert_eq!(insights.torrent_total_size_bytes, 1_000_000);
        assert_eq!(insights.progress_delta_bytes, 0);
        assert_eq!(insights.required_progress_bytes, 20_000);
        assert_eq!(insights.progress_deficit_bytes, 20_000);
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

        let first_peer = seeded_peer(120, 0.10, 0);
        let first = engine.evaluate_peer(&first_peer, None);
        assert!(matches!(
            engine.decide_ban(&first_peer, &first, &empty_history()),
            BanDisposition::NotBannableYet { .. }
        ));

        let second_peer = seeded_peer(180, 0.10, 0);
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

        let first = engine.evaluate_peer(&seeded_peer(60, 0.10, 0), None);
        let second = engine.evaluate_peer(&seeded_peer(120, 0.106, 0), Some(&first.session));
        let third_peer = seeded_peer(180, 0.112, 0);
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

        let first_peer = seeded_peer(61, 0.10, 0);
        let first = engine.evaluate_peer(&first_peer, None);
        assert!((first.sample_score_risk - 1.0).abs() < 0.0001);

        let second_peer = seeded_peer(121, 0.106, 0);
        let second = engine.evaluate_peer(&second_peer, Some(&first.session));
        assert!((second.sample_score_risk - 0.6).abs() < 0.0001);

        let third_peer = seeded_peer(181, 0.112, 0);
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
