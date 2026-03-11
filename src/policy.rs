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

const SLOW_NON_PROGRESSING_REASON_CODE: &str = "slow_non_progressing";

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
            peer_ip: peer.peer.ip,
        }
    }

    pub fn classify_exemption(&self, peer: &PeerContext) -> Option<ExemptionReason> {
        if !peer.torrent.in_scope {
            return Some(ExemptionReason::TorrentExcluded);
        }

        if peer.torrent.total_seeders < self.config.min_total_seeders {
            return Some(ExemptionReason::InsufficientSeeders {
                total_seeders: peer.torrent.total_seeders,
                required_seeders: self.config.min_total_seeders,
            });
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
            session.first_seen_at = previous.first_seen_at;
            session.baseline_progress = previous.baseline_progress.min(peer.peer.progress);
            session.rolling_avg_up_rate_bps = previous.rolling_avg_up_rate_bps;
            session.observed_duration = previous.observed_duration;
            session.bad_duration = self.decay_bad_duration(previous.bad_duration, gap);
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
            let progress_delta = 0.0;
            let exemption = session.last_exemption_reason.clone();
            let is_bad_sample = exemption.is_none()
                && peer.peer.up_rate_bps < self.config.slow_rate_bps
                && progress_delta < self.config.min_progress_delta;
            if is_bad_sample {
                session.bad_duration = sample_duration;
            }

            let is_bannable = exemption.is_none()
                && session.observed_duration >= self.config.min_observation_duration
                && session.bad_duration >= self.config.bad_for_duration;
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
            };
        }

        let previous = existing
            .cloned()
            .unwrap_or_else(|| self.begin_session(peer, None));

        let sample_duration = peer
            .observed_at
            .duration_since(previous.last_seen_at)
            .unwrap_or_default();
        let progress_delta = (peer.peer.progress - previous.latest_progress).max(0.0);
        let exemption = self.classify_exemption(peer);
        let is_bad_sample = exemption.is_none()
            && peer.peer.up_rate_bps < self.config.slow_rate_bps
            && progress_delta < self.config.min_progress_delta;
        let observed_duration = previous.observed_duration + sample_duration;
        let mut bad_duration = self.decay_bad_duration(previous.bad_duration, sample_duration);
        if is_bad_sample {
            bad_duration += sample_duration;
        }

        let is_bannable = exemption.is_none()
            && observed_duration >= self.config.min_observation_duration
            && bad_duration >= self.config.bad_for_duration;
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
            baseline_progress: previous.baseline_progress,
            latest_progress: peer.peer.progress,
            rolling_avg_up_rate_bps: self.weighted_rate(
                previous.rolling_avg_up_rate_bps,
                previous.observed_duration,
                peer.peer.up_rate_bps,
                sample_duration,
            ),
            observed_duration,
            bad_duration,
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
                bad_duration: evaluation.session.bad_duration,
                required_bad_duration: self.config.bad_for_duration,
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
        BanDisposition::Ban(BanDecision {
            peer_ip: peer.peer.ip,
            peer_port: peer.peer.port,
            offence_number,
            ttl: self.ban_ttl_for_offence(offence_number),
            reason_code: SLOW_NON_PROGRESSING_REASON_CODE.to_string(),
            reason_details: format!(
                "slow peer: avg_up_rate_bps={} progress_delta={:.4} bad_seconds={} observed_seconds={}",
                evaluation.session.rolling_avg_up_rate_bps,
                evaluation.progress_delta,
                evaluation.session.bad_duration.as_secs(),
                evaluation.session.observed_duration.as_secs()
            ),
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

        let decay_ratio =
            self.config.bad_for_duration.as_secs_f64() / self.config.decay_window.as_secs_f64();
        let decay = elapsed.mul_f64(decay_ratio);
        bad_duration.saturating_sub(decay)
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
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, SystemTime},
    };

    use crate::{
        config::{BanLadderConfig, FiltersConfig, PolicyConfig},
        types::{
            BanDisposition, ExemptionReason, OffenceHistory, PeerContext, PeerSessionState,
            PeerSnapshot, TorrentScope,
        },
    };

    use super::PolicyEngine;

    #[test]
    fn uses_torrent_ip_port_for_observation_identity_and_ip_for_offence_identity() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let peer = test_peer();

        let observation = engine.peer_observation_id(&peer);
        let offence = engine.offence_identity(&peer);

        assert_eq!(observation.torrent_hash, "abc123");
        assert_eq!(observation.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
        assert_eq!(observation.peer_port, 51413);
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

    #[test]
    fn classifies_insufficient_seeders_before_peer_checks() {
        let engine = PolicyEngine::new(PolicyConfig::default(), &FiltersConfig::default());
        let mut peer = test_peer();
        peer.torrent.total_seeders = 1;

        assert_eq!(
            engine.classify_exemption(&peer),
            Some(ExemptionReason::InsufficientSeeders {
                total_seeders: 1,
                required_seeders: 3,
            })
        );
    }

    #[test]
    fn accumulates_bad_time_until_peer_is_bannable() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(300),
            bad_for_duration: Duration::from_secs(180),
            decay_window: Duration::from_secs(600),
            slow_rate_bps: 1_000,
            min_progress_delta: 0.01,
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
        assert_eq!(evaluation.session.bad_duration, Duration::from_secs(288));
    }

    #[test]
    fn decays_bad_time_when_peer_improves() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            bad_for_duration: Duration::from_secs(300),
            decay_window: Duration::from_secs(600),
            min_progress_delta: 0.01,
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
            bad_for_duration: Duration::from_secs(300),
            decay_window: Duration::from_secs(600),
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
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
            decay_window: Duration::from_secs(600),
            min_progress_delta: 0.01,
            slow_rate_bps: 1_000,
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
    fn returns_not_bannable_until_thresholds_are_met() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(600),
            bad_for_duration: Duration::from_secs(300),
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
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
            reban_cooldown: Duration::from_secs(300),
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
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
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
                assert_eq!(decision.reason_code, "slow_non_progressing");
                assert!(decision.reason_details.contains("slow peer"));
            }
            other => panic!("expected ban decision, got {other:?}"),
        }
    }

    #[test]
    fn selects_first_ban_ladder_rung_for_first_offence() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
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
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
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
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
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
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(60),
            bad_for_duration: Duration::from_secs(30),
            decay_window: Duration::from_secs(60),
            reban_cooldown: Duration::from_secs(30),
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
            min_observation_duration: Duration::from_secs(180),
            bad_for_duration: Duration::from_secs(120),
            decay_window: Duration::from_secs(600),
            slow_rate_bps: 1_000,
            min_progress_delta: 0.01,
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
            min_observation_duration: Duration::from_secs(180),
            bad_for_duration: Duration::from_secs(120),
            decay_window: Duration::from_secs(600),
            slow_rate_bps: 1_000,
            min_progress_delta: 0.01,
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
    fn simulation_healthy_recovery_clears_bannable_state() {
        let config = PolicyConfig {
            new_peer_grace_period: Duration::from_secs(1),
            min_observation_duration: Duration::from_secs(180),
            bad_for_duration: Duration::from_secs(120),
            decay_window: Duration::from_secs(600),
            slow_rate_bps: 1_000,
            min_progress_delta: 0.01,
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
                "low_seeders",
                FiltersConfig::default(),
                {
                    let mut peer = seeded_peer(360, 0.10, 500);
                    peer.torrent.total_seeders = 1;
                    peer
                },
                ExemptionReason::InsufficientSeeders {
                    total_seeders: 1,
                    required_seeders: 3,
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
}
