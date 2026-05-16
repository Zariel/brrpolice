use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime},
};

use proptest::prelude::*;

use crate::{
    config::{BanLadderConfig, ChurnPolicyConfig, FiltersConfig, PolicyConfig, ScorePolicyConfig},
    types::{
        BanDisposition, ExemptionReason, OffenceHistory, PeerContext, PeerPolicyInput,
        PeerSessionState, PeerSnapshot, TorrentScope,
    },
};

use super::{
    PeerPolicy, PolicyRegistry, RECEIVE_IDLE_POLICY_NAME, SCORE_POLICY_NAME,
    receive_idle::ReceiveIdleSessionSnapshot,
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
        let slow_risk = super::score::normalized_rate_risk(slow, target);
        let fast_risk = super::score::normalized_rate_risk(fast, target);

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
        let low_risk = super::score::normalized_progress_risk(low, required);
        let high_risk = super::score::normalized_progress_risk(high, required);

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
        let registry = PolicyRegistry::new(config.clone(), &FiltersConfig::default());

        let mut elapsed = 120_u64;
        let mut progress = 0.10_f64;
        let mut session = None;

        for (sample_secs, up_rate_bps, progress_delta) in steps {
            elapsed += sample_secs;
            progress = (progress + progress_delta).min(0.90);
            let peer = seeded_peer(elapsed, progress, up_rate_bps);
            let evaluation = registry.evaluate_peer(&peer, session.as_ref());

            prop_assert!((0.0..=config.score.max_score).contains(&evaluation.session.ban_score));
            prop_assert!(evaluation.session.ban_score_above_threshold_duration <= evaluation.session.observed_duration);
            prop_assert!(evaluation.session.bad_duration <= evaluation.session.observed_duration);

            session = Some(evaluation.session);
        }
    }
}

#[test]
fn uses_torrent_ip_port_for_observation_identity_and_torrent_ip_for_offence_identity() {
    let registry = PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default());
    let peer = test_peer();

    let observation = registry.peer_observation_id(&peer);
    let offence = registry.offence_identity(&peer);

    assert_eq!(observation.torrent_hash, "abc123");
    assert_eq!(observation.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
    assert_eq!(observation.peer_port, 51413);
    assert_eq!(offence.torrent_hash, "abc123");
    assert_eq!(offence.peer_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
}

#[test]
fn constructs_enabled_policy_list_from_config() {
    let default_registry = PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default());
    let default_names = default_registry
        .enabled_peer_policies()
        .into_iter()
        .map(|policy| policy.name())
        .collect::<Vec<_>>();
    assert_eq!(
        default_names,
        vec![SCORE_POLICY_NAME, RECEIVE_IDLE_POLICY_NAME]
    );

    let receive_idle_only = PolicyRegistry::new(
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
    let registry = PolicyRegistry::new(PolicyConfig::default(), &filters);

    assert_eq!(
        registry.classify_exemption(&test_peer()),
        Some(ExemptionReason::AllowlistedPeer)
    );
}

#[test]
fn classifies_near_complete_exemption() {
    let registry = PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default());
    let mut peer = test_peer();
    peer.peer.progress = 0.99;
    peer.first_seen_at = SystemTime::UNIX_EPOCH;
    peer.observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);

    assert_eq!(
        registry.classify_exemption(&peer),
        Some(ExemptionReason::NearComplete {
            progress: 0.99,
            threshold: 0.95,
        })
    );
}

#[test]
fn classifies_grace_period_exemption() {
    let registry = PolicyRegistry::new(
        PolicyConfig {
            new_peer_grace_period: Duration::from_secs(300),
            ..PolicyConfig::default()
        },
        &FiltersConfig::default(),
    );

    match registry.classify_exemption(&test_peer()) {
        Some(ExemptionReason::NewPeerGracePeriod { grace_period, .. }) => {
            assert_eq!(grace_period, Duration::from_secs(300));
        }
        other => panic!("expected grace period exemption, got {other:?}"),
    }
}

#[test]
fn classifies_active_ban_exemption_after_grace_period() {
    let registry = PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default());
    let mut peer = test_peer();
    peer.first_seen_at = SystemTime::UNIX_EPOCH;
    peer.observed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(3600);
    peer.has_active_ban = true;

    assert_eq!(
        registry.classify_exemption(&peer),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let baseline = registry.required_progress_delta(Duration::from_secs(120), 1_000);
    let scaled = registry.required_progress_delta(Duration::from_secs(120), 4_000);

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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let initial = seeded_peer(0, 0.10, 500);
    let mut session = registry.begin_session(&initial, None);

    for offset in [120, 240] {
        let evaluation = registry.evaluate_peer(&seeded_peer(offset, 0.1005, 500), Some(&session));
        assert!(evaluation.is_bad_sample);
        assert!(!evaluation.is_bannable);
        session = evaluation.session;
    }

    let evaluation = registry.evaluate_peer(&seeded_peer(360, 0.1010, 500), Some(&session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let mut session = PeerSessionState {
        observation_id: PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default())
            .peer_observation_id(&seeded_peer(0, 0.10, 500)),
        offence_identity: registry.offence_identity(&seeded_peer(0, 0.10, 500)),
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

    let evaluation = registry.evaluate_peer(&seeded_peer(420, 0.13, 2_000), Some(&session));
    assert!(!evaluation.is_bad_sample);
    assert!(!evaluation.is_bannable);
    assert_eq!(evaluation.session.bad_duration, Duration::from_secs(240));
    session = evaluation.session;

    let second = registry.evaluate_peer(&seeded_peer(720, 0.20, 2_000), Some(&session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let mut peer = seeded_peer(120, 0.10, 500);
    let previous = PeerSessionState {
        observation_id: registry.peer_observation_id(&peer),
        offence_identity: registry.offence_identity(&peer),
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

    let resumed = registry.begin_session(&peer, Some(&previous));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let initial = test_peer();
    let session = registry.begin_session(&initial, None);

    let evaluation = registry.evaluate_peer(&test_peer(), Some(&session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let mut previous = registry
        .evaluate_peer(&seeded_peer(120, 0.10, 500), None)
        .session;
    previous.ban_score = 3.0;
    previous.ban_score_above_threshold_duration = Duration::from_secs(120);

    let evaluation = registry.evaluate_peer(&seeded_peer(180, 0.10, 0), Some(&previous));

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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let evaluation = registry.evaluate_peer(&seeded_peer(120, 0.10, 500), None);
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let initial = seeded_peer(60, 0.10, 500);
    let first = registry.evaluate_peer(
        &seeded_peer(120, 0.111, 500),
        Some(&registry.begin_session(&initial, None)),
    );
    assert!(!first.is_bad_sample);

    let second = registry.evaluate_peer(&seeded_peer(180, 0.127, 500), Some(&first.session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let initial = seeded_peer(60, 0.10, 500);
    let mut session = registry.begin_session(&initial, None);
    let mut final_eval = None;
    for observed_secs in [120, 180, 240, 300, 360] {
        let evaluation =
            registry.evaluate_peer(&seeded_peer(observed_secs, 0.10, 500), Some(&session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let evaluation = registry.evaluate_peer(&seeded_peer(120, 0.10, 500), None);

    assert_eq!(
        registry.decide_ban(&seeded_peer(120, 0.10, 500), &evaluation, &empty_history()),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);

    assert_eq!(
        registry.decide_ban(
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);

    match registry.decide_ban(
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);

    match registry.decide_ban(&peer, &evaluation, &empty_history()) {
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);

    match registry.decide_ban(
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = test_peer();
    let evaluation = registry.evaluate_peer(&peer, None);

    assert!(matches!(
        registry.decide_ban(&peer, &evaluation, &empty_history()),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);
    let first_session = match registry.decide_ban(&peer, &evaluation, &empty_history()) {
        BanDisposition::Ban(_) => {
            registry.record_ban_decision(&evaluation.session, peer.observed_at)
        }
        other => panic!("expected ban decision, got {other:?}"),
    };

    let next_peer = seeded_peer(240, 0.10, 500);
    let next_evaluation = registry.evaluate_peer(&next_peer, Some(&first_session));
    assert_eq!(
        registry.decide_ban(&next_peer, &next_evaluation, &empty_history()),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let peer = seeded_peer(180, 0.10, 500);
    let evaluation = registry.evaluate_peer(&peer, None);
    let banned_session = registry.record_ban_decision(&evaluation.session, peer.observed_at);

    let recovered_peer = seeded_peer(420, 0.20, 5_000);
    let recovered = registry.evaluate_peer(&recovered_peer, Some(&banned_session));
    assert!(matches!(
        registry.decide_ban(&recovered_peer, &recovered, &empty_history()),
        BanDisposition::NotBannableYet { .. }
    ));
    assert_eq!(recovered.session.last_ban_decision_at, None);

    let relapsed_peer = seeded_peer(540, 0.20, 500);
    let relapsed = registry.evaluate_peer(&relapsed_peer, Some(&recovered.session));
    assert!(matches!(
        registry.decide_ban(
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let mut session = None;
    let mut final_disposition = None;
    for (observed_secs, progress) in [(60, 0.10), (120, 0.1005), (180, 0.1010), (240, 0.1015)] {
        let peer = seeded_peer(observed_secs, progress, 500);
        let evaluation = registry.evaluate_peer(&peer, session.as_ref());
        final_disposition = Some(registry.decide_ban(&peer, &evaluation, &empty_history()));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = seeded_peer(120, 0.10, 500);
    let first_eval = registry.evaluate_peer(&first, None);
    assert!(matches!(
        registry.decide_ban(&first, &first_eval, &empty_history()),
        BanDisposition::NotBannableYet { .. }
    ));

    let mut reconnected = seeded_peer(240, 0.1005, 500);
    reconnected.peer.port = 51414;
    let second_eval = registry.evaluate_peer(&reconnected, Some(&first_eval.session));

    assert_eq!(second_eval.session.observation_id.peer_port, 51414);
    assert_eq!(
        second_eval.session.first_seen_at,
        first_eval.session.first_seen_at
    );
    assert!(matches!(
        registry.decide_ban(&reconnected, &second_eval, &empty_history()),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

    let mut second_peer = seeded_peer(180, 0.10, 1);
    second_peer.peer.port = 51414;
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    assert!(second.is_bad_sample);
    assert_eq!(second.session.churn_reconnect_count, 1);
    assert!((second.session.churn_amplifier - 0.0).abs() < 0.0001);
    assert!((second.effective_sample_score_risk - second.sample_score_risk).abs() < 0.0001);

    let mut third_peer = seeded_peer(240, 0.10, 1);
    third_peer.peer.port = 51415;
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));
    assert!(third.is_bad_sample);
    assert_eq!(third.session.churn_reconnect_count, 2);
    assert!((third.session.churn_amplifier - 0.3).abs() < 0.0001);
    assert!((third.effective_sample_score_risk - (third.sample_score_risk * 1.3)).abs() < 0.0001);

    let mut fourth_peer = seeded_peer(300, 0.10, 1);
    fourth_peer.peer.port = 51416;
    let fourth = registry.evaluate_peer(&fourth_peer, Some(&third.session));
    assert!(fourth.is_bad_sample);
    assert_eq!(fourth.session.churn_reconnect_count, 3);
    assert!((fourth.session.churn_amplifier - 0.6).abs() < 0.0001);
    assert!((fourth.effective_sample_score_risk - (fourth.sample_score_risk * 1.6)).abs() < 0.0001);
}

#[test]
fn churn_amplifier_does_not_accumulate_for_healthy_reconnects() {
    let config = PolicyConfig {
        new_peer_grace_period: Duration::from_secs(1),
        decay_window: Duration::from_secs(600),
        score: churn_enabled_score_policy_for_tests(),
        ..PolicyConfig::default()
    };
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(120, 0.10, 10_000), None);
    assert!(!first.is_bad_sample);

    let mut second_peer = seeded_peer(180, 0.12, 10_000);
    second_peer.peer.port = 51414;
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    assert!(!second.is_bad_sample);
    assert_eq!(second.session.churn_reconnect_count, 1);
    assert!((second.session.churn_amplifier - 0.0).abs() < 0.0001);

    let mut third_peer = seeded_peer(240, 0.14, 10_000);
    third_peer.peer.port = 51415;
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let previous = PeerSessionState {
        observation_id: registry.peer_observation_id(&seeded_peer(120, 0.10, 900)),
        offence_identity: registry.offence_identity(&seeded_peer(120, 0.10, 900)),
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
    let evaluation = registry.evaluate_peer(&peer, Some(&previous));

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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

    let mut second_peer = seeded_peer(180, 0.10, 1);
    second_peer.peer.port = 51414;
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    assert!((second.session.churn_amplifier - 0.5).abs() < 0.0001);

    let mut third_peer = seeded_peer(240, 0.10, 1);
    third_peer.peer.port = 51415;
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(120, 0.10, 1), None);

    let mut second_peer = seeded_peer(180, 0.10, 1);
    second_peer.peer.port = 51414;
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    assert!(second.session.churn_amplifier > 0.0);

    let mut exempt_peer = seeded_peer(240, 0.99, 1);
    exempt_peer.peer.port = 51415;
    let exempt = registry.evaluate_peer(&exempt_peer, Some(&second.session));

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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let peer = seeded_peer(240, 0.1015, 500);
    let initial = registry.evaluate_peer(&peer, None);
    let banned_session = registry.record_ban_decision(&initial.session, peer.observed_at);

    let recovered_peer = seeded_peer(1140, 0.20, 5_000);
    let recovered = registry.evaluate_peer(&recovered_peer, Some(&banned_session));

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
        let registry = PolicyRegistry::new(PolicyConfig::default(), &filters);
        let evaluation = registry.evaluate_peer(&peer, None);
        match registry.decide_ban(&peer, &evaluation, &empty_history()) {
            BanDisposition::Exempt(reason) => assert_eq!(reason, expected, "{name}"),
            other => panic!("expected exemption for {name}, got {other:?}"),
        }
    }
}

#[test]
fn receive_idle_bans_after_sustained_zero_upload_progress() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first_peer = seeded_peer_with_uploaded(180, 0);
    let first = registry.evaluate_receive_idle_peer(&first_peer, None);
    assert!(!first.is_bad_sample);
    assert!(!first.is_bannable);

    let second_peer = seeded_peer_with_uploaded(240, 0);
    let second = registry.evaluate_receive_idle_peer(&second_peer, Some(&first.session));
    assert!(second.is_bad_sample);
    assert!(second.is_bannable);

    match registry.decide_receive_idle_ban(&second_peer, &second, &empty_history()) {
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
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let second = registry
        .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(210, 0), Some(&first.session));
    assert!(second.is_bad_sample);
    assert_eq!(second.session.bad_duration, Duration::from_secs(30));
    assert!(!second.is_bannable);

    let third_peer = seeded_peer_with_uploaded(240, 0);
    let third = registry.evaluate_receive_idle_peer(&third_peer, Some(&second.session));
    assert!(third.is_bad_sample);
    assert_eq!(third.session.bad_duration, Duration::from_secs(60));
    assert!(third.is_bannable);

    match registry.decide_receive_idle_ban(&third_peer, &third, &empty_history()) {
        BanDisposition::Ban(decision) => assert_eq!(decision.reason_code, "receive_idle"),
        other => panic!("expected receive idle ban, got {other:?}"),
    }
}

#[test]
fn receive_idle_rejects_incompatible_session_payload_version() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let mut previous = first.session.clone();
    previous.policy_version = "policy-v2".to_string();

    let policy = registry.receive_idle_policy();
    let history = empty_history();
    let peer = seeded_peer_with_uploaded(210, 0);
    let previous = ReceiveIdleSessionSnapshot { session: previous };
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
fn receive_idle_rejects_incompatible_session_policy_name() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let mut previous = first.session.clone();
    previous.policy_name = SCORE_POLICY_NAME.to_string();

    let policy = registry.receive_idle_policy();
    let history = empty_history();
    let peer = seeded_peer_with_uploaded(210, 0);
    let previous = ReceiveIdleSessionSnapshot { session: previous };
    let error = policy
        .assess_peer(PeerPolicyInput {
            peer: &peer,
            previous_session: Some(&previous),
            offence_history: &history,
        })
        .unwrap_err();

    assert!(error.to_string().contains("received `score` session"));
}

#[test]
fn score_policy_preserves_registry_decision_and_state_summary() {
    let config = PolicyConfig {
        new_peer_grace_period: Duration::from_secs(1),
        score: score_policy_for_tests(60, 30, 0.01),
        ..PolicyConfig::default()
    };
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());
    let policy = registry.score_policy();
    let peer = seeded_peer(180, 0.10, 500);
    let history = OffenceHistory {
        offence_count: 2,
        last_ban_expires_at: None,
    };
    let direct_evaluation = registry.evaluate_peer(&peer, None);
    let direct_disposition = registry.decide_ban(&peer, &direct_evaluation, &history);
    let policy_assessment = policy
        .assess_peer(PeerPolicyInput {
            peer: &peer,
            previous_session: None,
            offence_history: &history,
        })
        .unwrap();

    assert_eq!(policy_assessment.disposition, direct_disposition);
    assert_eq!(
        policy_assessment.evaluation.offence_identity(),
        &direct_evaluation.session.offence_identity
    );
    assert_eq!(
        policy_assessment.evaluation.bad_duration(),
        direct_evaluation.session.bad_duration
    );
    assert_eq!(
        policy_assessment.evaluation.avg_upload_rate_bps(),
        direct_evaluation.session.rolling_avg_up_rate_bps
    );
    assert_eq!(
        policy_assessment.evaluation.is_bannable(),
        direct_evaluation.is_bannable
    );
    assert_eq!(
        policy_assessment.diagnostic_bool("threshold_met"),
        Some(true)
    );
}

#[test]
fn score_policy_rejects_incompatible_session_snapshot() {
    let registry = PolicyRegistry::new(PolicyConfig::default(), &FiltersConfig::default());
    let policy = registry.score_policy();
    let peer = seeded_peer(180, 0.10, 500);
    let previous = registry.begin_receive_idle_session(&peer, None);
    let previous = ReceiveIdleSessionSnapshot { session: previous };
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
fn receive_idle_policy_preserves_registry_decision_and_state_summary() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let policy = registry.receive_idle_policy();
    let first_peer = seeded_peer_with_uploaded(180, 0);
    let first = registry.evaluate_receive_idle_peer(&first_peer, None);
    let second_peer = seeded_peer_with_uploaded(240, 0);
    let history = empty_history();
    let direct_evaluation = registry.evaluate_receive_idle_peer(&second_peer, Some(&first.session));
    let direct_disposition =
        registry.decide_receive_idle_ban(&second_peer, &direct_evaluation, &history);
    let previous = ReceiveIdleSessionSnapshot {
        session: first.session,
    };
    let policy_assessment = policy
        .assess_peer(PeerPolicyInput {
            peer: &second_peer,
            previous_session: Some(&previous),
            offence_history: &history,
        })
        .unwrap();

    assert_eq!(policy_assessment.disposition, direct_disposition);
    assert_eq!(
        policy_assessment.evaluation.offence_identity(),
        &direct_evaluation.session.offence_identity
    );
    assert_eq!(
        policy_assessment.evaluation.bad_duration(),
        direct_evaluation.session.bad_duration
    );
    assert_eq!(
        policy_assessment.evaluation.avg_upload_rate_bps(),
        direct_evaluation.session.last_upload_rate_bps
    );
    assert_eq!(
        policy_assessment.evaluation.is_bannable(),
        direct_evaluation.is_bannable
    );
    assert_eq!(
        policy_assessment.diagnostic_bool("threshold_met"),
        Some(true)
    );
}

#[test]
fn receive_idle_does_not_count_absent_gap_as_idle_time() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let second = registry
        .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(210, 0), Some(&first.session));
    assert_eq!(second.session.bad_duration, Duration::from_secs(30));

    let returned_peer = seeded_peer_with_uploaded(600, 0);
    let returned = registry.evaluate_receive_idle_peer(&returned_peer, Some(&second.session));

    assert!(!returned.is_bad_sample);
    assert_eq!(returned.session.bad_duration, Duration::ZERO);
    assert!(!returned.is_bannable);
}

#[test]
fn receive_idle_resets_on_uploaded_byte_progress() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let second = registry
        .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(240, 0), Some(&first.session));
    assert!(second.is_bad_sample);

    let third = registry
        .evaluate_receive_idle_peer(&seeded_peer_with_uploaded(300, 1), Some(&second.session));
    assert!(!third.is_bad_sample);
    assert_eq!(third.session.bad_duration, Duration::ZERO);
    assert!(!third.is_bannable);
}

#[test]
fn receive_idle_missing_uploaded_bytes_is_not_bannable() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let mut first_peer = seeded_peer_with_uploaded(180, 0);
    first_peer.peer.uploaded_bytes = None;
    let first = registry.evaluate_receive_idle_peer(&first_peer, None);

    let mut second_peer = seeded_peer_with_uploaded(240, 0);
    second_peer.peer.uploaded_bytes = None;
    let second = registry.evaluate_receive_idle_peer(&second_peer, Some(&first.session));

    assert_eq!(second.uploaded_delta_bytes, None);
    assert!(!second.is_bad_sample);
    assert!(!second.is_bannable);
}

#[test]
fn receive_idle_uses_policy_specific_reban_cooldown() {
    let registry = PolicyRegistry::new(receive_idle_test_config(), &FiltersConfig::default());
    let first = registry.evaluate_receive_idle_peer(&seeded_peer_with_uploaded(180, 0), None);
    let peer = seeded_peer_with_uploaded(240, 0);
    let evaluation = registry.evaluate_receive_idle_peer(&peer, Some(&first.session));
    let history = OffenceHistory {
        offence_count: 1,
        last_ban_expires_at: Some(peer.observed_at - Duration::from_secs(300)),
    };

    match registry.decide_receive_idle_ban(&peer, &evaluation, &history) {
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first_peer = seeded_peer(120, 0.10, 1);
    let first = registry.evaluate_peer(&first_peer, None);
    assert!(matches!(
        registry.decide_ban(&first_peer, &first, &empty_history()),
        BanDisposition::NotBannableYet { .. }
    ));

    let second_peer = seeded_peer(180, 0.10, 1);
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    match registry.decide_ban(&second_peer, &second, &empty_history()) {
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(60, 0.10, 1), None);
    let second = registry.evaluate_peer(&seeded_peer(120, 0.106, 1), Some(&first.session));
    let third_peer = seeded_peer(180, 0.112, 1);
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));

    assert!(third.session.ban_score < 0.1);
    assert!(matches!(
        registry.decide_ban(&third_peer, &third, &empty_history()),
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first_peer = seeded_peer(61, 0.10, 1);
    let first = registry.evaluate_peer(&first_peer, None);
    assert!((first.sample_score_risk - 1.0).abs() < 0.0001);

    let second_peer = seeded_peer(121, 0.106, 1);
    let second = registry.evaluate_peer(&second_peer, Some(&first.session));
    assert!(second.sample_score_risk > 0.59);
    assert!(second.sample_score_risk < 0.6);

    let third_peer = seeded_peer(181, 0.112, 1);
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));
    match registry.decide_ban(&third_peer, &third, &empty_history()) {
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
    let registry = PolicyRegistry::new(config, &FiltersConfig::default());

    let first = registry.evaluate_peer(&seeded_peer(60, 0.10, 4_000), None);
    let second = registry.evaluate_peer(&seeded_peer(120, 0.104, 4_000), Some(&first.session));
    let third_peer = seeded_peer(180, 0.108, 4_000);
    let third = registry.evaluate_peer(&third_peer, Some(&second.session));

    assert!(third.sample_score_risk.abs() < f64::EPSILON);
    assert!(matches!(
        registry.decide_ban(&third_peer, &third, &empty_history()),
        BanDisposition::NotBannableYet { .. }
    ));
}
