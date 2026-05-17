use super::*;

pub(super) const POLICY_VERSION: &str = "policy-v1";

pub(super) fn session_carryover_allowed(
    last_seen_at: SystemTime,
    observed_at: SystemTime,
    decay_window: Duration,
) -> bool {
    observed_at >= last_seen_at
        && observed_at.duration_since(last_seen_at).unwrap_or_default() <= decay_window
}

pub(super) fn progress_delta_per_mille(progress_delta: f64) -> u32 {
    if !progress_delta.is_finite() || progress_delta <= 0.0 {
        return 0;
    }

    (progress_delta * 1000.0)
        .round()
        .clamp(0.0, u32::MAX as f64) as u32
}

pub(super) fn ban_ttl_from_ladder(durations: &[Duration], offence_number: u32) -> Duration {
    let index = offence_number.saturating_sub(1) as usize;
    durations
        .get(index)
        .copied()
        .unwrap_or_else(|| *durations.last().expect("ban ladder validated"))
}

pub(super) fn remaining_reban_cooldown(
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
