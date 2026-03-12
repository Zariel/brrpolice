use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FALLBACK_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

fn seed_from_clock() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ FALLBACK_SEED
}

fn random_u64() -> u64 {
    let mut current = RNG_STATE.load(Ordering::Relaxed);
    if current == 0 {
        let seeded = seed_from_clock();
        let _ = RNG_STATE.compare_exchange(0, seeded, Ordering::Relaxed, Ordering::Relaxed);
        current = RNG_STATE.load(Ordering::Relaxed);
    }

    loop {
        let mut next = current;
        next ^= next << 13;
        next ^= next >> 7;
        next ^= next << 17;
        if next == 0 {
            next = FALLBACK_SEED;
        }
        match RNG_STATE.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

pub fn exponential_backoff(base: Duration, attempt: u32, max: Duration) -> Duration {
    let multiplier = 1_u32.checked_shl(attempt).unwrap_or(u32::MAX);
    let delay = base.saturating_mul(multiplier);
    delay.min(max)
}

pub fn with_full_jitter(delay: Duration) -> Duration {
    if delay.is_zero() {
        return delay;
    }

    let upper_ms = delay.as_millis().clamp(1, u128::from(u64::MAX)) as u64;
    let lower_ms = (upper_ms / 2).max(1);
    let spread = upper_ms.saturating_sub(lower_ms);
    let jittered_ms = if spread == 0 {
        lower_ms
    } else {
        lower_ms + (random_u64() % (spread + 1))
    };
    Duration::from_millis(jittered_ms)
}

pub fn jittered_exponential_backoff(base: Duration, attempt: u32, max: Duration) -> Duration {
    with_full_jitter(exponential_backoff(base, attempt, max))
}
