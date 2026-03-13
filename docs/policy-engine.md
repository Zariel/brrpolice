# Policy Engine Overview

This document explains, at a high level, how `brrpolice` decides whether to ban a peer.

## Scope

Each poll cycle:

1. `brrpolice` asks qBittorrent for active torrents.
2. It keeps only completed torrents that pass configured category/tag filters and minimum seeder count.
3. For each peer on those torrents, it evaluates policy state.

## Identity and state

The policy engine tracks two related identities:

- Observation identity: `torrent_hash + peer_ip + peer_port`
- Offence identity: `torrent_hash + peer_ip`

The observation identity models the currently connected endpoint. The offence identity intentionally ignores port so reconnects on a new port still count toward the same behaviour history.

Per-peer session state is persisted in SQLite so score and timing survive restarts.

## Exemptions

A peer is immediately exempt when any of these apply:

- torrent is out of scope
- peer IP or CIDR is allowlisted
- peer progress is at or above `policy.ignore_peer_progress_at_or_above`
- peer is still inside `policy.new_peer_grace_period`
- peer already has an active ban

Exempt peers do not accumulate ban score for that sample.

## Score model

For non-exempt samples, risk is computed from:

- upload-rate risk: how far current upload rate is below `policy.score.target_rate_bps`
- progress risk: how far observed progress is below `policy.score.required_progress_delta`

The progress target is rate-aware. Once a peer is well above the upload target, the engine scales down the required progress expectation using:

- `policy.score.progress_rate_scale_start`
- `policy.score.progress_rate_scale_end`
- `policy.score.progress_rate_min_scale`

This keeps very fast peers from being treated the same as low-rate peers on large torrents where completion percentage moves more slowly.

Rate and progress risk are then combined by `policy.score.weight_rate` and `policy.score.weight_progress`, with `policy.score.rate_risk_floor` preventing very low upload rate from being fully masked by progress alone.

The running score:

1. Decays over time by `policy.score.decay_per_second`.
2. Adds the current sample risk after any churn amplification.
3. Is clamped to `policy.score.max_score`.

## Churn signal

If churn scoring is enabled, reconnect behaviour can amplify the current sample risk when all are true:

- reconnect count in `policy.score.churn.reconnect_window` is at least `policy.score.churn.min_reconnects`
- current sample is still poor
- peer is not exempt

The churn state decays over time by `policy.score.churn.decay_per_second` and is capped by `policy.score.churn.max_amplifier`.

The effective sample contribution is:

`effective_sample_score_risk = sample_score_risk * (1 + churn_amplifier)`

This means churn is a force multiplier on already-bad samples rather than an independent source of score. Reconnects by themselves should not turn a borderline peer into a ban.

## When a peer becomes bannable

A peer is bannable only when all conditions hold:

- observed long enough: `observed_duration >= policy.score.min_observation_duration`
- sustained poor score: score has remained above `policy.score.ban_threshold` for at least `policy.score.sustain_duration`
- no exemption applies
- re-ban cooldown is satisfied (`policy.reban_cooldown`)

Hysteresis uses two thresholds:

- `ban_threshold` to start/continue sustained-bad accumulation
- `clear_threshold` to reset sustained-bad accumulation after recovery

This reduces oscillation around a single threshold.

## Ban decision and enforcement

When bannable:

1. Offence number is derived from stored offence history.
2. Ban TTL is selected from `policy.ban_ladder.durations`.
3. A pending ban intent is persisted.
4. qBittorrent ban is applied.
5. Offence and active-ban records are persisted, and pending intent is cleared.

The pending intent exists so startup recovery can replay enforcement after partial failures.

## Recovery and expiry

On startup, `brrpolice` loads persisted peer sessions, active bans, and pending intents, then reconciles qBittorrent ban state.

Expired bans are reconciled and marked in storage so local state and qBittorrent remain consistent over time.

## Retention prune scheduling

Retention pruning currently runs inside the control loop. This is intentional because SQLite writes are serialized (`max_connections=1`), so a separate thread/task would not add write concurrency today and would add coordination complexity.

Revisit this and move pruning to a dedicated background task if one or more of these conditions hold in production:

- Prune duration regularly exceeds 25% of `qbittorrent.poll_interval`.
- Control-loop health/readiness degradation correlates with prune runs.
- Poll-cycle latency or retry frequency increases due to prune contention.
- Storage architecture changes to permit meaningful concurrent write throughput.
