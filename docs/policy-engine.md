# Policy Engine Overview

This document explains, at a high level, how `brrpolice` decides whether to ban a peer.

## Scope

Each poll cycle:

1. `brrpolice` asks qBittorrent for active torrents.
2. It keeps only completed torrents that pass configured category/tag filters and minimum seeder count.
   When qBittorrent reports connected leecher counts for the torrent, completed torrents with zero
   connected leechers are skipped before peer detail is fetched. Connected seeds do not keep a
   completed torrent eligible because they are not upload recipients.
3. For each peer on those torrents, it evaluates policy state.

## Identity and state

Each enabled peer-ban policy tracks two related identities:

- Observation identity: `policy_name + torrent_hash + peer_ip + peer_port`
- Offence identity: `policy_name + torrent_hash + peer_ip`

The observation identity models the currently connected endpoint. The offence identity intentionally ignores port so reconnects on a new port still count toward the same policy-specific behaviour history and ban ladder.

Per-peer session state is persisted in SQLite so policy timing survives restarts. Score state is still read from the legacy `peer_sessions` table for compatibility, while generic policy sessions use `peer_policy_sessions` with a `policy_name` key and versioned policy state.

The control loop executes `RuntimePolicy` objects. That boundary combines the narrow `PeerPolicy`
assessment API with the storage and replay hooks needed to run a full poll cycle, while keeping
policy-local state opaque to orchestration. The control loop reads only common summary fields for
logging, metrics, identity, and enforcement. Concrete score or receive-idle state is interpreted only
by the concrete policy that produced it.

To avoid per-peer/per-policy database reads, each poll cycle preloads session and offence-history
rows for the in-scope torrent set into a cycle-scoped `PolicyDataStore` cache. Runtime policies still
load previous state and offence history through the same interface, so the orchestration layer does
not need to know whether a policy uses legacy score sessions, generic policy sessions, or future
policy-specific state. The tradeoff is that a cycle reads all policy rows for observed torrents,
which is preferable for active swarms because it replaces many small indexed reads with a few
bounded batch reads.

## Exemptions

A peer is immediately exempt when any of these apply:

- torrent is out of scope
- peer IP or CIDR is allowlisted
- peer progress is at or above `policy.ignore_peer_progress_at_or_above`
- peer is still inside `policy.new_peer_grace_period`
- peer already has an active ban

Exempt peers do not accumulate bad policy state for that sample. All enabled policies still record their current session state for the peer, so one policy proposing a ban does not short-circuit another policy's state progression.

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
- re-ban cooldown is satisfied (`policy.score.reban_cooldown`)

Hysteresis uses two thresholds:

- `ban_threshold` to start/continue sustained-bad accumulation
- `clear_threshold` to reset sustained-bad accumulation after recovery

This reduces oscillation around a single threshold.

## Ban decision and enforcement

When bannable:

1. Offence number is derived from stored policy-specific offence history.
2. Ban TTL is selected from the proposing policy's ban ladder.
3. A pending ban intent is persisted.
4. qBittorrent ban is applied.
5. Offence and active-ban records are persisted, and pending intent is cleared.

Every enabled policy evaluates the peer in a poll cycle. If several policies or torrents propose a ban for the same IP, `brrpolice` records each policy offence and pending intent separately, then sends only the longest effective TTL to qBittorrent for that IP. qBittorrent's `banned_IPs` preference is kept deduplicated by IP.

The pending intent exists so startup recovery can replay enforcement after partial failures.
Pending intents are unique by `torrent_hash + peer_ip + policy_name + offence_number`; peer port is retained as enforcement metadata and updated if the same policy offence is retried after reconnect. Startup replay uses a registry of known runtime policies, including policies currently disabled for new evaluations, so a valid pre-restart intent can still be enforced or retried. Unknown future policy names are retained with an error instead of being discarded.

## Telemetry

Policy logs use the same generic fields for every policy: state, policy name, torrent identity,
tracker hostname, peer IP and port, observation time, bad-time seconds, average upload rate, sample
count, latest peer progress, reason fields when present, and bounded policy diagnostics. The
control loop does not add score- or receive-idle-specific log branches; policy-specific detail is
reported as diagnostics.

Diagnostics are low-cardinality name/value pairs owned by the concrete policy. At most 8 diagnostics
may be emitted per assessment. Names are static snake_case identifiers no longer than 48 bytes, and
string values are printable summaries no longer than 128 bytes. Diagnostics must not include
unbounded peer client strings, torrent names, URLs, or raw remote data. `threshold_met` is the shared
boolean diagnostic the control loop may use for generic not-bannable log state.

Prometheus policy labels are static labels provided by the runtime policy through the common
interface. Reason-code metric labels are also selected by the policy from that policy's fixed
reason set, with unknown policy-local reasons collapsed to `other`. This keeps series cardinality
bounded by configured runtime policies rather than dynamic remote data, and it avoids concrete
policy matches in the metrics layer. Score-specific histograms remain score-scoped metrics emitted
by the score policy; receive-idle currently uses the generic policy counters and diagnostics.

Generic telemetry label sets are intentionally finite:

- Log `state`: `ban_pending`, `ban`, `ban_failed`, `ban_persist_failed`, `exempt`,
  `not_bannable`, `reban_cooldown`, or `duplicate_suppressed`.
- Metric `policy_name`: `score` or `receive_idle` for the current compiled runtime policies.
- Metric `sample`: `all` or `bad`.
- Metric `result`: `all`, `bannable`, `applied`, `failed`, or `expired`, depending on metric.
- Metric `decision`: `ban`, `not_bannable`, `exemption`, `reban_cooldown`, or
  `duplicate_suppressed`.
- Metric `reason_code`: `score_based`, `receive_idle`, or `other`.

## Rollout and config compatibility

Peer-ban policy construction is static at startup. `policy.score.enabled` and
`policy.receive_idle.enabled` decide which runtime policies evaluate new peer samples. Replay uses
the compiled registry of known runtime policies rather than only the enabled set, so disabling a
policy stops new assessments but does not orphan pending ban intents created before the restart.

Existing score-policy configuration remains compatible. The legacy top-level
`policy.reban_cooldown` and `policy.ban_ladder.durations` keys are treated as score-policy aliases
unless the nested `policy.score.reban_cooldown` or `policy.score.ban_ladder.durations` keys are set.
Operators should move new configuration to the nested policy sections because additional policies
have their own cooldown and ladder settings.

The database rollout is additive. Legacy score sessions stay readable for compatibility, while new
generic policy state is written to `peer_policy_sessions`. Pending ban intents and offence history
include `policy_name`, so policy ladders advance independently even when several policies nominate
the same IP in one poll cycle.

Rollout checkpoints for retiring old score-specific plumbing:

1. Release with the generic policy API, legacy score-session reads, and policy-name pending-intent
   replay enabled.
2. Observe production metrics and logs for unexpected invalid payloads, unsupported policy pending
   intents, or score/receive-idle decision drift.
3. After one retention window, consider migrating or pruning remaining legacy score session reads
   behind the score policy.
4. Remove legacy score aliases only in a future breaking config release with an explicit migration
   note.

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
