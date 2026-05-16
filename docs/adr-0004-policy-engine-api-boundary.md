# ADR-0004: Separate Policy Assessment from Control Loop Orchestration

## Status

Proposed

## Context

`brrpolice` now has more than one peer-ban policy. The score policy and the receive-idle policy
share a lot of operational workflow: peers are loaded from qBittorrent, prior state is loaded from
SQLite, offence history is looked up, decisions are logged and counted, pending ban intents are
persisted, qBittorrent enforcement is attempted, and enforcement results are written back to
storage.

The current API does not make that workflow generic. The control loop has explicit branches for
`score` and `receive_idle`, and it knows which state type, persistence method, policy method,
metrics, logging fields, pending-intent fields, and startup replay shape each policy needs. The
`PolicyRegistry` type also owns multiple concrete policy behaviors instead of exposing a common
policy implementation interface.

This makes the next policy expensive to add. A new policy would require edits across the control
loop, persistence replay code, logging, metrics, and policy internals before the actual policy
logic can be expressed. That coupling also makes tests broad and brittle because generic
orchestration behavior is mixed with policy-specific behavior.

## Decision

Reshape peer-ban policy evaluation around a common policy implementation API.

The control loop will own an ordered list of enabled policy implementations. For every observed
peer, it will run the same generic workflow for each implementation:

- load the policy's previous session state by `policy_name` and peer identity
- load offence history by `policy_name` and offence identity
- pass the peer context, previous state, and offence history into the policy implementation
- persist the returned session state
- record generic metrics and logs from a bounded assessment summary
- persist pending ban intents before enforcement
- enforce bans through qBittorrent
- record enforcement and clear pending intents

The control loop should not branch on concrete policy names except while building the configured
policy list. After construction, policy-specific behavior should live behind the policy API. A
policy implementation receives the observation timestamp, previous state, offence history, and shared
eligibility result, then returns a bounded assessment. Runtime policies may also own policy-specific
persistence and metric mapping hooks behind the same interface, but they must not mutate qBittorrent
state, read wall-clock time, or require the upper orchestration path to match on concrete policy
implementations.

Previous-session and assessment state are opaque trait objects at the orchestration boundary. The
control loop may read only common summary methods such as `first_seen_at`, offence identity,
bad-duration seconds, average upload rate, sample count, and bad/bannable booleans. Concrete policy
state is downcast only inside the policy implementation that created it.

Policy reads go through a `PolicyDataStore` interface. Production poll cycles use a cycle-scoped
cache preloaded from batch session and offence-history queries for the in-scope torrent set. Runtime
policies still request previous state and offence history through the interface, which keeps the
control loop independent of whether state came from legacy score sessions, generic policy sessions,
or another implementation. The cache intentionally batches by observed torrent rather than by every
individual peer, trading some bounded over-read for fewer SQLite round trips on large swarms.

The intended interface shape is:

```rust
trait PeerPolicy {
    fn name(&self) -> &'static str;
    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> Result<PeerPolicyAssessment>;
}
```

`PeerPolicyInput` should contain only generic data needed by policies:

- the current peer and torrent context
- the previous policy session, if any
- offence history for this policy and offence identity
- shared eligibility information such as torrent scope, allowlist status, grace-period status, and
  active-ban status
- the observation timestamp supplied by the control loop

`PeerPolicyAssessment` should contain:

- updated policy session state
- a generic ban disposition
- bounded diagnostic fields for logs and metrics
- optional policy-specific details stored as structured state or structured diagnostics, not as
  control-loop branches

Policy session storage should use one generic session envelope for all policies. The envelope owns
common fields such as `policy_name`, observation identity, offence identity, first and last seen
timestamps, observed duration, bad duration, sample count, exemption state, bannable timestamp, and
last ban decision timestamp. Policy-specific state belongs in a structured payload such as
`state_json`.

The existing score and receive-idle behavior should become two implementations of this interface.
Shared exemption and identity helpers can remain shared support code, but they should not force the
control loop to know which concrete policy is running.

### API Contract

`PeerPolicyInput` borrows the current `PeerContext`, the previous persisted policy session, and the
offence history for exactly one `(policy_name, torrent_hash, peer_ip)` offence identity. The previous
session is optional and already filtered to the same policy. Policies may reject incompatible or
corrupt payloads with an assessment error, but they must not silently reinterpret another policy's
state. The control loop treats assessment errors as poll-cycle failures so invalid policy state does
not produce partial enforcement.

Policy-specific configuration is owned by the concrete policy implementation at construction time.
The generic input does not carry concrete config enums or untyped maps. Shared control-loop settings
that are policy-independent, such as the already-computed eligibility result and identity values,
are passed as generic input fields.

The observation timestamp is owned by the control loop and passed through `PeerContext`; policies
must derive durations from that timestamp and the prior session. This keeps tests deterministic and
prevents policies from observing different times within one poll cycle.

Shared eligibility is computed once for the current peer and passed into every policy. It includes
out-of-scope torrent, allowlist, near-complete progress, new-peer grace period, and already-active
ban decisions. Policies may add stricter policy-local guardrails, but they must not weaken a shared
exemption. A shared exemption produces an updated session and an `Exempt` disposition for every
enabled policy so every policy's state remains current.

`PeerPolicyAssessment` contains exactly one disposition:

- `Exempt` when shared or policy-local eligibility blocks a ban.
- `NotBannableYet` when the sample updates state but observation or sustain guardrails are not met.
- `RebanCooldown` when the policy-specific offence history is still cooling down.
- `DuplicateSuppressed` when this policy already made a ban decision for the same current session.
- `Ban` when the policy proposes a qBittorrent enforcement action.

The `Ban` payload is generic and must include the enforcement target IP and port, the
policy-specific offence number, the selected TTL, a bounded reason code, and a bounded reason
details string. The control loop derives `ban_expires_at` from its poll timestamp plus the TTL,
persists the pending intent from those generic fields, and uses the TTL/expiry to choose the longest
qBittorrent ban when multiple policies target the same IP. Policy assessment code does not write
offence rows or active-ban rows directly; any policy-specific persistence happens through the
generic runtime policy interface.

The assessment always includes the updated session, even when the disposition is not a ban. The
control loop persists that session before or alongside any pending intent so crash recovery sees the
same decision inputs that produced the intent.

Diagnostics are bounded name/value pairs with low-cardinality names owned by the policy
implementation. At most 8 diagnostics may be emitted per assessment. Names are static snake_case
identifiers no longer than 48 bytes; string values must be printable summaries no longer than 128
bytes. Diagnostics must not include unbounded peer client strings, torrent names, URLs, or free-form
remote data. High-cardinality operational context such as peer IP, torrent hash, and port remains
generic control-loop log context, not policy diagnostics. `threshold_met` is the shared boolean
diagnostic the control loop may use for generic not-bannable log state.

Policy metric labels are static labels provided by the runtime policy through the common interface.
Reason-code metric labels are selected by the policy from its fixed reason set, with unknown
policy-local reasons collapsed to `other`. Existing score-only histograms remain score-scoped
telemetry emitted by the score policy; additional policies should use generic counters unless they
need explicitly policy-scoped histograms.

The generic telemetry fields have finite value sets:

- Log `state`: `ban_pending`, `ban`, `ban_failed`, `ban_persist_failed`, `exempt`,
  `not_bannable`, `reban_cooldown`, or `duplicate_suppressed`.
- Metric `policy_name`: `score` or `receive_idle` for the current compiled runtime policies.
- Metric `sample`: `all` or `bad`.
- Metric `result`: `all`, `bannable`, `applied`, `failed`, or `expired`, depending on metric.
- Metric `decision`: `ban`, `not_bannable`, `exemption`, `reban_cooldown`, or
  `duplicate_suppressed`.
- Metric `reason_code`: `score_based`, `receive_idle`, or `other`.

Policy errors are reserved for invalid configuration, incompatible persisted payloads, arithmetic or
serialization failures, and other cases where a policy cannot produce a trustworthy assessment.
Ordinary non-ban outcomes are dispositions, not errors.

### Identity and Enforcement Semantics

The observation identity is `(policy_name, torrent_hash, peer_ip, peer_port)` for session storage.
The offence identity is `(policy_name, torrent_hash, peer_ip)` so reconnects on a new port continue
the policy-specific ladder for the same torrent/IP peer. qBittorrent enforcement is IP-global, so
active-ban checks are by peer IP and current torrent scope, while offence history and re-ban
cooldowns remain policy-specific.

All enabled policies assess every observed peer. There is no policy priority ordering and no
short-circuit when one policy proposes a ban. When several assessments propose bans for the same IP
in one cycle, each policy offence and pending intent is recorded under its own policy name and
offence number, but only the longest effective TTL is sent to qBittorrent for that IP.

Pending ban intents are unique by `(torrent_hash, peer_ip, policy_name, offence_number)`, matching
the policy offence identity. The current peer port is stored as enforcement metadata and updated if
the same policy offence is retried after a reconnect. Replay is idempotent: an expired intent is
skipped for retention pruning, an unknown policy name is retained with a diagnostic error,
enforcement failure updates `last_error`, and success records the policy-specific offence before
clearing only the matching intent.

## Consequences

### Positive

- Adding a new policy becomes mostly local to policy construction, policy logic, and tests.
- The control loop becomes easier to reason about because it handles one policy workflow.
- Pending-ban replay can become policy-name driven instead of hard-coded to known policy names.
- Logging and metrics remain consistent across policies while still allowing bounded diagnostics.
- Persistence has one session model instead of a special score path plus a partial generic path.

### Negative

- The refactor touches several core paths at once: control loop, policy types, persistence, replay,
  metrics, and tests.
- Existing score session data needs a compatibility path or migration into the generic session
  model.
- Some score-specific telemetry will need a generic diagnostic representation, or it must remain as
  explicitly score-scoped metrics emitted by the score policy.
- Trait-object ergonomics may require careful ownership choices for session state and diagnostics.

## Migration Notes

Implementation review: [`adr-0004-boundary-review.md`](adr-0004-boundary-review.md).

Start by introducing the generic policy API and moving the existing score and receive-idle logic
behind it without changing ban semantics. Policy construction is static at startup: enabled policy
flags decide which runtime policies evaluate new samples, while replay uses the compiled registry of
known policies so disabling a policy does not orphan pending pre-restart intents.

Configuration compatibility is part of the rollout. Existing score-policy config remains valid:
legacy `policy.reban_cooldown` and `policy.ban_ladder.durations` keys are score-policy aliases
unless the nested `policy.score.*` keys are explicitly set. New policy-specific settings live under
their own sections, such as `policy.receive_idle.*`, with independent cooldowns and ban ladders.

Once the control loop can iterate policy implementations, move pending-intent replay and enforcement
persistence onto the same generic assessment/enforcement records. After production has run through a
retention window with stable generic session reads and no unexpected payload errors, retire
score-specific session plumbing or migrate it into the generic `peer_policy_sessions` table.

This ADR does not require runtime plugin loading. The first goal is compile-time extensibility with
a clean orchestration boundary.

Rollback is compatible at the database level but not semantically lossless. Older binaries that do
not know `peer_policy_sessions`, `policy_name` on offences, or policy-name pending intents will
continue to use legacy score sessions and ignore generic sessions. If a rollback happens after a
new binary has written non-score pending intents, those intents will not be replayed by the older
binary and should be handled by rolling forward again or manually reconciling qBittorrent bans.
Policy implementations must reject incompatible payload versions for known policies rather than
silently reusing state. Unknown policy names and payloads are retained in storage for a future
compatible binary; retention pruning may eventually remove them according to configured retention
windows.
