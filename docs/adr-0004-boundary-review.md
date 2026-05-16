# ADR-0004 Boundary Review

Review date: 2026-05-16

## Result

ADR-0004's policy-engine boundary is implemented for the production control-loop path.

The control loop evaluates configured peer-ban policies through `PeerPolicy` trait objects. It does
not match on score versus receive-idle to load state, assess peers, persist assessment state, record
enforcement, emit policy metrics, log policy outcomes, or replay pending intents. Policy selection is
limited to startup construction of the enabled policy list and the replay registry.

## Review Scope

The review checked production code for concrete policy branches and implementation-name matches in:

- `src/control.rs`
- `src/metrics.rs`
- `src/persistence.rs`
- `src/policy.rs`
- `src/types.rs`

The audit also checked tests and docs separately so regression fixtures that mention score and
receive-idle do not get confused with production orchestration behavior.

## Remaining Concrete References

Allowed concrete references:

- `PolicyEngine::enabled_peer_policies` and `PolicyEngine::replay_peer_policies` construct the
  compiled runtime policy registry from config.
- Score and receive-idle policies downcast only the opaque session/evaluation state that they
  created.
- Receive-idle validates its own `policy_name` and payload version before reusing generic session
  state.
- Persistence still exposes legacy score-session and score-enforcement helpers. These are called
  from the score policy as compatibility plumbing for existing `peer_sessions` rows, not from the
  generic control-loop path.
- Tests and migration fixtures mention concrete policy names to prove compatibility, replay,
  migration, and multi-policy ordering semantics.

No production logging, metrics, pending-intent replay, ban merge, or qBittorrent enforcement path
branches over concrete policy implementations after policy construction.

## Follow-Up

The only remaining score-specific production plumbing is the legacy score session/enforcement storage
path. It is contained behind the score policy today, but should be retired after the rollout window
once operators have had a retention period on the generic policy API.

Tracked as `brrpolice-f9iu`.
