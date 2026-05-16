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
`PolicyEngine` type also owns multiple concrete policy behaviors instead of exposing a common
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
policy list. After construction, policy-specific behavior should live behind the policy API.

The intended interface shape is:

```rust
trait PeerPolicy {
    fn name(&self) -> &'static str;
    fn assess_peer(&self, input: PeerPolicyInput<'_>) -> PeerPolicyAssessment;
}
```

`PeerPolicyInput` should contain only generic data needed by policies:

- the current peer and torrent context
- the previous policy session, if any
- offence history for this policy and offence identity
- shared eligibility information such as torrent scope, allowlist status, grace-period status, and
  active-ban status

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
  explicitly score-scoped metrics emitted by the score policy adapter.
- Trait-object ergonomics may require careful ownership choices for session state and diagnostics.

## Migration Notes

Start by introducing the generic policy API and adapting the existing score and receive-idle logic
behind it without changing ban semantics. Once the control loop can iterate policy implementations,
move pending-intent replay and enforcement persistence onto the same generic assessment/enforcement
records. After that, retire score-specific session plumbing or migrate it into the generic
`peer_policy_sessions` table.

This ADR does not require runtime plugin loading. The first goal is compile-time extensibility with
a clean orchestration boundary.
