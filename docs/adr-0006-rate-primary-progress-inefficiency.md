# ADR-0006: Use Rate as the Primary Signal and Progress as Marginal Inefficiency

## Status

Accepted

## Context

`brrpolice` exists to block peers that waste local resources by consuming upload, cache, and I/O
for too long while providing poor value in return. The most direct product concern is not abstract
peer health; it is whether serving a peer is worth the cost.

Current and recent experiments clarified several things:

- torrent size matters because it converts progress fractions into byte-domain movement
- pure size-aware scaling is not a good top-level policy direction
- completion-velocity-first models are too loose when used as the primary ban signal
- the false-positive class that still matters most is the peer on a very large torrent that takes
  a healthy amount of data from us but is banned because percentage progress appears too slow

At the same time, clearly bad peers are still usually identifiable by poor upload rate from us to
them. That signal remains the closest thing to a direct operational indicator that a peer is low
value.

## Decision

The next policy direction should keep rate risk as the primary ban signal.

Torrent progress should not act as an independent co-equal ban engine. Instead, progress
inefficiency should increase ban risk for peers whose upload rate is only marginally acceptable.

The core design question is:

> If a peer is hovering around the upload-rate threshold, are they progressing the torrent
> materially enough to justify the time and resources we are spending serving them?

This implies three operating regimes:

1. Clearly bad rate:
   - low upload rate alone can justify banning
2. Marginal rate:
   - insufficient torrent progress should make the peer more bannable
3. Clearly healthy rate:
   - slow-looking percentage progress on a large torrent should not, by itself, drive a ban

## Design Guidance

Preferred direction:

1. Keep a primary rate-based risk signal.
2. Use torrent size only to convert progress into a comparable notion of useful movement.
3. Apply progress inefficiency mainly in the marginal-rate band, where it helps distinguish peers
   that will linger for too long from peers that are acceptable to continue serving.

Promising model shapes include:

- rate-primary amplification:
  - `effective_risk = rate_risk * (1 + inefficiency_penalty)`
- marginal-band add-on:
  - progress-derived penalty contributes only when rate is near the configured threshold
- piecewise policy regimes:
  - different handling for clearly bad, marginal, and clearly healthy upload-rate bands

The intended effect is:

- low-rate peers remain bannable without needing a strong progress argument
- marginal peers pay a cost if they are not making material progress
- high-rate peers are protected from progress-only false positives on very large torrents

## Decision Criteria

Any candidate model in this direction must satisfy all of these:

- rate remains the dominant primary signal
- progress inefficiency cannot, by itself, dominate clearly healthy high-rate peers
- torrent size is used as a principled unit conversion, not as a corpus-derived heuristic
- the model reduces the known large-torrent false-positive class
- the model preserves safety on genuinely poor low-rate peers
- the resulting behavior is explainable in logs and documentation

## Non-Goals

- Treating progress risk as a standalone top-level ban reason for healthy high-rate peers
- Reintroducing corpus-derived size normalization as the main policy lever
- Replacing rate with completion velocity as the primary signal

## Consequences

### Positive

- The model is more closely aligned with the actual product goal.
- It preserves the operational usefulness of rate as the primary control signal.
- It gives progress a narrower, more defensible role.

### Negative

- This is still a substantive redesign of the score model.
- Existing score fields and logs may need to change to explain the new relationship cleanly.
- Some earlier experiment families become supporting context rather than active candidates.

## Follow-up Work

- Define explicit acceptance criteria for marginal-rate inefficiency decisions.
- Make replay inputs and reports rich enough to evaluate rate-band behavior and peer-level deltas.
- Compare at least the current policy, one rate-primary amplification model, and one piecewise or
  bounded marginal-band variant.
- Implement the production change only after a candidate clearly beats the current policy on the
  known false-positive class without weakening poor-peer safety.
