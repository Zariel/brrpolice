# ADR-0006: Use Rate as the Primary Signal and Progress as Marginal Inefficiency

## Status

Accepted

## Context

`brrpolice` exists to block peers that waste local resources by consuming upload, cache, and I/O
for too long while providing poor value in return. The product question is not abstract peer
health. It is whether continuing to serve a peer is worth the local cost.

Current and recent experiments clarified several things:

- torrent size matters because it converts progress fractions into byte-domain movement
- pure size-aware scaling is not a good top-level policy direction
- completion-velocity-first models are too loose when used as the primary ban signal
- the false-positive class that still matters most is the peer on a very large torrent that takes
  a healthy amount of data from us but is banned because percentage progress appears too slow

The current score engine already tries to reduce this failure mode by scaling required progress
down for high-rate peers. That helps, but it does not fully encode the intended policy. Rate and
progress are still first-order composite inputs across the full rate range, so progress can remain
too influential outside the genuinely borderline cases.

At the same time, clearly bad peers are still usually identifiable by poor upload rate from us to
them. That signal remains the closest direct operational indicator that a peer is low value.

## Decision

The next policy direction will keep rate risk as the dominant primary ban signal.

Torrent progress will not act as an independent co-equal ban engine. Progress inefficiency will be
used to sharpen decisions only for peers whose upload rate is near the configured threshold and
therefore ambiguous on rate alone.

The governing question is:

> If a peer is hovering around the upload-rate threshold, are they progressing the torrent
> materially enough to justify the time and resources we are spending serving them?

This implies three operating regimes:

1. Clearly bad rate:
   - low upload rate alone can justify banning
   - progress may help explain the decision but must not be required to make the peer bannable
2. Marginal rate:
   - insufficient torrent progress should make the peer more bannable
   - this is the only regime where progress inefficiency should materially change the outcome
3. Clearly healthy rate:
   - slow-looking percentage progress on a large torrent must not, by itself, drive a ban
   - progress may be logged for diagnostics but must not be able to dominate the decision

This ADR accepts the policy shape, not a final formula. The exact curve, thresholds, and field
names remain implementation work.

## Design Constraints

Any implementation in this direction must satisfy all of these:

- rate remains the dominant primary signal
- a healthy-rate peer cannot become bannable from progress inefficiency alone
- torrent size is used only as a unit conversion between progress fraction and useful byte-domain
  movement, not as a corpus-derived normalization heuristic
- the same rate reference used to determine policy regime must be visible in logs, simulator
  output, and replay reports
- the resulting behavior must be explainable in peer-level reason strings and operator
  documentation

## Preferred Implementation Shape

Preferred direction:

1. Keep a primary rate-based risk signal.
2. Classify peers into clearly bad, marginal, and clearly healthy rate bands using a single,
   explicit rate reference relative to `policy.score.target_rate_bps`.
3. Convert progress observations into a byte-domain notion of useful movement using torrent size.
4. Apply progress inefficiency only inside the marginal-rate band, or in a bounded way that is
   mathematically equivalent to marginal-band-only influence.

Promising model shapes include:

- rate-primary amplification:
  - `effective_risk = rate_risk * (1 + bounded_inefficiency_penalty)`
- marginal-band add-on:
  - progress-derived penalty contributes only when rate is inside a configured band around the
    target
- piecewise policy regimes:
  - clearly bad, marginal, and clearly healthy bands have different scoring behavior

The intended effect is:

- low-rate peers remain bannable without needing a strong progress argument
- marginal peers pay a cost if they are not making material progress
- high-rate peers are protected from progress-only false positives on very large torrents

## Deferred Decisions

The ADR intentionally does not lock these details yet:

- whether the regime classifier should use instantaneous sample upload rate, rolling average upload
  rate, or another explicitly defined rate reference
- the exact marginal-band boundaries around `policy.score.target_rate_bps`
- whether progress inefficiency is expressed as a bounded multiplier, bounded additive term inside
  the marginal band, or equivalent piecewise rule
- the exact byte-domain progress metric exposed to logs and replay tooling
- final config names and migration strategy from the current weighted composite model

These are deferred because they should be chosen against replay evidence, not by prose alone.

## Acceptance Gates

No production implementation should land until replay and simulator results show all of these:

- known large-torrent false-positive peers are no longer banned because of progress-only pressure
  in the healthy-rate regime
- clearly poor low-rate peers remain bannable without requiring strong progress evidence
- marginal-rate peers become more separable than under the current policy, with peer-level output
  that explains whether rate or inefficiency drove the decision
- candidate reports include regime classification, rate reference, progress inefficiency inputs,
  and before/after decision deltas for the same peer observations
- at least the current policy, one rate-primary amplification variant, and one piecewise or
  bounded marginal-band variant are compared on the same corpus

## Non-Goals

- Treating progress risk as a standalone top-level ban reason for healthy high-rate peers
- Reintroducing corpus-derived size normalization as the main policy lever
- Replacing rate with completion velocity as the primary signal
- Shipping a formula change before replay tooling can explain why a peer changed outcome

## Consequences

### Positive

- The policy becomes more aligned with the actual product goal.
- It preserves the operational usefulness of rate as the primary control signal.
- It gives progress a narrower and more defensible role.
- It creates a cleaner basis for replay-driven tuning because regime behavior becomes explicit.

### Negative

- This is still a substantive redesign of the score model.
- Existing config, score fields, simulator output, and reason strings will likely need to change.
- Some earlier experiment families become supporting context rather than active candidates.
- The rollout requires better replay data and comparison reporting before implementation is safe.

## Follow-up Work

1. Define the replay corpus and pass/fail criteria for clearly bad, marginal, and clearly healthy
   rate bands.
2. Enrich replay inputs, simulator output, and logs so they expose torrent-size-derived movement,
   regime classification, and peer-level deltas between candidate policies.
3. Implement and compare at least one rate-primary amplification model and one piecewise or
   bounded marginal-band model against the current policy.
4. Implement the production model only after a candidate clearly beats the current policy on the
   known large-torrent false-positive class without weakening poor-peer safety.
5. Update operator-facing documentation and reason strings so decisions remain explainable after
   the model change.
