# ADR-0003: Model Churn as Sample Amplification

## Status

Implemented

## Context

The score-based policy currently treats reconnect churn as an additive contribution to the
overall ban score. A reconnecting peer accumulates a `churn_penalty` state that decays over
time, and when the current sample is classified as bad, that penalty is added directly to the
score alongside the sample risk.

This has a useful property: reconnect churn matters only when the peer is also behaving
poorly. However, it also has a sharp edge. Because the churn term is additive and can grow
independently of the current sample quality, it can dominate borderline peers whose current
sample is only slightly below the policy threshold.

The observed failure mode is a peer with:

- a reasonable upload rate
- only a marginal progress deficit
- reconnect count at or just above the churn threshold

Under the current additive design, the churn term can become the main reason the peer is
banned. This is difficult to explain operationally and does not match the intended semantics:
churn should make clearly bad behavior worse, not create badness from a mostly healthy sample.

## Decision

Churn will be modeled as a bounded multiplicative amplifier on the current sample risk rather
than as an additive term on the accumulated score.

The intended shape is:

```text
effective_sample_risk = sample_score_risk * churn_multiplier
score += effective_sample_risk
```

Where:

- `sample_score_risk` remains the existing rate/progress composite
- `churn_multiplier` is `1.0` when churn is inactive
- `churn_multiplier` increases as reconnect churn accumulates within the churn window
- the churn state decays over time
- the multiplier is capped so it cannot explode

The churn state remains gated on poor sample quality. Reconnects by themselves do not trigger
bans.

## Design Notes

The preferred implementation shape is:

```text
churn_multiplier = 1.0 + churn_amplifier
```

Where `churn_amplifier`:

- ramps with reconnect count above the configured threshold
- decays over time using the existing churn decay semantics
- is bounded by a configured maximum

This preserves the useful memory of reconnect churn while ensuring that:

- zero or tiny sample risk stays zero or tiny
- churn increases the impact of already-bad samples
- churn cannot single-handedly convert a nearly healthy sample into a ban

## Consequences

### Positive

- Churn becomes a force multiplier rather than an independent ban engine.
- Borderline peers are less likely to be banned purely because they reconnected.
- Operational explanations become clearer because the primary cause remains the sample quality.

### Negative

- Existing churn-related thresholds and defaults will need retuning.
- Historical comparisons against prior corpora will shift because the churn term no longer adds
  score directly.
- The simulator and regression corpus need explicit churn-heavy cases to keep tuning safe.

## Follow-up Work

- Define the exact reconnect-to-amplifier curve and parameter names.
- Replace additive churn contribution in the policy engine.
- Add regression coverage for borderline churn cases and known production examples.
- Re-tune churn defaults against the simulator corpus after the new model is in place.
