# ADR-0006 Candidate Comparison

## Status

Accepted

## Purpose

This document records the first replay comparison required by
[`adr-0006-evaluation-spec.md`](./adr-0006-evaluation-spec.md). It compares the current shipped
score model with replay-only ADR-0006 candidates on local corpora under `samples/logs`.

Throughout this document, `current_composite` is the replay stand-in for the behavior currently on
`main` and is the primary evaluation baseline. Candidate-to-candidate comparisons are included only
as secondary search guidance.

The corpus files are intentionally gitignored and are not part of this document. This report keeps
only aggregated outcomes and representative peer examples.

## Replay Command

The comparison runs used:

```bash
target/debug/score-simulator --compare-adr-0006 --corpus-name prod-fixed --input samples/logs/prod-logs-fixed.enriched.json
target/debug/score-simulator --compare-adr-0006 --corpus-name logs-2026-03-23 --input samples/logs/2026-03-23-logs-1.enriched.json
```

Comparison mode recomputes score state for every candidate from the same replay lines. It does not
hydrate the logged current-policy scores.

## Candidate Definitions

### `current_composite`

Current weighted composite score model using the existing rate and progress weighting. This is the
replay representation of the policy currently on `main`.

### `rate_primary_amplified`

Replay-only candidate using rolling average upload rate as the primary risk signal:

- base risk is normalized rate risk from the rolling reference rate
- progress inefficiency can only amplify existing rate risk
- progress amplification stays full up to `1.0x` target rate and then rolls off smoothly to zero
  by `1.25x` target rate
- progress cannot create risk when rate risk is zero

Formula shape:

```text
sample_risk = clamp(rate_risk * (1 + 0.75 * progress_risk * taper), 0, 1)
```

### `rate_primary_curved_shoulder`

Replay-only follow-up that keeps the same rate-primary family but makes the progress and shoulder
pressure more conservative with curved weighting:

- mid-range progress deficits are suppressed with a convex progress curve
- the below-target taper rolls off more steeply than the current amplified candidate
- the above-target shoulder also decays more steeply, so only near-target high deficits get any
  extra pressure

On the current corpora this produces the same aggregate and band outcomes as
`rate_primary_amplified`, so this class of curved marginal tuning appears too weak to move replay
results.

### `rate_primary_thresholded_accumulation`

Replay-only follow-up that keeps the `rate_primary_amplified` sample-risk shape but changes how
score accumulates:

- below target, only the stronger part of sample risk contributes materially
- above target, accumulation requires an even higher entry floor
- the goal is to stop moderate repeated risk from drifting across the same thresholds as clearly
  bad peers

On the current corpora this does move outcomes, but it weakens low-side and clearly-bad safety, so
it is not production-ready.

### `rate_primary_persistent_watch`

Replay-only follow-up that keeps the amplified base path and adds a separate above-target watch
signal that only accumulates after persistence:

- above-target watch samples need to persist across several observations
- the watch path also requires low completion and high progress deficit before it can add score

On the current corpora this ends up behaving the same as `rate_primary_amplified`, so the watch
signal is too weak in this form.

### `marginal_band_bounded`

Replay-only candidate using rolling average upload rate as the primary signal and adding progress
inefficiency only inside the ADR-0006 marginal band.

- outside `0.75x..=1.25x` target rate, risk is pure rate risk
- inside the marginal band, progress adds a bounded penalty

Formula shape:

```text
sample_risk = rate_risk                         when rate_ratio outside 0.75..=1.25
sample_risk = clamp(rate_risk + 0.6 * progress_risk, 0, 1) otherwise
```

### `rate_primary_residency_shoulder`

Replay-only candidate that keeps the rate-primary shape but adds two mechanisms that the simpler
amplified model lacks:

- a small above-target rate shoulder so peers slightly above target are not automatically safe
- a residency-pressure term that combines progress inefficiency with remaining completion so
  high-completion peers are protected and low-completion peers stay risky

This candidate was added after clarifying that "slightly above target" peers can still be strong
ban candidates when expected residency is long.

### `rate_primary_gated_residency_shoulder`

Replay-only follow-up that keeps the same intuition but applies it more conservatively:

- the shoulder only applies above target, not below it
- the shoulder narrows to `1.0x..1.15x` target rate
- the extra pressure only applies while completion is still low

On the current corpora this avoids the broad shoulder regression, but it ends up behaving
identically to `rate_primary_amplified` in aggregate.

### `rate_primary_gated_long_residency`

Replay-only follow-up built directly on `rate_primary_amplified` and intended to capture only the
specific above-target peers that are still likely to sit on resources for a long time:

- keep `rate_primary_amplified` as the base path
- add a separate lane only inside `1.0x..1.10x` target rate
- require very low completion and a very high progress deficit
- use `max(base_risk, long_residency_risk)` rather than additive scoring

On the current corpora this still over-bans badly against `main`, which suggests a sample-local
above-target lane is too easy to trigger across whole peer behaviors and floods score accumulation.

## Summary

### Corpus: `prod-fixed`

| candidate | peer behaviors | simulated bans | actual bans in log |
| --- | ---: | ---: | ---: |
| `current_composite` | 188 | 23 | 22 |
| `rate_primary_amplified` | 188 | 23 | 22 |
| `rate_primary_curved_shoulder` | 188 | 23 | 22 |
| `rate_primary_thresholded_accumulation` | 188 | 20 | 22 |
| `rate_primary_persistent_watch` | 188 | 23 | 22 |
| `rate_primary_residency_shoulder` | 188 | 24 | 22 |
| `rate_primary_gated_residency_shoulder` | 188 | 23 | 22 |
| `rate_primary_gated_long_residency` | 188 | 62 | 22 |
| `marginal_band_bounded` | 188 | 22 | 22 |

Key band outcomes versus current:

| candidate | clearly bad bans lost | clearly bad bans gained | marginal bans lost | clearly healthy bans lost | clearly healthy bans kept |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rate_primary_amplified` | 0 | 3 | 2 | 3 | 1 |
| `rate_primary_curved_shoulder` | 0 | 3 | 2 | 3 | 1 |
| `rate_primary_thresholded_accumulation` | 1 | 3 | 2 | 3 | 1 |
| `rate_primary_persistent_watch` | 0 | 3 | 2 | 3 | 1 |
| `rate_primary_residency_shoulder` | 0 | 3 | 1 | 3 | 1 |
| `rate_primary_gated_residency_shoulder` | 0 | 3 | 2 | 3 | 1 |
| `rate_primary_gated_long_residency` | 0 | 40 | 2 | 3 | 1 |
| `marginal_band_bounded` | 2 | 3 | 1 | 3 | 1 |

### Corpus: `logs-2026-03-23`

| candidate | peer behaviors | simulated bans | actual bans in log |
| --- | ---: | ---: | ---: |
| `current_composite` | 176 | 22 | 21 |
| `rate_primary_amplified` | 176 | 16 | 21 |
| `rate_primary_curved_shoulder` | 176 | 16 | 21 |
| `rate_primary_thresholded_accumulation` | 176 | 13 | 21 |
| `rate_primary_persistent_watch` | 176 | 16 | 21 |
| `rate_primary_residency_shoulder` | 176 | 23 | 21 |
| `rate_primary_gated_residency_shoulder` | 176 | 16 | 21 |
| `rate_primary_gated_long_residency` | 176 | 44 | 21 |
| `marginal_band_bounded` | 176 | 16 | 21 |

Key band outcomes versus current:

| candidate | clearly bad bans lost | clearly bad bans gained | marginal bans lost | high-side gray bans lost | clearly healthy bans lost | clearly healthy bans kept |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `rate_primary_amplified` | 0 | 1 | 2 | 2 | 3 | 5 |
| `rate_primary_curved_shoulder` | 0 | 1 | 2 | 2 | 3 | 5 |
| `rate_primary_thresholded_accumulation` | 0 | 1 | 2 | 2 | 4 | 3 |
| `rate_primary_persistent_watch` | 0 | 1 | 2 | 2 | 3 | 5 |
| `rate_primary_residency_shoulder` | 0 | 2 | 1 | 1 | 3 | 6 |
| `rate_primary_gated_residency_shoulder` | 0 | 1 | 2 | 2 | 3 | 5 |
| `rate_primary_gated_long_residency` | 0 | 26 | 2 | 2 | 3 | 5 |
| `marginal_band_bounded` | 1 | 1 | 1 | 1 | 4 | 4 |

## Representative Peer Examples

The examples below are anonymized case labels derived from the local replay output. Real torrent
names, trackers, hashes, and peer IPs are intentionally omitted.

### Healthy-rate rescues the ADR wants

These peers were banned by the current model despite clearly healthy rate bands and large
byte-domain progress deficits that appear to be percentage-driven artefacts:

- `prod-fixed healthy-case-a`:
  baseline banned, all rate-primary candidates keep; rate ratio `6.32`, progress deficit `2.33 GB`
- `prod-fixed healthy-case-b`:
  baseline banned, all rate-primary candidates keep; rate ratio `4.29`, progress deficit `2.67 GB`
- `logs-2026-03-23 healthy-case-c`:
  baseline banned, all rate-primary candidates keep; rate ratio `2.28`, progress deficit `1.60 GB`

### Healthy-rate regressions that remain unacceptable

No replay-only candidate cleared the healthy-rate hard gate:

- `prod-fixed` still ends with `1` clearly healthy simulated ban under all rate-primary candidates
- `logs-2026-03-23` still ends with `5` clearly healthy bans under `rate_primary_amplified`
  and `4` under `marginal_band_bounded`
- `logs-2026-03-23 healthy-regression-a` flips from keep to ban under
  `rate_primary_amplified` at rate ratio `2.11`

### Poor-peer safety regressions

`marginal_band_bounded` weakens low-rate safety and is not production-ready:

- `prod-fixed low-rate-regression-a`:
  clearly bad band, current bans, candidate keeps
- `prod-fixed low-rate-regression-b`:
  clearly bad band, current bans, candidate keeps
- `logs-2026-03-23` loses `1` clearly bad ban relative to current

`rate_primary_amplified` preserves clearly-bad ban status on these two corpora, but still weakens
current behaviour outside that narrow test:

- it drops `2` marginal-band bans on both corpora
- it drops `2` high-side-gray bans on `logs-2026-03-23`
- it still leaves healthy-rate bans in place

## Decision

This comparison completes the ADR-0006 candidate-family checkpoint, but it does not select a
production formula.

Current conclusion:

- against `main`, `rate_primary_amplified` is directionally closer to the ADR because it rescues
  several clearly healthy large-torrent peers while preserving clearly-bad ban status on these
  corpora
- `rate_primary_curved_shoulder` keeps the same overall behavior against `main`; the curved taper
  and penalty shape are conservative enough that they do not move aggregate or band outcomes on
  the current corpora
- `rate_primary_thresholded_accumulation` is the first replay-only branch that materially changes
  accumulation semantics, and it does reduce healthy-rate bans on the noisier corpus, but it also
  weakens low-side and clearly-bad safety and is therefore not acceptable as-is
- `rate_primary_persistent_watch` adds persistence semantics for above-target suspicion, but in
  this form it collapses back to the same outcomes as `rate_primary_amplified`
- `rate_primary_residency_shoulder` better matches the clarified product intuition for
  slightly-above-target, low-completion peers, but against `main` it overcorrects and becomes too
  ban-heavy on the noisier corpus
- `rate_primary_gated_residency_shoulder` fixes that over-banning by narrowing the shoulder to an
  above-target-only, low-completion gate, but against `main` it does not improve aggregate
  outcomes beyond the existing `rate_primary_amplified` candidate
- `rate_primary_gated_long_residency` keeps the base candidate and uses a strict conjunctive lane,
  but against `main` it still over-bans badly, especially by gaining many bans inside peer
  behaviors that fall into the clearly-bad cohort overall
- even the best current candidate against `main`, `rate_primary_amplified`, still fails the
  healthy-rate hard gate and remains too permissive in marginal and high-side-gray cases
- `marginal_band_bounded` is not acceptable in its current form because it weakens clearly-bad
  low-rate safety while still leaving healthy-rate bans behind

## Follow-up Iteration

The next refinement passes tested seven ideas:

1. A stricter taper for `rate_primary_amplified`:
   - full progress influence at or below `1.0x` target rate
   - smooth rolloff between `1.0x` and `1.25x`
   - zero progress influence above `1.25x`
2. A curved `rate_primary_curved_shoulder` follow-up:
   - convex progress penalty to suppress mid-range deficits
   - steeper below-target taper
   - steeper above-target shoulder
3. A `rate_primary_thresholded_accumulation` follow-up:
   - keep the amplified sample-risk shape
   - only stronger sample risk contributes materially to score
   - use stricter accumulation floors above target
4. A `rate_primary_persistent_watch` follow-up:
   - keep the amplified base path
   - add a separate above-target watch signal
   - only accumulate that signal after persistence
5. A separate `rate_primary_residency_shoulder` candidate:
   - small above-target base-risk shoulder through `1.5x`
   - residency pressure from low completion plus progress inefficiency
6. A narrower `rate_primary_gated_residency_shoulder` follow-up:
   - shoulder only above target, never below it
   - shoulder narrowed to `1.0x..1.15x`
   - extra pressure only while completion remains low
7. A `rate_primary_gated_long_residency` follow-up:
   - keep `rate_primary_amplified` as the base path
   - open a second lane only in `1.0x..1.10x`
   - require `<=10%` completion and `>=0.95` progress risk
   - take `max(base_risk, long_residency_risk)` instead of adding a broad shoulder

Results:

- the stricter taper did not materially change aggregate outcomes for `rate_primary_amplified`
- the curved shoulder candidate also did not materially change aggregate or band outcomes relative
  to `rate_primary_amplified`
- the thresholded accumulation candidate is the first branch that materially changes replay
  outcomes without exploding, but it buys that by dropping to `20` simulated bans on `prod-fixed`
  and `13` on `logs-2026-03-23`, including a clearly-bad loss on `prod-fixed` and a low-side-gray
  loss on `logs-2026-03-23`
- the persistent watch candidate did not materially change outcomes relative to
  `rate_primary_amplified`
- the broad residency-shoulder candidate improved marginal losses on `prod-fixed` from `2` to `1`
  relative to `main`, but regressed badly on `logs-2026-03-23`, increasing total simulated bans
  from `22` on `main` to `23`
- the gated residency-shoulder candidate removed that regression relative to `main`, but it also
  failed to improve aggregate outcomes beyond `rate_primary_amplified`
- the gated long-residency candidate regressed badly on both corpora, jumping from `23` to `62`
  simulated bans on `prod-fixed` and from `22` to `44` on `logs-2026-03-23`

Current interpretation:

- the rate-primary tapered-amplification family is still the most credible ADR-0006 direction to
  keep iterating on
- the specific taper refinement is not enough to unblock production work
- conservative curved tapering and progress weighting were also too weak to move outcomes on the
  current corpora
- changing accumulation semantics does move outcomes, which means the search should keep focusing
  there rather than on more taper tuning, but the first thresholded version is too permissive to
  preserve poor-peer safety
- persistence semantics for above-target watch signals are plausible, but the first version is too
  weak to move the replay results
- a broad above-target shoulder over-bans, while a tightly gated shoulder becomes too weak to move
  replay outcomes on the current corpora
- a single-sample long-residency lane also over-bans, which suggests any above-target residency
  path probably needs explicit persistence or separate state rather than one-sample gating
- shoulder and taper tuning alone still appear insufficient to select a production winner

## Consequence For Backlog

`brrpolice-d6br.4` should not start from either candidate in this document. More candidate
iteration is required before a production ADR-0006 model can be selected, but future refinement
should start from the `rate_primary_amplified` family rather than the bounded marginal-band
variant, should treat `rate_primary_residency_shoulder` as an informative failed branch rather
than the new baseline, and should treat `rate_primary_gated_residency_shoulder` as evidence that
conservative shoulder/taper tuning can quickly collapse back to the same outcomes as the current
best candidate without materially improving on `main`, and should treat
`rate_primary_gated_long_residency` as evidence that sample-local conjunctive gating is still too
coarse for the above-target residency problem. Future search should favor accumulation and
threshold semantics over additional shoulder/taper micro-tuning.
