# ADR-0006 Candidate Comparison

## Status

Accepted

## Purpose

This document records the first replay comparison required by
[`adr-0006-evaluation-spec.md`](./adr-0006-evaluation-spec.md). It compares the current shipped
score model with two replay-only ADR-0006 candidates on local corpora under `samples/logs`.

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

Current weighted composite score model using the existing rate and progress weighting.

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

## Summary

### Corpus: `prod-fixed`

| candidate | peer behaviors | simulated bans | actual bans in log |
| --- | ---: | ---: | ---: |
| `current_composite` | 188 | 23 | 22 |
| `rate_primary_amplified` | 188 | 23 | 22 |
| `marginal_band_bounded` | 188 | 22 | 22 |

Key band outcomes versus current:

| candidate | clearly bad bans lost | clearly bad bans gained | marginal bans lost | clearly healthy bans lost | clearly healthy bans kept |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rate_primary_amplified` | 0 | 3 | 2 | 3 | 1 |
| `marginal_band_bounded` | 2 | 3 | 1 | 3 | 1 |

### Corpus: `logs-2026-03-23`

| candidate | peer behaviors | simulated bans | actual bans in log |
| --- | ---: | ---: | ---: |
| `current_composite` | 176 | 22 | 21 |
| `rate_primary_amplified` | 176 | 16 | 21 |
| `marginal_band_bounded` | 176 | 16 | 21 |

Key band outcomes versus current:

| candidate | clearly bad bans lost | clearly bad bans gained | marginal bans lost | high-side gray bans lost | clearly healthy bans lost | clearly healthy bans kept |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `rate_primary_amplified` | 0 | 1 | 2 | 2 | 3 | 5 |
| `marginal_band_bounded` | 1 | 1 | 1 | 1 | 4 | 4 |

## Representative Peer Examples

The examples below are anonymized case labels derived from the local replay output. Real torrent
names, trackers, hashes, and peer IPs are intentionally omitted.

### Healthy-rate rescues the ADR wants

These peers were banned by the current model despite clearly healthy rate bands and large
byte-domain progress deficits that appear to be percentage-driven artefacts:

- `prod-fixed healthy-case-a`:
  baseline banned, both candidates keep; rate ratio `6.32`, progress deficit `2.33 GB`
- `prod-fixed healthy-case-b`:
  baseline banned, both candidates keep; rate ratio `4.29`, progress deficit `2.67 GB`
- `logs-2026-03-23 healthy-case-c`:
  baseline banned, both candidates keep; rate ratio `2.28`, progress deficit `1.60 GB`

### Healthy-rate regressions that remain unacceptable

Neither candidate cleared the healthy-rate hard gate:

- `prod-fixed` still ends with `1` clearly healthy simulated ban under both candidates
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

- `rate_primary_amplified` is directionally closer to the ADR than the current composite model
  because it rescues several clearly healthy large-torrent peers while preserving clearly-bad ban
  status on these corpora
- `rate_primary_amplified` still fails the healthy-rate hard gate and remains too permissive in
  marginal and high-side-gray cases
- `marginal_band_bounded` is not acceptable in its current form because it weakens clearly-bad
  low-rate safety while still leaving healthy-rate bans behind

## Follow-up Iteration

The next refinement pass tightened the `rate_primary_amplified` taper to the more protective end
of the ADR-0006 range:

- full progress influence at or below `1.0x` target rate
- smooth rolloff between `1.0x` and `1.25x`
- zero progress influence above `1.25x`

That stricter taper did not materially change the aggregate outcomes on either local corpus. The
same hard-gate failures remained:

- `prod-fixed` still had `1` clearly healthy simulated ban under `rate_primary_amplified`
- `logs-2026-03-23` still had `5` clearly healthy simulated bans under `rate_primary_amplified`
- marginal and high-side-gray bans lost relative to current were unchanged on `logs-2026-03-23`

Current interpretation:

- the rate-primary tapered-amplification family is still the most credible ADR-0006 direction to
  keep iterating on
- this specific taper refinement is not enough to unblock production work
- the remaining errors are not solved by taper shape alone; the next iteration needs to adjust how
  near-target and slightly-above-target peers accumulate risk, not only how clearly healthy peers
  are protected

## Consequence For Backlog

`brrpolice-d6br.4` should not start from either candidate in this document. More candidate
iteration is required before a production ADR-0006 model can be selected, but future refinement
should start from the `rate_primary_amplified` family rather than the bounded marginal-band
variant.
