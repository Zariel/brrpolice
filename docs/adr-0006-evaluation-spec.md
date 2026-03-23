# ADR-0006 Evaluation Spec

## Status

Accepted

## Purpose

This document defines the replay corpus shape, evaluation bands, and candidate pass/fail gates for
the ADR-0006 policy direction in [`adr-0006-rate-primary-progress-inefficiency.md`](./adr-0006-rate-primary-progress-inefficiency.md).

It is an engineering evaluation spec, not a product-policy ADR. The goal is to make candidate
models comparable before any production formula change lands.

## Scope

This spec governs replay-driven evaluation for:

- the current shipped score model
- at least one rate-primary amplification candidate
- at least one piecewise or bounded marginal-band candidate

This spec does not choose the final production formula. It defines how candidates are judged.

## Current Replay Inputs

Today the replay harness can consume decision logs from `score-simulator` and recover these peer
fields:

- `torrent_hash`
- `torrent_name`
- `torrent_tracker`
- `peer_ip`
- `peer_port`
- `observed_at`
- `progress_delta`
- `average_upload_rate_bps`
- `bad_time_seconds`
- `ban_score`
- `ban_score_above_threshold_seconds`
- `sample_score_risk`
- `effective_sample_score_risk`
- `churn_reconnect_count`
- `churn_amplifier`
- `sample_count`
- decision message/state such as `peer policy update` and `peer ban applied`

Current limitations:

- replay currently hydrates from `average_upload_rate_bps`, not an explicitly logged instantaneous
  sample upload rate
- torrent size is not yet present in replay input lines
- replay output does not yet emit regime classification or byte-domain progress movement

Those gaps are intentionally left to `brrpolice-d6br.2`. This spec still defines the acceptance
gates that later tooling must satisfy.

## Unit of Analysis

Two analysis identities matter:

- peer observation identity: `torrent_hash + peer_ip + peer_port`
- peer behaviour identity: `torrent_hash + peer_ip`

Pass/fail reporting must use the peer behaviour identity as the primary unit because reconnects can
change port while representing the same behavioural case.

Peer observation identity should still be preserved in detailed output for debugging and log joins.

## Evaluation Rate Reference

Until richer logging exists, the evaluation rate reference is:

- `average_upload_rate_bps / policy.score.target_rate_bps`

This is an evaluation-only choice for replay comparability. It does not pre-decide which rate
reference the final production regime classifier must use.

When `brrpolice-d6br.2` lands, reports must show both:

- the evaluation rate reference defined here for backwards comparison
- the candidate's own regime-classification rate reference if it differs

## Evaluation Bands

To avoid turning the replay gate into a premature formula choice, the evaluation corpus uses coarse
bands with explicit gray zones.

### Clearly bad

- ratio `< 0.50`

### Low-side gray zone

- ratio `>= 0.50` and `< 0.75`

### Marginal

- ratio `>= 0.75` and `<= 1.25`

### High-side gray zone

- ratio `> 1.25` and `< 2.0`

### Clearly healthy

- ratio `>= 2.0`

Only the clearly bad, marginal, and clearly healthy bands are acceptance-gating. Gray-zone peers
must still be reported, but they are informative rather than decisive when comparing candidates.

## Required Corpus Buckets

The replay corpus must be partitioned into labelled buckets. A candidate comparison is incomplete
if any required bucket is missing.

### Healthy-rate large-torrent false-positive set

Required contents:

- peers on large torrents that were historically concerning because percentage progress looked slow
  despite healthy upload value
- all examples must fall in the clearly healthy band by the evaluation rate reference

Expected outcome:

- these peers must not be banned by progress-only pressure

### Poor low-rate safety set

Required contents:

- peers that are operationally clear low-value cases
- examples must fall in the clearly bad band
- cases should include at least some reconnect churn where available so a candidate is not judged
  only on clean single-session traces

Expected outcome:

- these peers must remain bannable without requiring strong progress evidence

### Marginal inefficiency review set

Required contents:

- peers in the marginal band whose acceptability is ambiguous on rate alone
- include both likely-acceptable and likely-inefficient examples when known

Expected outcome:

- the comparison report must make these peers more explainable than the current policy
- if ground-truth labels exist, the report must show keep/ban correctness against those labels
- if labels do not yet exist, the set remains review-driven and cannot by itself justify choosing a
  production candidate

### Guardrail sanity set

Required contents:

- near-complete peers
- allowlisted peers
- peers below minimum-seeder threshold

Expected outcome:

- policy exemptions and guardrails behave consistently across candidates

These cases are not the primary ADR-0006 target, but they protect against accidental regressions
while experimenting.

## Candidate Pass/Fail Gates

A candidate passes replay evaluation only if all hard gates below are satisfied.

### Hard gate 1: healthy-rate false positives

- zero labelled healthy-rate false-positive cases may end in a simulated ban

### Hard gate 2: poor low-rate safety

- zero labelled poor low-rate safety cases may lose bannable status relative to the current policy
- if the current policy already bans the case, the candidate must still ban it

### Hard gate 3: comparability

- the candidate must be evaluated on the same corpus and same replay window as the current policy
- the report must include peer-level deltas, not only summary counts

### Hard gate 4: explainability

- the report must show enough per-peer evidence to explain whether rate or inefficiency drove the
  outcome
- if the candidate uses a different rate reference than the evaluation reference, both must be
  visible

### Soft gate: marginal improvement

Marginal-band performance is the main selection criterion once the hard gates pass.

At minimum the report must show:

- which marginal peers changed outcome relative to the current policy
- whether the change was caused primarily by rate handling or inefficiency handling
- which marginal peers still require human review because labels are weak or absent

A candidate should not be selected for production if it only passes the hard gates by becoming less
sensitive everywhere. It must also provide a clearer and more defensible treatment of the marginal
set.

## Required Comparison Output

Every candidate run must produce:

- corpus identifier or input file set
- policy parameters used for the run
- total peer behaviour identities seen
- total simulated bans
- labelled-case outcome summary by evaluation band
- peer-level delta rows for every labelled case

Each peer-level delta row must include at least:

- `torrent_hash`
- `torrent_name` when available
- `torrent_tracker` when available
- `peer_ip`
- peer behaviour identity (`torrent_hash + peer_ip`)
- first and last observation timestamps in the replay window
- evaluation rate reference
- evaluation band
- baseline outcome under current policy
- candidate outcome
- candidate-minus-baseline delta summary
- `progress_delta`
- `average_upload_rate_bps`
- `ban_score`
- `sample_score_risk`
- `effective_sample_score_risk`
- churn fields when present

Once `brrpolice-d6br.2` is complete, the comparison output must additionally include:

- torrent size
- byte-domain useful movement derived from progress and torrent size
- candidate regime classification
- candidate-specific inefficiency inputs

## Execution Procedure

Minimum evaluation procedure:

1. Run the current policy against the labelled corpus and save the peer-level output.
2. Run each ADR-0006 candidate against the same corpus.
3. Group results by peer behaviour identity.
4. Assign each labelled case to an evaluation band using the evaluation rate reference.
5. Check hard gates before any deeper comparison.
6. Review marginal-band deltas only after the hard gates pass.

## Current Tooling Contract

Until richer reporting lands, the evaluation owner must treat this spec as the contract for
`brrpolice-d6br.2` and `brrpolice-d6br.3`.

Specifically:

- `brrpolice-d6br.2` must make it possible to emit the required comparison output
- `brrpolice-d6br.3` must use this spec when comparing candidate models
- `brrpolice-d6br.4` must not be closed until a chosen candidate passes the hard gates defined
  here
