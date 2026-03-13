# ADR 0001: Score-Based Peer Banning North Star and Design

- Status: Implemented
- Date: 2026-03-12
- Decision Owner: brrpolice maintainers

## Context

brrpolice currently has two ban decision modes:

1. `duration` (legacy): thresholding on accumulated "bad" time based on fixed rate/progress checks.
2. `score`: thresholding on a continuously updated risk score with decay and sustain semantics.

Running dual policy modes increases complexity, tuning ambiguity, and user confusion. The project direction is to converge on a single score-based policy that is easier to reason about, observe, and tune.

## North Star

Ban only peers that are persistently harmful to upload efficiency, while minimizing false positives against temporarily constrained or recovering peers.

In practical terms:

1. Prioritize stable upload health over instant reaction.
2. Require sustained poor behavior before banning.
3. Make decisions explainable through structured score components and metrics.
4. Keep configuration surface focused on policy intent, not implementation details.

## Decision

Adopt score-based banning as the only ban mechanism and retire duration-based decisioning from the shipped product.

## Design

### 1) Risk Model

For each observation sample:

1. Compute `rate_risk` from `up_rate_bps` vs `policy.score.target_rate_bps`, normalized to `[0, 1]`.
2. Compute `progress_risk` from observed progress delta vs `policy.score.required_progress_delta`, normalized to `[0, 1]`.
3. Compute weighted sample risk:
   `sample_risk = (weight_rate * rate_risk + weight_progress * progress_risk) / (weight_rate + weight_progress)`.

### 2) Score Evolution

For each peer session:

1. Apply time-based decay between samples:
   `score = max(0, score - decay_per_second * elapsed_seconds)`.
2. Add current sample risk:
   `score = clamp(score + sample_risk, 0, max_score)`.

### 3) Ban Eligibility

1. If `score >= ban_threshold`, accumulate `score_above_threshold_duration`.
2. If `score <= clear_threshold`, reset `score_above_threshold_duration` to zero.
3. Peer is bannable when all are true:
   - `observed_duration >= score.min_observation_duration`
   - `score_above_threshold_duration >= score.sustain_duration`
   - no policy exemption applies (allowlist, tracker rules, near-complete peers, etc.).

### 4) Enforcement and Escalation

1. Ban reasons use `reason_code=score_based` with structured details.
2. Ban TTL uses existing ban ladder by offence count.
3. Reban cooldown and duplicate suppression continue to prevent ban churn.

### 5) State and Durability

Persist and restore:

1. `ban_score`
2. `ban_score_above_threshold_duration`
3. session timing needed to continue score behavior correctly across restarts.

## Configuration Principles

1. Keep score config explicit and unit-safe.
2. Use hysteresis (`ban_threshold > clear_threshold`) to reduce oscillation.
3. Bias defaults toward avoiding premature bans, then tune from replay plus production telemetry.
4. Remove duration-mode knobs after score-only migration to reduce surface area.

## Observability and Explainability

Required signals:

1. score evaluations, bannable evaluations, and ban decisions.
2. score value and sample risk distributions.
3. above-threshold duration distribution.
4. structured logs that include torrent identity context and score rationale.

This enables tuning decisions to be evidence-driven rather than anecdotal.

## Guardrails

1. Exempt new peers via a minimum observation window.
2. Preserve allowlist and tracker-based exemptions.
3. Keep near-complete peer exemption (`ignore_peer_progress_at_or_above`) to avoid low-value bans.
4. Enforce strict config validation at startup.

## Consequences

### Positive

1. Single policy mental model and clearer tuning loop.
2. Better resilience to noisy short-term behavior.
3. Better post-incident explainability via score decomposition.

### Tradeoffs

1. Requires careful default tuning to avoid silent under-banning or over-banning.
2. Adds reliance on persisted score state quality.
3. Requires stronger telemetry discipline to tune safely.

## Acceptance Criteria for Migration Completion

1. `duration` mode removed from runtime decision path and config.
2. Score policy is the only shipped ban mechanism.
3. Replay and production evidence show acceptable false-positive/false-negative profile.
4. Documentation describes only score-based policy behavior.

## Rollout Notes

1. Tune with local replay tooling and production logs before final cutover.
2. Keep tooling developer-only and non-user-facing.
3. Do not ship simulator as product functionality.
