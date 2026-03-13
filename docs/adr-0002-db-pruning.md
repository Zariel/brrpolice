# ADR 0002: SQLite Data Retention and Pruning

- Status: Implemented
- Date: 2026-03-12
- Decision Owner: brrpolice maintainers

## Context

`brrpolice` persists runtime and enforcement history in SQLite:

- `peer_sessions`
- `peer_offences`
- `active_bans`
- `pending_ban_intents`

Today, runtime cleanup handles only ban lifecycle reconciliation and pending intent replay/removal. There is no general retention policy for historical session/offence data, so database size trends upward over time.

This is acceptable for short-lived deployments but creates long-term risk in Kubernetes singleton operation with persistent volumes:

1. Unbounded storage growth.
2. Slower startup snapshot loads.
3. Higher VACUUM pressure and maintenance overhead.

## Decision

Add explicit, configurable pruning with conservative defaults and strict safety rails.

Pruning is internal maintenance, not policy behavior. It must never affect currently active enforcement correctness.

## Design

### 1) Retention configuration

Add a `retention` config section:

- `retention.enabled` (default: `true`)
- `retention.prune_interval` (default: `1h`)
- `retention.peer_session_max_age` (default: `7d`)
- `retention.peer_offence_max_age` (default: `90d`)
- `retention.reconciled_ban_max_age` (default: `30d`)
- `retention.pending_intent_max_age` (default: `24h`)
- `retention.max_rows_per_run` (default: `5000`)
- `retention.vacuum.mode` (default: `incremental`)  
  values: `off | incremental | full`

### 2) Pruning rules

Use `observed_at`/`updated` style timestamps already persisted in each table.

1. `peer_sessions`
   - Delete rows where `last_seen_at < now - peer_session_max_age`.
   - Never delete rows currently active in this poll cycle.

2. `peer_offences`
   - Delete rows where `banned_at < now - peer_offence_max_age`.
   - Keep at least the most recent offence row per offence identity (`torrent_hash + peer_ip`) to preserve escalation continuity.

3. `active_bans`
   - Delete only rows with `reconciled_at IS NOT NULL` and `reconciled_at < now - reconciled_ban_max_age`.
   - Never delete unreconciled rows.

4. `pending_ban_intents`
   - Delete stale rows where `ban_expires_at < now - pending_intent_max_age`.
   - Keep existing startup replay/drop logic; this rule is additional hygiene.

### 3) Execution model

Run pruning in the control loop after metrics update on a fixed interval (`prune_interval`), wrapped in its own transaction.

- Use bounded deletes (`LIMIT max_rows_per_run`) to avoid long write locks.
- Repeat on next interval until backlog clears.
- Incremental approach avoids latency spikes.

### 4) SQLite maintenance

After prune batches:

- `incremental` mode: run `PRAGMA incremental_vacuum(N)` with small page budget.
- `full` mode: run `VACUUM` only when explicitly configured due to rewrite cost.
- `off` mode: skip compaction.

## Safety Constraints

1. No pruning of unreconciled `active_bans`.
2. No pruning of pending intents that may still be replayable.
3. Preserve escalation continuity by retaining at least one offence row per offence identity.
4. Fail-open behavior: prune failures log warnings and increment metrics, but do not break control-loop enforcement.

## Observability

Add metrics:

- `brrpolice_prune_runs_total{result}`
- `brrpolice_pruned_rows_total{table}`
- `brrpolice_prune_duration_seconds`
- `brrpolice_sqlite_pages_freed_total`

Add structured logs per prune run:

- run_id
- table counts deleted
- elapsed_ms
- vacuum action
- errors

## Migration and Compatibility

No schema migration required for initial implementation if existing timestamp columns are reused.

Because project policy allows pre-v1 breaking changes, config additions can be introduced without compatibility shims.

## Rollout Plan

1. Ship with pruning enabled and conservative defaults.
2. Monitor prune metrics and DB growth for at least one release.
3. Tune retention windows from real data (startup time, DB size, offence history usefulness).
4. Document operator guidance for high-churn swarms.

## Consequences

### Positive

1. Bounded long-term DB growth.
2. Better predictable startup/recovery performance.
3. Lower storage churn and operational surprises.

### Tradeoffs

1. Additional maintenance logic and metrics surface.
2. Need careful retention tuning to avoid losing useful offence history too aggressively.
3. VACUUM strategy must be tuned for PVC I/O characteristics.

## Acceptance Criteria

1. DB size growth flattens under stable workload.
2. Startup snapshot load remains bounded over long-running deployments.
3. No regression in ban replay/reconciliation correctness.
4. Prune metrics/logs provide enough detail to debug retention behavior.
