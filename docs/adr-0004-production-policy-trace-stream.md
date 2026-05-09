# ADR-0004: Add On-Demand Production Policy Traces

## Status

Accepted

## Context

Recent policy research has relied on replaying structured decision logs. That has been useful for
triage, but it is not a strong enough data source to select production scoring changes.

The current log replay path has several structural limits:

- logs are operator output first and model input second
- absolute peer progress, prior session state, guardrail inputs, and offence history are incomplete
  or reconstructed
- replay can misclassify which rate band caused score accumulation when the final peer band differs
  from the band where risk was accumulated
- adding more operator log fields increases log volume and makes ordinary logs carry research-only
  data

`brrpolice` is usually run in Kubernetes, so local files on the pod are awkward to retrieve and
long-running always-on debug logging is expensive. The research workflow needs a way to capture
high-fidelity policy observations only when an operator asks for them.

## Decision

Add a dedicated production policy trace facility.

The trace facility will expose an on-demand HTTP streaming endpoint that emits newline-delimited
JSON policy trace records while a client is connected. It is intended for short, explicit capture
windows through Kubernetes port-forwarding or a tightly scoped internal debug service.

Initial endpoint shape:

```text
GET /debug/policy-trace/stream
Content-Type: application/x-ndjson
```

Example Kubernetes workflow:

```bash
kubectl port-forward pod/brrpolice-... 9091:9091
curl -N http://127.0.0.1:9091/debug/policy-trace/stream > policy-trace.jsonl
```

The trace stream is not ordinary application logging. It is a replay-oriented event stream with a
versioned schema and enough state to reproduce the policy engine's current decision for each peer
observation.

## Goals

- collect high-fidelity production observations without permanently increasing log volume
- make policy research independent of operator log formatting
- let the simulator replay current production behavior exactly before comparing candidate policies
- support Kubernetes-friendly ad hoc capture through `kubectl port-forward`
- keep sensitive trace data away from default logs and public ingress paths

## Non-Goals

- replacing normal logs, metrics, health checks, or readiness checks
- exposing trace capture through a public ingress
- building a general telemetry or OpenTelemetry exporter in the first iteration
- storing traces inside `brrpolice` by default
- selecting a scoring-policy formula

## Configuration Shape

The trace endpoint must be disabled by default.

Preferred configuration:

```toml
[debug.policy_trace]
enabled = false
host = "127.0.0.1"
port = 9091
max_clients = 1
max_duration = "10m"
default_sample_rate = 1.0
redact_peer_ip = false
redact_torrent_name = true
```

The debug listener should be separate from the existing service HTTP listener. That keeps
`/healthz`, `/readyz`, `/metrics`, and admin routes independent from high-sensitivity trace capture
and makes Kubernetes network policy easier to reason about.

## Trace Record Shape

The stream should emit one JSON object per line. Every record must include `schema_version` and
enough identity fields to group observations by peer behaviour.

Required top-level fields:

- `record_type`
- `schema_version`
- `observed_at`
- `service_version`
- `policy_trace_id`
- `config_fingerprint`

For peer observation records, include:

- torrent identity: hash, optional name, optional tracker, total size bytes, category, tags, total
  seeder count, in-scope result
- peer identity: IP, port, current progress, instantaneous upload rate
- prior session state before evaluation
- evaluated session state after evaluation
- policy inputs: target rate, rate references, progress requirement, byte-domain movement, score
  thresholds, churn settings
- guardrail inputs: exemption reason, allowlist result, active ban status, reban cooldown state,
  offence history summary
- decision output: disposition, reason code, reason details, selected TTL when present
- simulator hints: peer observation identity, peer behaviour identity, sample duration, current rate
  band, band at ban when applicable

The first implementation may emit a compact schema, but it must preserve replay-critical state.
Fields may be added in later schema versions, but existing field meanings must not change silently.

## Replay Contract

The simulator must gain a trace-input mode that consumes policy trace JSONL.

The core correctness gate is:

- replaying a trace through the same policy version and config must reproduce the recorded
  evaluation state and decision outcome

Only after that fidelity check passes should the simulator compare candidate models against the same
trace observations.

Trace replay reports should separate:

- current-policy reproduction failures
- candidate-vs-current decision deltas
- candidate-vs-current score-state deltas
- guardrail or exemption differences

This keeps data quality failures from being mistaken for policy behavior.

## Runtime Behavior

The endpoint should stream live observations from the control loop to connected clients using a
bounded channel.

Required behavior:

- no connected client means no trace serialization work beyond cheap enabled-state checks
- if the client is slow, the stream may drop records and must report dropped counts in the stream
- stream duration is capped by configuration and may also be capped by a query parameter
- concurrent client count is capped
- trace capture failures must not block peer evaluation or ban enforcement
- startup should log whether the debug trace endpoint is enabled and where it is bound

Useful query parameters:

```text
duration=5m
peer_ip=203.0.113.10
torrent_hash=...
sample=0.25
include_names=false
```

Query parameters may further restrict capture, but they must not override configured safety caps.

## Security and Privacy

Policy traces are sensitive. They can contain peer IP addresses, torrent names, trackers, categories,
tags, and operational policy state.

Required controls:

- disabled by default
- bind to loopback by default
- no default Kubernetes ingress exposure
- redaction controls for torrent names and peer IPs
- bounded stream duration and client count
- clear documentation that traces should be handled as sensitive operational data

Kubernetes deployment guidance should prefer `kubectl port-forward` to a pod or debug-only service.
If a service is used, it should be internal-only and protected by network policy.

## Alternatives Considered

### Continue enriching ordinary logs

Rejected as the primary research path. It is simple and works with existing log collection, but it
mixes high-cardinality research payloads into operator logs and still leaves replay coupled to log
formatting choices.

### Write trace files inside the container

Rejected for the first iteration. Files are useful for long captures, but they add lifecycle,
storage, cleanup, and exfiltration concerns in Kubernetes.

### Export through OpenTelemetry

Deferred. It may become useful later, but the immediate research need is deterministic replay data,
not a general telemetry pipeline.

### Always-on sidecar collector

Deferred. A sidecar can help for long-running studies, but it is more operational machinery than an
on-demand stream and does not remove the need for a versioned trace schema.

## Consequences

### Positive

- policy research can use exact production observations instead of inferred log state
- candidate comparisons can be gated on current-policy replay fidelity
- traces can be captured from Kubernetes without persistent pod storage
- operator logs stay focused on operations instead of becoming research datasets

### Negative

- this adds a second HTTP listener and additional configuration
- trace records can expose sensitive operational data if enabled carelessly
- simulator and trace schema versioning become part of the policy research workflow
- the control loop needs a non-blocking trace publication path

## Rollout Plan

1. Add configuration and a disabled-by-default debug listener.
2. Define the initial trace schema in code and documentation.
3. Emit policy trace records from the control loop after each peer evaluation.
4. Add simulator support for trace JSONL input.
5. Add a reproduction check that compares recorded current-policy decisions with replayed decisions.
6. Use trace replay as the gate for future scoring-policy research.

## Acceptance Gates

No policy research decision should depend on production traces until all of these are true:

- the debug endpoint is disabled by default and binds to loopback by default
- trace capture can be started with `kubectl port-forward` and `curl -N`
- slow or disconnected clients cannot block policy evaluation
- trace replay reproduces current-policy decisions for a captured trace corpus
- the simulator reports reproduction failures separately from candidate deltas
- documentation clearly marks trace files as sensitive data

## Relationship to Scoring-Policy Research

This ADR changes the evidence pipeline for future scoring-policy changes. Candidate selection should
be driven by dedicated policy traces rather than ordinary operator-log replay alone.
