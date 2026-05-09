# ADR-0004 Rollout Verification

Verified on May 9, 2026 for `brrpolice-24b7.4.4`.

| Gate | Evidence | Result |
| --- | --- | --- |
| Debug trace endpoint is disabled by default | `DebugPolicyTraceConfig::default()` sets `enabled = false`; covered by `debug_trace::tests::default_trace_config_is_disabled_and_loopback_only`. | Pass |
| Debug listener is loopback-bound by default | `DebugPolicyTraceConfig::default()` sets `host = "127.0.0.1"` and `port = 9091`; covered by the same default test. | Pass |
| Capture uses port-forward plus `curl -N` | README documents `kubectl port-forward pod/brrpolice-abc123 9091:9091` followed by `curl -N 'http://127.0.0.1:9091/debug/policy-trace/stream?duration=5m' > policy-trace.jsonl`. | Pass |
| Debug route is not on the normal service listener | `http::tests::service_router_does_not_expose_debug_trace_stream` verifies `/debug/policy-trace/stream` returns `404` from the service router. | Pass |
| Slow or disconnected trace clients cannot block policy evaluation | `trace_publisher::tests::slow_client_drops_records_without_backpressure`, `trace_publisher::tests::disconnected_client_is_pruned_without_backpressure`, and `debug_trace::tests::stream_reports_dropped_records_for_slow_clients` cover bounded fanout and dropped-record notices. | Pass |
| Runtime caps are enforced | `debug_trace::tests::stream_enforces_client_limit` and `debug_trace::tests::duration_query_is_capped_by_config` cover max-client and duration caps. | Pass |
| Redaction is documented and tested | README documents trace sensitivity and redaction tradeoffs; `control::tests::run_poll_cycle_emits_policy_trace_with_redaction` and `debug_trace::tests::stream_include_names_does_not_override_configured_redaction` cover peer IP and torrent-name redaction behavior. | Pass |
| Current-policy reproduction passes for a local corpus | `cargo run -p score-simulator -- --input testdata/policy-trace/v1-replay-corpus.jsonl` passed with `reproduction_passes=1`, `reproduction_failures=0`, and `dropped_trace_records=0`. | Pass |
| Simulator reports replay problems separately from policy deltas | `score-simulator` output includes `current_policy_reproduction`, `candidate_decision_deltas`, `candidate_score_state_deltas`, and `guardrail_or_exemption_deltas`; covered by `current_policy_replay_deltas_are_reproduction_failures` and `candidate_overrides_report_deltas_without_reproduction_failure`. | Pass |
| Operator logs are rejected as research replay input | `cargo run -p score-simulator -- --input /private/tmp/adr-0004-operator-log.jsonl` rejected a structured operator-log envelope with `expected ADR-0004 policy trace line with top-level record_type`. | Pass |

No remaining ADR-0004 rollout gaps were found during this verification.
