# ADR-0004 Trace Corpus Check

This note records the local trace replay corpus used to unblock scoring-policy research after ADR-0004.

## Corpus

`testdata/policy-trace/v1-replay-corpus.jsonl` is a sanitized local JSONL corpus for the current policy replay gate. It uses documentation-range peer IPs and fixture torrent metadata, not a production capture. Raw trace captures from `/debug/policy-trace/stream` remain sensitive operational data and must stay in untracked local storage such as `/private/tmp` or another restricted operator workspace.

The existing pretty JSON files in `testdata/policy-trace/` are schema examples. They are intentionally useful for schema compatibility, but they are not the replay corpus gate because they are hand-authored examples rather than current-policy output.

## Command History

Run the replay gate with:

```bash
cargo run -p score-simulator -- --input testdata/policy-trace/v1-replay-corpus.jsonl
```

The May 9, 2026 local run passed with four trace decisions, zero dropped trace records, four current-policy reproduction passes, and zero reproduction failures. The corpus includes exempt, not-bannable, ban, prior-session carryover, offence-history, and non-default policy-input cases.

For a live local or Kubernetes capture, keep the raw file untracked and use the same command shape:

```bash
cargo run -p score-simulator -- --input /private/tmp/policy-trace.jsonl
```

ADR-0006 and later scoring-policy comparisons should replace the sanitized corpus path with a local captured trace only after the current-policy reproduction gate passes.
