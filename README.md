# brrpolice

`brrpolice` is a Rust service for qBittorrent seeding nodes. It watches peers, identifies peers that stay slow and do not make progress, applies temporary bans, and stores state in SQLite so decisions survive restarts.

## What It Does

`brrpolice` continuously:

1. Polls qBittorrent for seeding torrents and connected peers.
2. Tracks per-peer behavior over time (upload rate, progress change, observation window).
3. Applies policy rules to decide whether a peer should be banned.
4. Enforces bans in qBittorrent and reconciles ban expiry.

## How It Works

- Startup runs DB migrations, starts HTTP endpoints, then initializes qBittorrent access and recovery in the control loop.
- Peer state, offence history, and active bans are stored in SQLite.
- Retention pruning periodically deletes stale rows so SQLite size converges instead of growing without bound.
- Ban duration increases by offence count using a configurable ban ladder.
- Expired bans are reconciled so qBittorrent and the database stay consistent.
- Policy logic overview: [`docs/policy-engine.md`](docs/policy-engine.md).

## Requirements

- qBittorrent WebUI API reachable from this service
- Docker (for container runs) or Rust toolchain (for local source runs)
- Writable storage for SQLite (`/data` in the container image by default)
- qBittorrent credentials only when WebUI auth is enabled

## Quick Start (Docker)

Create a `config.toml`:

```toml
[qbittorrent]
base_url = "http://qbittorrent:8080"
username = ""
password_env = ""

[database]
path = "/data/brrpolice.sqlite"
```

Build and run:

```bash
docker build -t brrpolice:latest .
docker run --rm -p 9090:9090 \
  -v "$(pwd)/config.toml:/app/config.toml:ro" \
  -v "$(pwd)/data:/data" \
  brrpolice:latest
```

If qBittorrent auth is enabled, set both `qbittorrent.username` and `qbittorrent.password_env`, then pass the password env var:

```bash
docker run --rm -p 9090:9090 \
  -e QBITTORRENT_PASSWORD='your-password' \
  -v "$(pwd)/config.toml:/app/config.toml:ro" \
  -v "$(pwd)/data:/data" \
  brrpolice:latest
```

## Run From Source

```bash
cargo run
```

Use a non-default config path:

```bash
BRRPOLICE_CONFIG=/path/to/config.toml cargo run
```

Or with CLI flags:

```bash
cargo run -- --config /path/to/config.toml --http-host 0.0.0.0 --http-port 9090
```

## Configuration

Configuration load order:

1. Built-in defaults
2. `config.toml` in the working directory
3. Environment variable overrides (`BRRPOLICE_...`)

If `BRRPOLICE_CONFIG` is set, the file is required. Any missing file, parse error, or validation error causes startup to fail.

Duration values use human-readable strings such as `30s`, `5m`, `1h`.

qBittorrent auth rule:

- `qbittorrent.username` and `qbittorrent.password_env` must both be set, or both be unset.

### qBittorrent Settings

| Setting | Env Var | Default | Impact |
|---|---|---|---|
| `qbittorrent.base_url` | `BRRPOLICE_QBITTORRENT__BASE_URL` | `http://qbittorrent:8080` | Base URL for qBittorrent WebUI API calls. Must be `http` or `https` and must not include credentials in the URL. |
| `qbittorrent.username` | `BRRPOLICE_QBITTORRENT__USERNAME` | `""` | Enables authenticated API mode when set together with `password_env`. |
| `qbittorrent.password_env` | `BRRPOLICE_QBITTORRENT__PASSWORD_ENV` | `""` | Name of the environment variable that contains the qBittorrent password. Used only when auth is enabled. |
| `qbittorrent.poll_interval` | `BRRPOLICE_QBITTORRENT__POLL_INTERVAL` | `10s` | Control loop polling frequency. Lower values react faster but increase API/database load. |
| `qbittorrent.request_timeout` | `BRRPOLICE_QBITTORRENT__REQUEST_TIMEOUT` | `10s` | Timeout per qBittorrent API request. Must be `<= poll_interval`. |
| `qbittorrent.pool_idle_timeout` | `BRRPOLICE_QBITTORRENT__POOL_IDLE_TIMEOUT` | `5s` | Maximum idle lifetime for pooled qBittorrent HTTP connections before closing and reopening. |
| `qbittorrent.transient_retries` | `BRRPOLICE_QBITTORRENT__TRANSIENT_RETRIES` | `10` | Retries for transient qBittorrent request failures (connection resets, timeouts, and retryable HTTP status). |

### Policy Settings

| Setting | Env Var | Default | Impact |
|---|---|---|---|
| `policy.new_peer_grace_period` | `BRRPOLICE_POLICY__NEW_PEER_GRACE_PERIOD` | `60s` | New peers are exempt during this initial age window. |
| `policy.decay_window` | `BRRPOLICE_POLICY__DECAY_WINDOW` | `60m` | Window used to decay bad history and carry over peer state between sightings. |
| `policy.ignore_peer_progress_at_or_above` | `BRRPOLICE_POLICY__IGNORE_PEER_PROGRESS_AT_OR_ABOVE` | `0.95` | Exempts peers at or above this completion ratio. |
| `policy.min_total_seeders` | `BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS` | `3` | Skips torrents below this seeder count. |
| `policy.reban_cooldown` | `BRRPOLICE_POLICY__REBAN_COOLDOWN` | `30m` | Cooldown before re-banning a recently handled peer identity. |
| `policy.score.target_rate_bps` | `BRRPOLICE_POLICY__SCORE__TARGET_RATE_BPS` | `65536` | Score model upload target in bytes/sec. Lower observed rates increase score risk. |
| `policy.score.required_progress_delta` | `BRRPOLICE_POLICY__SCORE__REQUIRED_PROGRESS_DELTA` | `0.02` | Score model progress target as a fraction (`0.02` = `2%`). Lower progress increases score risk. |
| `policy.score.weight_rate` | `BRRPOLICE_POLICY__SCORE__WEIGHT_RATE` | `0.35` | Weight for upload-rate risk in score calculations. |
| `policy.score.weight_progress` | `BRRPOLICE_POLICY__SCORE__WEIGHT_PROGRESS` | `0.65` | Weight for progress risk in score calculations. |
| `policy.score.rate_risk_floor` | `BRRPOLICE_POLICY__SCORE__RATE_RISK_FLOOR` | `0.4` | Non-compensatory floor for upload-rate risk (`sample_risk >= rate_risk_floor * rate_risk`). |
| `policy.score.ban_threshold` | `BRRPOLICE_POLICY__SCORE__BAN_THRESHOLD` | `1.6` | Score threshold that starts/continues ban-eligible accumulation. |
| `policy.score.clear_threshold` | `BRRPOLICE_POLICY__SCORE__CLEAR_THRESHOLD` | `0.8` | Score threshold that resets accumulated above-threshold time. |
| `policy.score.sustain_duration` | `BRRPOLICE_POLICY__SCORE__SUSTAIN_DURATION` | `120s` | Time score must stay at or above `ban_threshold` before a ban is allowed. |
| `policy.score.decay_per_second` | `BRRPOLICE_POLICY__SCORE__DECAY_PER_SECOND` | `0.02` | Passive score decay rate per second between observations. |
| `policy.score.min_observation_duration` | `BRRPOLICE_POLICY__SCORE__MIN_OBSERVATION_DURATION` | `2m` | Minimum tracked peer age before score-based bans can trigger. |
| `policy.score.max_score` | `BRRPOLICE_POLICY__SCORE__MAX_SCORE` | `5.0` | Upper clamp for per-peer score state. |
| `policy.score.churn.enabled` | `BRRPOLICE_POLICY__SCORE__CHURN__ENABLED` | `true` | Enables reconnect churn as an additive score signal for repeatedly reconnecting low-rate, low-progress peers. |
| `policy.score.churn.reconnect_window` | `BRRPOLICE_POLICY__SCORE__CHURN__RECONNECT_WINDOW` | `30m` | Time window used to count reconnects for churn scoring. |
| `policy.score.churn.min_reconnects` | `BRRPOLICE_POLICY__SCORE__CHURN__MIN_RECONNECTS` | `2` | Minimum reconnect count in the churn window before churn penalty starts applying. |
| `policy.score.churn.max_penalty` | `BRRPOLICE_POLICY__SCORE__CHURN__MAX_PENALTY` | `1.0` | Maximum additional score contribution from churn for a single peer session. |
| `policy.score.churn.decay_per_second` | `BRRPOLICE_POLICY__SCORE__CHURN__DECAY_PER_SECOND` | `0.002` | Decay rate for accumulated churn penalty between observations. |
| `policy.ban_ladder.durations` | `BRRPOLICE_POLICY__BAN_LADDER__DURATIONS` | `["1h","6h","24h","168h"]` | Ban durations by offence number. If offences exceed the list, the final duration is reused. |

### Filter Settings

| Setting | Env Var | Default | Impact |
|---|---|---|---|
| `filters.include_categories` | `BRRPOLICE_FILTERS__INCLUDE_CATEGORIES` | `[]` | Optional allow-list of torrent categories. If includes are configured, torrent category or tag must match. |
| `filters.exclude_categories` | `BRRPOLICE_FILTERS__EXCLUDE_CATEGORIES` | `[]` | Deny-list of torrent categories. Excludes are applied before includes. |
| `filters.include_tags` | `BRRPOLICE_FILTERS__INCLUDE_TAGS` | `[]` | Optional allow-list of torrent tags. Works with `include_categories`. |
| `filters.exclude_tags` | `BRRPOLICE_FILTERS__EXCLUDE_TAGS` | `[]` | Deny-list of torrent tags. Excludes are applied before includes. |
| `filters.allowlist_peer_ips` | `BRRPOLICE_FILTERS__ALLOWLIST_PEER_IPS` | `[]` | Peer IPs that are never banned. |
| `filters.allowlist_peer_cidrs` | `BRRPOLICE_FILTERS__ALLOWLIST_PEER_CIDRS` | `[]` | Peer CIDR ranges that are never banned. |

### Retention Settings

| Setting | Env Var | Default | Impact |
|---|---|---|---|
| `retention.enabled` | `BRRPOLICE_RETENTION__ENABLED` | `true` | Enables periodic SQLite retention pruning. |
| `retention.prune_interval` | `BRRPOLICE_RETENTION__PRUNE_INTERVAL` | `1h` | Minimum time between prune runs. |
| `retention.peer_session_max_age` | `BRRPOLICE_RETENTION__PEER_SESSION_MAX_AGE` | `7d` | Maximum age of peer session rows before they become prune-eligible. |
| `retention.peer_offence_max_age` | `BRRPOLICE_RETENTION__PEER_OFFENCE_MAX_AGE` | `90d` | Maximum age of offence history rows before they become prune-eligible. |
| `retention.reconciled_ban_max_age` | `BRRPOLICE_RETENTION__RECONCILED_BAN_MAX_AGE` | `30d` | Maximum age of reconciled active ban rows before cleanup. |
| `retention.pending_intent_max_age` | `BRRPOLICE_RETENTION__PENDING_INTENT_MAX_AGE` | `24h` | Maximum age for failed pending ban intents once expired. Replayable intents are retained. |
| `retention.max_rows_per_run` | `BRRPOLICE_RETENTION__MAX_ROWS_PER_RUN` | `5000` | Per-table delete cap per prune run to bound write pressure. |
| `retention.vacuum.mode` | `BRRPOLICE_RETENTION__VACUUM__MODE` | `incremental` | SQLite reclaim mode after prune runs (`incremental` or `off`). |
| `retention.vacuum.incremental_pages` | `BRRPOLICE_RETENTION__VACUUM__INCREMENTAL_PAGES` | `200` | Number of SQLite pages requested per incremental vacuum run. |

### Storage, HTTP, and Logging Settings

| Setting | Env Var | Default | Impact |
|---|---|---|---|
| `database.path` | `BRRPOLICE_DATABASE__PATH` | `/data/brrpolice.sqlite` | SQLite database location for sessions, bans, and offence history. |
| `database.busy_timeout` | `BRRPOLICE_DATABASE__BUSY_TIMEOUT` | `5s` | SQLite busy timeout for lock contention. |
| `http.host` | `BRRPOLICE_HTTP__HOST` | `0.0.0.0` | HTTP bind host for `/healthz`, `/readyz`, and `/metrics`. |
| `http.port` | `BRRPOLICE_HTTP__PORT` | `9090` | HTTP bind port for `/healthz`, `/readyz`, and `/metrics`. |
| `logging.level` | `BRRPOLICE_LOGGING__LEVEL` | `warn` | Log level filter (for example `trace`, `debug`, `info`, `warn`, `error`). At `info`, peer policy decisions are emitted; at `warn`, non-fatal errors and peer bans are emitted. |
| `logging.format` | `BRRPOLICE_LOGGING__FORMAT` | `json` | Output format: `json`, `plain`, or `text`. |

## Environment Overrides

Any setting can be overridden with env vars using:

`BRRPOLICE_<SECTION>__<KEY>`

Examples:

```bash
BRRPOLICE_QBITTORRENT__BASE_URL=http://qbittorrent.svc:8080
BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS=5
BRRPOLICE_POLICY__BAN_LADDER__DURATIONS=1h,12h,48h
BRRPOLICE_FILTERS__EXCLUDE_TAGS=private,restricted
BRRPOLICE_HTTP__HOST=0.0.0.0
BRRPOLICE_HTTP__PORT=9090
```

For list values, use comma-separated entries.

## Retention Tuning

- Start with defaults and observe `brrpolice_sqlite_size_bytes` over multiple prune intervals.
- Reduce `retention.prune_interval` or increase `retention.max_rows_per_run` when stale rows accumulate faster than cleanup.
- Lower `retention.peer_session_max_age` first if database growth is dominated by session churn.
- Keep `retention.peer_offence_max_age` long enough to preserve meaningful offence history for ban ladder continuity.
- Use incremental vacuum for bounded background reclaim; switch to `off` only if disk reclaim is managed externally.

## HTTP Endpoints

- `/healthz`: process liveness
- `/readyz`: readiness with gate diagnostics in JSON
- `/metrics`: Prometheus metrics

Example:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/metrics
```

## License

This project is licensed under the terms in [`LICENSE`](LICENSE).
