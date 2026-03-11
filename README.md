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
- Ban duration increases by offence count using a configurable ban ladder.
- Expired bans are reconciled so qBittorrent and the database stay consistent.

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

| Setting | Default | Impact |
|---|---|---|
| `qbittorrent.base_url` | `http://qbittorrent:8080` | Base URL for qBittorrent WebUI API calls. Must be `http` or `https` and must not include credentials in the URL. |
| `qbittorrent.username` | `""` | Enables authenticated API mode when set together with `password_env`. |
| `qbittorrent.password_env` | `""` | Name of the environment variable that contains the qBittorrent password. Used only when auth is enabled. |
| `qbittorrent.poll_interval` | `30s` | Control loop polling frequency. Lower values react faster but increase API/database load. |
| `qbittorrent.request_timeout` | `10s` | Timeout per qBittorrent API request. Must be `<= poll_interval`. |

### Policy Settings

| Setting | Default | Impact |
|---|---|---|
| `policy.slow_rate_bps` | `262144` | Upload-rate threshold (bytes/sec). Peers below this may be treated as slow. |
| `policy.min_progress_delta` | `0.0025` | Minimum progress increase per sample to be considered progressing. |
| `policy.new_peer_grace_period` | `5m` | New peers are exempt during this initial age window. |
| `policy.min_observation_duration` | `20m` | Minimum tracked duration before a peer can become bannable. |
| `policy.bad_for_duration` | `15m` | Required accumulated "bad" time before ban eligibility. |
| `policy.decay_window` | `60m` | Window used to decay bad history and carry over peer state between sightings. |
| `policy.ignore_peer_progress_at_or_above` | `0.95` | Exempts peers at or above this completion ratio. |
| `policy.min_total_seeders` | `3` | Skips torrents below this seeder count. |
| `policy.reban_cooldown` | `30m` | Cooldown before re-banning a recently handled peer identity. |
| `policy.ban_ladder.durations` | `["1h","6h","24h","168h"]` | Ban durations by offence number. If offences exceed the list, the final duration is reused. |

### Filter Settings

| Setting | Default | Impact |
|---|---|---|
| `filters.include_categories` | `[]` | Optional allow-list of torrent categories. If includes are configured, torrent category or tag must match. |
| `filters.exclude_categories` | `[]` | Deny-list of torrent categories. Excludes are applied before includes. |
| `filters.include_tags` | `[]` | Optional allow-list of torrent tags. Works with `include_categories`. |
| `filters.exclude_tags` | `[]` | Deny-list of torrent tags. Excludes are applied before includes. |
| `filters.allowlist_peer_ips` | `[]` | Peer IPs that are never banned. |
| `filters.allowlist_peer_cidrs` | `[]` | Peer CIDR ranges that are never banned. |

### Storage, HTTP, and Logging Settings

| Setting | Default | Impact |
|---|---|---|
| `database.path` | `/data/brrpolice.sqlite` | SQLite database location for sessions, bans, and offence history. |
| `database.busy_timeout` | `5s` | SQLite busy timeout for lock contention. |
| `http.bind` | `0.0.0.0:9090` | HTTP bind address for `/healthz`, `/readyz`, and `/metrics`. |
| `logging.level` | `info` | Log level filter (for example `trace`, `debug`, `info`, `warn`, `error`). |
| `logging.format` | `json` | Output format: `json`, `plain`, or `text`. |

## Environment Overrides

Any setting can be overridden with env vars using:

`BRRPOLICE_<SECTION>__<KEY>`

Examples:

```bash
BRRPOLICE_QBITTORRENT__BASE_URL=http://qbittorrent.svc:8080
BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS=5
BRRPOLICE_POLICY__BAN_LADDER__DURATIONS=1h,12h,48h
BRRPOLICE_FILTERS__EXCLUDE_TAGS=private,whitelist
BRRPOLICE_HTTP__BIND=0.0.0.0:9090
```

For list values, use comma-separated entries.

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
