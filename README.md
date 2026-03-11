# brrpolice

`brrpolice` is a singleton Rust service that watches qBittorrent peers on seeding torrents, classifies slow non-progressing peers, and applies temporary bans backed by SQLite state.

This repository currently covers the local binary and container-friendly runtime only. Kubernetes manifests and deployment automation are intentionally out of scope.

## Requirements

- Docker (for local OCI image build/run)
- Rust toolchain with `cargo` (the pinned version is in `rust-toolchain.toml`)
- Reachable qBittorrent WebUI API
- A qBittorrent password provided through an environment variable
- A writable location for the SQLite database when not using `:memory:`

## Build

```bash
cargo build
```

Build an optimized binary with:

```bash
cargo build --release
```

## OCI image (Docker)

Build the image:

```bash
docker build -t brrpolice:latest .
```

Run it:

```bash
docker run --rm -p 9090:9090 \
  -e QBITTORRENT_PASSWORD='your-password' \
  -v "$(pwd)/.data:/data" \
  brrpolice:latest
```

## Configuration

Configuration resolution order is:

1. built-in defaults
2. `config.toml`
3. environment overrides

The default config file path is `./config.toml`. Override it with `BRRPOLICE_CONFIG=/path/to/config.toml`.

The qBittorrent password is not read from the TOML file. `main` resolves it from the env var named by `qbittorrent.password_env`, which defaults to `QBITTORRENT_PASSWORD`.

Example `config.toml`:

```toml
[qbittorrent]
base_url = "http://127.0.0.1:8080"
username = "admin"
password_env = "QBITTORRENT_PASSWORD"
poll_interval = "30s"
request_timeout = "10s"

[policy]
slow_rate_bps = 262144
min_progress_delta = 0.0025
new_peer_grace_period = "5m"
min_observation_duration = "20m"
bad_for_duration = "15m"
decay_window = "60m"
ignore_peer_progress_at_or_above = 0.95
min_total_seeders = 3
reban_cooldown = "30m"

[policy.ban_ladder]
durations = ["1h", "6h", "24h", "168h"]

[filters]
include_categories = []
exclude_categories = []
include_tags = []
exclude_tags = []
allowlist_peer_ips = []
allowlist_peer_cidrs = []

[database]
path = "/tmp/brrpolice.sqlite"
busy_timeout = "5s"

[http]
bind = "127.0.0.1:9090"

[logging]
level = "info"
format = "json"
```

Supported environment overrides:

- `BRRPOLICE_QBITTORRENT__BASE_URL`
- `BRRPOLICE_QBITTORRENT__USERNAME`
- `BRRPOLICE_QBITTORRENT__PASSWORD_ENV`
- `BRRPOLICE_QBITTORRENT__POLL_INTERVAL`
- `BRRPOLICE_QBITTORRENT__REQUEST_TIMEOUT`
- `BRRPOLICE_POLICY__SLOW_RATE_BPS`
- `BRRPOLICE_POLICY__MIN_PROGRESS_DELTA`
- `BRRPOLICE_POLICY__NEW_PEER_GRACE_PERIOD`
- `BRRPOLICE_POLICY__MIN_OBSERVATION_DURATION`
- `BRRPOLICE_POLICY__BAD_FOR_DURATION`
- `BRRPOLICE_POLICY__DECAY_WINDOW`
- `BRRPOLICE_POLICY__IGNORE_PEER_PROGRESS_AT_OR_ABOVE`
- `BRRPOLICE_POLICY__MIN_TOTAL_SEEDERS`
- `BRRPOLICE_POLICY__REBAN_COOLDOWN`
- `BRRPOLICE_POLICY__BAN_LADDER__DURATIONS`
- `BRRPOLICE_FILTERS__INCLUDE_CATEGORIES`
- `BRRPOLICE_FILTERS__EXCLUDE_CATEGORIES`
- `BRRPOLICE_FILTERS__INCLUDE_TAGS`
- `BRRPOLICE_FILTERS__EXCLUDE_TAGS`
- `BRRPOLICE_FILTERS__ALLOWLIST_PEER_IPS`
- `BRRPOLICE_FILTERS__ALLOWLIST_PEER_CIDRS`
- `BRRPOLICE_DATABASE__PATH`
- `BRRPOLICE_DATABASE__BUSY_TIMEOUT`
- `BRRPOLICE_HTTP__BIND`
- `BRRPOLICE_LOGGING__LEVEL`
- `BRRPOLICE_LOGGING__FORMAT`

## Run locally

Set the qBittorrent password env var, then start the service:

```bash
export QBITTORRENT_PASSWORD='your-password'
cargo run
```

To point at a non-default config file:

```bash
export BRRPOLICE_CONFIG=/path/to/config.toml
export QBITTORRENT_PASSWORD='your-password'
cargo run
```

The service runs migrations on startup, authenticates to qBittorrent, restores persisted state, starts the HTTP server, and then enters the polling loop.

## Test

Run the full test suite with:

```bash
cargo test
```

If you want dependencies isolated inside the repo, use:

```bash
CARGO_HOME=.cargo-home cargo test
```

The tests are hermetic and should not depend on ambient qBittorrent credentials or mutate the process environment.

## GitHub Actions

Workflows under `.github/workflows` provide:

- `ci.yml`: runs `cargo test` and `cargo clippy` on pushes and pull requests.
- `docker-publish.yml`: builds and publishes the Docker image to GHCR with Buildx on branch and `v*` tag pushes.

Published image naming:

- branch push: `ghcr.io/<owner>/brrpolice:<branch>`
- tag push: `ghcr.io/<owner>/brrpolice:<tag>` (for example `v1.0.0`)

## HTTP endpoints

The HTTP server exposes:

- `/healthz` for liveness
- `/readyz` for readiness after DB, qBittorrent initialization, recovery, and poll-loop entry
- `/metrics` for Prometheus metrics

Example checks:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/metrics
```

## Logging

Use `logging.format = "json"` for structured logs. The service emits startup, migration, qBittorrent authentication, torrent filter, exemption, bad-peer, ban, expiry, and retry/failure events with machine-parseable fields.
