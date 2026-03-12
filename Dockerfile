# syntax=docker/dockerfile:1.7

FROM rust:slim-bookworm AS chef

WORKDIR /workspace

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef --locked --version 0.1.74

FROM chef AS planner

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates/score-simulator/Cargo.toml crates/score-simulator/Cargo.toml

RUN mkdir -p src crates/score-simulator/src \
    && printf "fn main() {}\n" > src/main.rs \
    && printf "fn main() {}\n" > crates/score-simulator/src/main.rs \
    && cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates/score-simulator/Cargo.toml crates/score-simulator/Cargo.toml
COPY --from=planner /workspace/recipe.json recipe.json
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    cargo chef cook --release --locked --recipe-path recipe.json

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates/score-simulator/Cargo.toml crates/score-simulator/Cargo.toml
COPY migrations ./migrations
COPY src ./src
COPY crates/score-simulator/src crates/score-simulator/src

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    rm -f /workspace/target/release/brrpolice /workspace/target/release/deps/brrpolice* \
    && cargo build --release --locked -p brrpolice --bin brrpolice \
    && mkdir -p /workspace/data

FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /workspace/target/release/brrpolice /app/brrpolice
COPY --from=builder --chown=nonroot:nonroot /workspace/data /data
COPY --from=builder /workspace/migrations /app/migrations
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV BRRPOLICE_DATABASE__PATH=/data/brrpolice.sqlite
ENV BRRPOLICE_HTTP__HOST=0.0.0.0
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 9090
USER nonroot:nonroot
ENTRYPOINT ["/app/brrpolice"]
