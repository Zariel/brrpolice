# syntax=docker/dockerfile:1.7

FROM rust:slim-bookworm AS builder

WORKDIR /workspace

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./

RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --locked

COPY migrations ./migrations
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --locked \
    && mkdir -p /workspace/data

FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /workspace/target/release/brrpolice /app/brrpolice
COPY --from=builder --chown=nonroot:nonroot /workspace/data /data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV BRRPOLICE_DATABASE__PATH=/data/brrpolice.sqlite
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 9090
USER nonroot:nonroot
ENTRYPOINT ["/app/brrpolice"]
