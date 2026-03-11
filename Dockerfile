# syntax=docker/dockerfile:1.7

FROM rust:1.85-bookworm AS builder
WORKDIR /workspace

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
ENV LIBSQLITE3_SYS_BUNDLED=1

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --locked

RUN mkdir -p /out/app /out/data \
    && cp /workspace/target/release/brrpolice /out/app/brrpolice \
    && chmod 0555 /out/app/brrpolice \
    && chmod 0750 /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /out/app/brrpolice /app/brrpolice
COPY --from=builder --chown=nonroot:nonroot /out/data /data

ENV BRRPOLICE_DATABASE__PATH=/data/brrpolice.sqlite

EXPOSE 9090
ENTRYPOINT ["/app/brrpolice"]
