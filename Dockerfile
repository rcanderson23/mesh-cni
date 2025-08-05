FROM rust:1.88-trixie AS builder

RUN apt-get update && \
  apt-get -y install ca-certificates \
  llvm && \
  update-ca-certificates
RUN rustup install stable && \
  rustup toolchain install nightly --component rust-src && \
  cargo install just --locked && \
  cargo install bpf-linker
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY . .

RUN just build

FROM gcr.io/distroless/cc-debian12

WORKDIR /app

COPY --from=builder /app/target/release/homelab-cni /app/homelab-cni

ENTRYPOINT [ "/app/homelab-cni" ]

