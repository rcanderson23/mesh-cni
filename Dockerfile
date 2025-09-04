# when changing image be aware of GLIB version matching in build and running images
FROM rust:1.89-bookworm AS builder

RUN apt-get update && \
  apt-get -y install ca-certificates \
  protobuf-compiler \
  llvm && \
  update-ca-certificates

RUN rustup install stable && \
  rustup toolchain install nightly --component rust-src && \
  cargo install just --locked && \
  cargo install bpf-linker
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY mesh-cni-plugin mesh-cni-plugin
COPY mesh-cni-api mesh-cni-api
COPY mesh-cni-cli mesh-cni-cli
COPY mesh-cni mesh-cni
COPY mesh-cni-common mesh-cni-common
COPY mesh-cni-ebpf mesh-cni-ebpf
COPY justfile justfile

RUN just build

FROM gcr.io/distroless/cc-debian12

WORKDIR /app
ENV PATH="$PATH:/app"

COPY --from=builder /app/target/release/mesh-cni /app/target/release/mesh-cni-plugin /app/target/release/mesh /app/

ENTRYPOINT [ "/app/mesh-cni" ]

