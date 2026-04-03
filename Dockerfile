# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.94

FROM rust:${RUST_VERSION}-trixie AS chef

RUN curl -sS https://debian.griffo.io/EA0F721D231FDD3A0A17B9AC7808B4DD62C41256.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/debian.griffo.io.gpg && \
  echo "deb https://debian.griffo.io/apt trixie main" | tee /etc/apt/sources.list.d/debian.griffo.io.list 

RUN apt-get update && \
  apt-get -y install \
  ca-certificates \
  libclang-dev \
  llvm \
  protobuf-compiler \
  zig && \
  update-ca-certificates

RUN rustup toolchain install nightly --component rust-src && \
  cargo install --locked cargo-chef cargo-zigbuild bpf-linker

WORKDIR /app

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

ARG TARGETARCH

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json
COPY mesh-cni-api/proto mesh-cni-api/proto
COPY mesh-cni-ebpf mesh-cni-ebpf
COPY mesh-cni-ebpf-common mesh-cni-ebpf-common

RUN case "${TARGETARCH}" in \
  amd64)  echo x86_64-unknown-linux-musl > /tmp/rust_target ;; \
  arm64)  echo aarch64-unknown-linux-musl > /tmp/rust_target ;; \
  *)      echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
  esac && \
  rustup target add "$(cat /tmp/rust_target)"


RUN cargo chef cook --zigbuild --release --recipe-path recipe.json --target "$(cat /tmp/rust_target)"

COPY . .

RUN RUST_TARGET="$(cat /tmp/rust_target)" && \
  cargo zigbuild --release --target "${RUST_TARGET}" \
  --bin mesh-cni \
  --bin mesh-cni-plugin \
  --bin mesh && \
  mkdir -p /out && \
  cp "target/${RUST_TARGET}/release/mesh-cni" /out/ && \
  cp "target/${RUST_TARGET}/release/mesh-cni-plugin" /out/ && \
  cp "target/${RUST_TARGET}/release/mesh" /out/

FROM public.ecr.aws/eks-distro/kubernetes-sigs/aws-iam-authenticator:v0.7.4-eks-1-34-latest AS aws-iam

FROM debian:trixie-slim AS runtime

WORKDIR /app
ENV PATH="$PATH:/app"

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  ca-certificates \
  nftables && \
  rm -rf /var/lib/apt/lists/* && \
  update-ca-certificates

COPY --from=builder /out/mesh-cni /out/mesh-cni-plugin /out/mesh /app/
COPY --from=aws-iam /aws-iam-authenticator /app/

ENTRYPOINT ["/app/mesh-cni"]
