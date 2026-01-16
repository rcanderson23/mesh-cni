# when changing image be aware of GLIB version matching in build and running images
FROM rust:1.92-trixie AS builder

RUN apt-get update && \
  apt-get -y install ca-certificates \
  protobuf-compiler \
  llvm && \
  update-ca-certificates

RUN rustup install stable && \
  rustup toolchain install nightly --component rust-src && \
  cargo install bpf-linker
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY mesh-cni-plugin mesh-cni-plugin
COPY mesh-cni-api mesh-cni-api
COPY mesh-cni-cli mesh-cni-cli
COPY mesh-cni mesh-cni
COPY mesh-cni-ebpf-common mesh-cni-ebpf-common
COPY mesh-cni-identity-gen-controller mesh-cni-identity-gen-controller
COPY mesh-cni-policy-controller mesh-cni-policy-controller
COPY mesh-cni-policy-ebpf mesh-cni-policy-ebpf
COPY mesh-cni-service-ebpf mesh-cni-service-ebpf
COPY mesh-cni-k8s-utils mesh-cni-k8s-utils
COPY mesh-cni-crds mesh-cni-crds
COPY mesh-cni-service-controller mesh-cni-service-controller
COPY mesh-cni-service-bpf-controller mesh-cni-service-bpf-controller
COPY mesh-cni-cluster-controller mesh-cni-cluster-controller

RUN cargo build --release

FROM public.ecr.aws/eks-distro/kubernetes-sigs/aws-iam-authenticator:v0.7.4-eks-1-34-latest AS aws-iam

FROM debian:trixie-slim

WORKDIR /app
ENV PATH="$PATH:/app"

COPY --from=builder /app/target/release/mesh-cni /app/target/release/mesh-cni-plugin /app/target/release/mesh /app/
COPY --from=aws-iam /aws-iam-authenticator /app/

ENTRYPOINT [ "/app/mesh-cni" ]
