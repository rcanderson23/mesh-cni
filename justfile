name := "homelab-cni"
kind_path := "./kind/multi-node.yaml"

default:
  @just --list

fmt:
  cargo fmt

container:
  docker buildx build --tag {{name}}:latest . --load

build: 
  cargo build --release

kind-up:
  kind create cluster --name={{name}} --config={{kind_path}}

kind-down:
  kind delete cluster --name={{name}}
