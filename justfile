name := "homelab-cni"
container_image := "ghcr.io/rcanderson23/" + name
kind_path := "./kind/multi-node.yaml"

default:
  @just --list

fmt:
  cargo fmt

container:
  docker buildx build --tag {{container_image}}:latest . --load

build: 
  cargo build --release

kind-up:
  -kind create cluster --name={{name}} --config={{kind_path}}

kind-down:
  kind delete cluster --name={{name}}

install: 
  helm upgrade --install {{name}} ./charts/homelab-cni -n kube-system --set=agent.image.tag=latest

restart:
  kubectl rollout restart daemonset -n kube-system {{name}}-agent

load-image:
    kind load docker-image {{container_image}}:latest --name={{name}}

run-local: container kind-up load-image install restart
