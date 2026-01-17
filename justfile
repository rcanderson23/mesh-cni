name := "mesh-cni"
container_image := "ghcr.io/rcanderson23/" + name
kind_path := "./kind/single-node.yaml"
host_target := `rustc -vV | sed -n 's/^host: //p'`

default:
  @just --list

fmt:
  cargo +nightly fmt

lint:
  cargo clippy

container:
  docker buildx build --tag {{container_image}}:latest . --load

build:
  cargo build --release

test target=host_target:
  cargo test --target {{target}}

kind-up:
  -kind create cluster --name={{name}} --config={{kind_path}}

kind-down:
  kind delete cluster --name={{name}}

install: 
  helm upgrade --install {{name}} ./charts/mesh-cni -n kube-system --set=agent.image.tag=latest --kube-context=kind-{{name}}

restart:
  kubectl rollout restart daemonset -n kube-system {{name}}-agent
  kubectl rollout restart deployment -n kube-system {{name}}-controller

load-image:
    kind load docker-image {{container_image}}:latest --name={{name}}

run-local: container kind-up load-image install restart
