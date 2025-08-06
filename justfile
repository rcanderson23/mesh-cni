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
  #!/usr/bin/which bash
  kind get clusters --name={{name}} | grep {{name}}
  status=$?
  if [ $status -ne 0];
  then
    kind create cluster --name={{name}} --config={{kind_path}}
  fi
    

kind-down:
  kind delete cluster --name={{name}}

run-local: container kind-up load-image
  helm upgrade --install {{name}} ./charts/homelab-cni -n kube-system --set=agent.image.tag=latest

load-image:
    kind load docker-image {{container_image}}:latest --name={{name}}
