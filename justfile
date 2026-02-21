name := "mesh-cni"
container_image := "ghcr.io/rcanderson23/" + name
kind_path := "./kind/single-node.yaml"
kindnet_image := "docker.io/kindest/kindnetd:v20230809-80a64d96"
kubeconfig_dir := "./.kube"
cluster1_name := "cluster1"
cluster2_name := "cluster2"
cluster1_kind_path := "./kind/cluster1.yaml"
cluster2_kind_path := "./kind/cluster2.yaml"
cluster1_kubeconfig := kubeconfig_dir + "/cluster1.yaml"
cluster2_kubeconfig := kubeconfig_dir + "/cluster2.yaml"
cluster1_internal_kubeconfig := kubeconfig_dir + "/cluster1-internal.yaml"
cluster2_internal_kubeconfig := kubeconfig_dir + "/cluster2-internal.yaml"
cluster1_remote_secret := "mesh-remote-" + cluster2_name + "-kubeconfig"
cluster2_remote_secret := "mesh-remote-" + cluster1_name + "-kubeconfig"
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
  kind create cluster --name={{name}} --config={{kind_path}}
  # Set to version of kindnet that does not support network policy
  kubectl -n kube-system set image ds kindnet kindnet-cni={{kindnet_image}}

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

reset-cluster: kind-down run-local

multi-kind-up:
  mkdir -p {{kubeconfig_dir}}
  kind create cluster --name={{cluster1_name}} --config={{cluster1_kind_path}}
  kind create cluster --name={{cluster2_name}} --config={{cluster2_kind_path}}
  kind export kubeconfig --name={{cluster1_name}} --kubeconfig={{cluster1_kubeconfig}}
  kind export kubeconfig --name={{cluster2_name}} --kubeconfig={{cluster2_kubeconfig}}
  kind export kubeconfig --name={{cluster1_name}} --internal --kubeconfig={{cluster1_internal_kubeconfig}}
  kind export kubeconfig --name={{cluster2_name}} --internal --kubeconfig={{cluster2_internal_kubeconfig}}
  # Set to version of kindnet that does not support network policy
  kubectl --kubeconfig {{cluster1_kubeconfig}} -n kube-system set image ds kindnet kindnet-cni={{kindnet_image}}
  kubectl --kubeconfig {{cluster2_kubeconfig}} -n kube-system set image ds kindnet kindnet-cni={{kindnet_image}}

multi-kind-down:
  kind delete cluster --name={{cluster1_name}} || true
  kind delete cluster --name={{cluster2_name}} || true

multi-load-image:
  kind load docker-image {{container_image}}:latest --name={{cluster1_name}}
  kind load docker-image {{container_image}}:latest --name={{cluster2_name}}

multi-install:
  helm upgrade --install {{name}} ./charts/mesh-cni --kubeconfig {{cluster1_kubeconfig}} -n kube-system --create-namespace --set=agent.image.tag=latest --set=controller.image.tag=latest --set=agent.clusterURL="$(kubectl config view --kubeconfig {{cluster1_internal_kubeconfig}} --minify -o jsonpath='{.clusters[0].cluster.server}')"
  helm upgrade --install {{name}} ./charts/mesh-cni --kubeconfig {{cluster2_kubeconfig}} -n kube-system --create-namespace --set=agent.image.tag=latest --set=controller.image.tag=latest --set=agent.clusterURL="$(kubectl config view --kubeconfig {{cluster2_internal_kubeconfig}} --minify -o jsonpath='{.clusters[0].cluster.server}')"

multi-create-kubeconfig-secrets:
  kubectl --kubeconfig {{cluster1_kubeconfig}} -n kube-system create secret generic {{cluster1_remote_secret}} --from-file=config={{cluster2_internal_kubeconfig}} --dry-run=client -o yaml | kubectl --kubeconfig {{cluster1_kubeconfig}} apply -f -
  kubectl --kubeconfig {{cluster2_kubeconfig}} -n kube-system create secret generic {{cluster2_remote_secret}} --from-file=config={{cluster1_internal_kubeconfig}} --dry-run=client -o yaml | kubectl --kubeconfig {{cluster2_kubeconfig}} apply -f -

multi-apply-cluster-crs:
  kubectl --kubeconfig {{cluster1_kubeconfig}} apply -f kind/cluster-cr-cluster2.yaml
  kubectl --kubeconfig {{cluster2_kubeconfig}} apply -f kind/cluster-cr-cluster1.yaml

multi-restart:
  kubectl --kubeconfig {{cluster1_kubeconfig}} rollout restart daemonset -n kube-system {{name}}-agent
  kubectl --kubeconfig {{cluster1_kubeconfig}} rollout restart deployment -n kube-system {{name}}-controller
  kubectl --kubeconfig {{cluster2_kubeconfig}} rollout restart daemonset -n kube-system {{name}}-agent
  kubectl --kubeconfig {{cluster2_kubeconfig}} rollout restart deployment -n kube-system {{name}}-controller

multi-run-local: container multi-kind-up multi-load-image multi-install multi-create-kubeconfig-secrets multi-restart multi-apply-cluster-crs

multi-reset-cluster: multi-kind-down multi-run-local

gen-crds:
  mkdir -p charts/mesh-cni/crds
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind mesh-endpoint > charts/mesh-cni/crds/meshendpoint.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind identity > charts/mesh-cni/crds/identity.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind cidr-identity > charts/mesh-cni/crds/cidridentity.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind cluster > charts/mesh-cni/crds/cluster.yaml
