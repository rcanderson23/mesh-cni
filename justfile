name := "mesh-cni"
set shell := ["bash", "-euo", "pipefail", "-c"]
container_image := "ghcr.io/rcanderson23/" + name
image_tag := env_var_or_default("IMAGE_TAG", "local")
kind_path := "./kind/two-node.yaml"
kindnet_image := "docker.io/kindest/kindnetd:v20230809-80a64d96"
kubeconfig_dir := "./.kube"
cluster1_name := name + "-1"
cluster2_name := name + "-2"
cluster1_kind_path := "./kind/cluster1.yaml"
cluster2_kind_path := "./kind/cluster2.yaml"
cluster1_kubeconfig := kubeconfig_dir + "/" + cluster1_name + ".yaml"
cluster2_kubeconfig := kubeconfig_dir + "/" + cluster2_name + ".yaml"
cluster1_internal_kubeconfig := kubeconfig_dir + "/" + cluster1_name + "-internal.yaml"
cluster2_internal_kubeconfig := kubeconfig_dir + "/" + cluster2_name + "-internal.yaml"
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
  docker buildx build --tag {{container_image}}:{{image_tag}} . --load

build:
  cargo build --release

test target=host_target:
  cargo test --target {{target}}

kind-up mode='vxlan':
  if kind get clusters | grep -qx '{{cluster1_name}}'; then \
    echo "kind cluster {{cluster1_name}} already exists"; \
  else \
    kind create cluster --name={{cluster1_name}} --config={{kind_path}}; \
  fi
  just _ensure_kindnet_context kind-{{cluster1_name}} {{mode}}

kind-down:
  kind delete cluster --name={{cluster1_name}} || true

install mode='vxlan':
  just _install_context kind-{{cluster1_name}} {{mode}}

restart:
  just _restart_context kind-{{cluster1_name}}

load-image:
  just _load_image {{cluster1_name}}

reset-cluster mode='vxlan':
  just kind-down
  just run-local {{mode}}

multi-kind-up mode='vxlan':
  mkdir -p {{kubeconfig_dir}}
  if kind get clusters | grep -qx '{{cluster1_name}}'; then \
    echo "kind cluster {{cluster1_name}} already exists"; \
  else \
    kind create cluster --name={{cluster1_name}} --config={{cluster1_kind_path}}; \
  fi
  if kind get clusters | grep -qx '{{cluster2_name}}'; then \
    echo "kind cluster {{cluster2_name}} already exists"; \
  else \
    kind create cluster --name={{cluster2_name}} --config={{cluster2_kind_path}}; \
  fi
  kind export kubeconfig --name={{cluster1_name}} --kubeconfig={{cluster1_kubeconfig}}
  kind export kubeconfig --name={{cluster2_name}} --kubeconfig={{cluster2_kubeconfig}}
  kind export kubeconfig --name={{cluster1_name}} --internal --kubeconfig={{cluster1_internal_kubeconfig}}
  kind export kubeconfig --name={{cluster2_name}} --internal --kubeconfig={{cluster2_internal_kubeconfig}}
  just _ensure_kindnet_kubeconfig {{cluster1_kubeconfig}} {{mode}}
  just _ensure_kindnet_kubeconfig {{cluster2_kubeconfig}} {{mode}}

multi-kind-down:
  kind delete cluster --name={{cluster1_name}} || true
  kind delete cluster --name={{cluster2_name}} || true

multi-load-image:
  just _load_image {{cluster1_name}}
  just _load_image {{cluster2_name}}

multi-install mode='vxlan':
  just _install_kubeconfig {{cluster1_kubeconfig}} {{mode}}
  just _install_kubeconfig {{cluster2_kubeconfig}} {{mode}}

multi-create-kubeconfig-secrets:
  just _create_remote_secret {{cluster1_kubeconfig}} {{cluster1_remote_secret}} {{cluster2_internal_kubeconfig}}
  just _create_remote_secret {{cluster2_kubeconfig}} {{cluster2_remote_secret}} {{cluster1_internal_kubeconfig}}

multi-apply-cluster-crs:
  just _apply_file {{cluster1_kubeconfig}} kind/cluster-cr-cluster2.yaml
  just _apply_file {{cluster2_kubeconfig}} kind/cluster-cr-cluster1.yaml

multi-restart:
  just _restart_kubeconfig {{cluster1_kubeconfig}}
  just _restart_kubeconfig {{cluster2_kubeconfig}}

run-local mode='vxlan':
  just container
  just kind-up {{mode}}
  just load-image
  just install {{mode}}
  just restart

multi-run-local mode='vxlan':
  just container
  just multi-kind-up {{mode}}
  just multi-load-image
  just multi-install {{mode}}
  just multi-create-kubeconfig-secrets
  just multi-restart
  just multi-apply-cluster-crs

multi-reset-cluster mode='vxlan':
  just multi-kind-down
  just multi-run-local {{mode}}

gen-crds:
  mkdir -p charts/mesh-cni/crds
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind mesh-endpoint > charts/mesh-cni/crds/meshendpoint.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind identity > charts/mesh-cni/crds/identity.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind cidr-identity > charts/mesh-cni/crds/cidridentity.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind cluster > charts/mesh-cni/crds/cluster.yaml
  cargo run --target {{host_target}} -p mesh-cni-crds-gen -- --kind mesh-identity-slice > charts/mesh-cni/crds/meshidentityslice.yaml

_install_context context mode:
  [[ "{{mode}}" == "vxlan" || "{{mode}}" == "chained" ]] || { \
    echo "invalid mode: {{mode}} (expected vxlan or chained)" >&2; \
    exit 1; \
  }
  cluster_url="https://$(kubectl --context {{context}} get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | tr -d '\n'):6443"; \
  helm upgrade --install {{name}} ./charts/mesh-cni --kube-context {{context}} -n mesh-cni --create-namespace --set=agent.image.tag={{image_tag}} --set=controller.image.tag={{image_tag}} --set=agent.mode={{mode}} --set-string=agent.clusterURL="${cluster_url}"

_install_kubeconfig kubeconfig mode:
  [[ "{{mode}}" == "vxlan" || "{{mode}}" == "chained" ]] || { \
    echo "invalid mode: {{mode}} (expected vxlan or chained)" >&2; \
    exit 1; \
  }
  cluster_url="https://$(kubectl --kubeconfig {{kubeconfig}} get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | tr -d '\n'):6443"; \
  helm upgrade --install {{name}} ./charts/mesh-cni --kubeconfig {{kubeconfig}} -n mesh-cni --create-namespace --set=agent.image.tag={{image_tag}} --set=controller.image.tag={{image_tag}} --set=agent.mode={{mode}} --set-string=agent.clusterURL="${cluster_url}"

_restart_context context:
  kubectl --context {{context}} rollout restart daemonset -n mesh-cni {{name}}-agent
  kubectl --context {{context}} rollout restart deployment -n mesh-cni {{name}}-controller

_restart_kubeconfig kubeconfig:
  kubectl --kubeconfig {{kubeconfig}} rollout restart daemonset -n mesh-cni {{name}}-agent
  kubectl --kubeconfig {{kubeconfig}} rollout restart deployment -n mesh-cni {{name}}-controller

_load_image cluster:
  kind load docker-image {{container_image}}:{{image_tag}} --name={{cluster}}

_create_remote_secret kubeconfig secret_name remote_kubeconfig:
  kubectl --kubeconfig {{kubeconfig}} -n mesh-cni create secret generic {{secret_name}} --from-file=config={{remote_kubeconfig}} --dry-run=client -o yaml | kubectl --kubeconfig {{kubeconfig}} apply -f -

_apply_file kubeconfig file:
  kubectl --kubeconfig {{kubeconfig}} apply -f {{file}}

_ensure_kindnet_context context mode:
  if [[ "{{mode}}" == "chained" ]]; then \
    kubectl --context {{context}} -n kube-system set image ds kindnet kindnet-cni={{kindnet_image}}; \
  fi

_ensure_kindnet_kubeconfig kubeconfig mode:
  if [[ "{{mode}}" == "chained" ]]; then \
    kubectl --kubeconfig {{kubeconfig}} -n kube-system set image ds kindnet kindnet-cni={{kindnet_image}}; \
  fi
