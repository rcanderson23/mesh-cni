# mesh-cni

Just a CNI that I am writing for my homelab, currently only works (partially) on a local cluster via Kind.

[End Goal](https://github.com/rcanderson23/mesh-cni/issues/6)

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features --features=llvm-21` on macOS)
1. just: `cargo install just --locked`
1. kind: [Installation](https://kind.sigs.k8s.io/#installation-and-usage)

## Deploy to local cluster

Deploy to a local [Kind](https://kind.sigs.k8s.io/) cluster by running `just run-local`. Depending on your setup, you may need to adjust the var `agent.clusterURL` found at `charts/mesh-cni/values.yaml` to match the Kubernetes endpoint for your Kind
cluster.

Changes to the BPF maps may require resetting the cluster. This can be done with a `just kind-down` and `just run-local`.

## CRDs

### Cluster

Meshes configured cluster state into the local cluster allowing for services to be routed to the local and remote cluster (if configured with multi-cluster annotation).

Example:

```yaml
apiVersion: mesh-cni.dev/v1alpha1
kind: Cluster
metadata:
  name: cluster2
spec:
  secret:
    name: mesh-remote-cluster2-kubeconfig
    key: config
```

The referenced Secret must exist in the controller namespace and contain kubeconfig bytes under `data.config`.

### MeshEndpoint

`MeshEndpoint` are controller-derived and should not be manually created. Created when a `Service` is annotated with the multi-cluster annotation.
Contains endpoint information from the owned cluster and represents state that should be programmed into the service BPF map.

To include a Service in multi-cluster mesh endpoint generation, set:

```yaml
metadata:
  annotations:
    mesh-cni.dev/multi-cluster: "true"
```

Example:

```yaml
apiVersion: mesh-cni.dev/v1alpha1
kind: MeshEndpoint
metadata:
  name: web-cluster2
  namespace: app
  labels:
    kubernetes.io/service-name: web
    mesh-cni.dev/cluster-owner: cluster2
spec:
  service_ips:
    - 10.97.10.20
  backend_port_mappings:
    - ip: 10.242.0.21
      service_port: 80
      backend_port: 8080
      protocol: TCP
```

### Identity and CIDRIdentity

`Identity` and `CIDRIdentity` are controller-derived and should not be manually created. `Identity` are created from unique sets of pods based on labels. `CIDRIdentity` is generated based on 
`ipBlock` present in `NetworkPolicy` resources in the cluster. Both are used to program the policy related BPF maps.

Example generated `Identity`:

```yaml
apiVersion: mesh-cni.dev/v1alpha1
kind: Identity
metadata:
  name: web-identity
  namespace: app
spec:
  id: 2599738693
  namespaceLabels:
    kubernetes.io/metadata.name: app
  podLabels:
    app: web
```

Example generated `CIDRIdentity`:

```yaml
apiVersion: mesh-cni.dev/v1alpha1
kind: CIDRIdentity
metadata:
  name: cidr-10-0-0-0-8
spec:
  id: 30002
  cidr: 10.0.0.0/8
  except:
    - 10.96.0.0/12
  cidrPrefixes:
    - 10.0.0.0/9
    - 10.128.0.0/10
    - 10.192.0.0/11
    - 10.224.0.0/12
```

## Multi-Cluster Local Setup

For two kind clusters on the same Docker network with cross-cluster kubeconfig secrets and `Cluster` CRs applied:

```bash
just multi-reset-cluster
```

## License

With the exception of eBPF code, mesh-cni is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
