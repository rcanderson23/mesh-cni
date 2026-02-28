# Repository Guidelines

## Project Structure & Module Organization
- Rust workspace with multiple crates under `mesh-cni*/` directories.
- Core agent/controller logic lives in `mesh-cni/src/`.
- CLI tool is in `mesh-cni-cli/src/`.
- eBPF code is in `mesh-cni-ebpf/src/` with shared types in `mesh-cni-ebpf-common/src/`.
- Kubernetes manifests and Helm chart are under `charts/mesh-cni/`; local kind configs are under `kind/`.

## Build, Test, and Development Commands
- `just test`: run unit tests across the workspace.
- `just fmt`: format Rust code (uses `rustfmt.toml`).
- `just build`: release build via `justfile`.
- `just container`: build Docker image for the CNI.
- `just run-local`: build, create kind cluster, load image, install Helm chart, and restart.
- `just reset-cluster`: tear down and recreate local cluster with current changes.
- `just multi-run-local`: build and deploy both multi-cluster kind environments.
- `just multi-reset-cluster`: recreate multi-cluster environments from scratch.

## Coding Style & Naming Conventions
- Rust edition 2024; follow `rustfmt.toml` and run `just fmt`.
- Use Rust conventions:
- `snake_case` for modules/functions.
- `CamelCase` for types.
- `SCREAMING_SNAKE_CASE` for constants.
- Prefer explicit module structure and keep related logic grouped by domain.

## Testing Guidelines
- Unit tests live inline with modules using `#[cfg(test)]`.
- Run `just test` for full coverage.
- Use targeted tests during iteration, for example:
- `cargo test -p mesh-cni`
- `cargo test -p mesh-cni-policy-controller`
- Name tests descriptively (for example `generate_endpoint_events`).

## Security & Configuration Tips
- For local clusters, use provided `kind/*.yaml` files and `charts/mesh-cni/`.
- When changing host/kernel settings (for example conntrack/sysctl), prefer additive/non-destructive updates.
