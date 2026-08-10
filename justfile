set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

_io := "ionice -c 3"

default: pre-commit-fast

fmt:
    {{_io}} cargo fmt --all

fmt-check:
    {{_io}} cargo fmt --all -- --check

check:
    {{_io}} cargo check --workspace --all-targets --locked

clippy:
    {{_io}} cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    {{_io}} cargo test --workspace --locked

lock:
    {{_io}} cargo generate-lockfile

# Verify Cargo.lock already matches the workspace manifests without rewriting it.
lock-check:
    {{_io}} cargo generate-lockfile --locked

metadata:
    {{_io}} cargo metadata --format-version 1 --locked

test-local-gates:
    bash scripts/test-local-gates.sh

check-branch:
    scripts/local-gates.sh check-branch

pre-commit-fast: check-branch fmt-check lock-check check clippy test-local-gates

_quality-gates: fmt-check check clippy test test-local-gates

quality-gates:
    scripts/local-gates.sh produce

pre-push:
    scripts/local-gates.sh pre-push

# Install the repository's Lefthook-managed local gates after cloning.
install-hooks:
    lefthook install
