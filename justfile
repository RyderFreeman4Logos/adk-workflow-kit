set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

_io := "ionice -c 3"

default: pre-commit-fast

fmt:
    {{_io}} cargo fmt --all

fmt-check:
    {{_io}} cargo fmt --all -- --check

check:
    {{_io}} cargo +1.98.0 check --workspace --all-targets --locked

clippy:
    {{_io}} cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings

test:
    {{_io}} cargo +1.98.0 test --workspace --locked
    ./target/debug/workflowctl test crates/workflowctl/tests/fixtures/cli004-test.json
    ./target/debug/workflowctl eval crates/workflowctl/tests/fixtures/cli004-eval.json
    ./target/debug/workflowctl replay crates/workflowctl/tests/fixtures/cli004-replay.json
    if ./target/debug/workflowctl audit; then exit 1; else test "$?" -eq 2; fi

bench-001:
    {{_io}} cargo run -p workflow-testkit --bin bench-001 --locked

m1-01-red:
    {{_io}} cargo +1.98.0 test -p adk-2-1-ownership --locked

m1-01-green:
    {{_io}} cargo +1.98.0 test -p adk-2-1-ownership --locked

lock:
    {{_io}} cargo generate-lockfile

# Verify Cargo.lock already matches the workspace manifests without rewriting it.
lock-check:
    {{_io}} cargo metadata --format-version 1 --locked > /dev/null

metadata:
    {{_io}} cargo metadata --format-version 1 --locked

dependency-audit:
    {{_io}} cargo deny check licenses advisories

test-local-gates:
    bash scripts/test-local-gates.sh

test-releasing:
    bash scripts/test-releasing.sh

release-local:
    bash scripts/local-release.sh

test-release-local:
    bash scripts/test-local-release.sh

check-branch:
    scripts/local-gates.sh check-branch

pre-commit-fast: check-branch fmt-check lock-check check clippy dependency-audit test-local-gates

_quality-gates: fmt-check check clippy dependency-audit test test-local-gates

quality-gates:
    scripts/local-gates.sh produce

pre-push:
    scripts/local-gates.sh pre-push

# Install the repository's Lefthook-managed local gates after cloning.
install-hooks:
    lefthook install
