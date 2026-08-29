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

m1-03-red:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test runtime_plan --locked

m1-03-green:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test runtime_plan --locked

# Focused M1-15 conformance contract tests.
m1-15-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance --locked

# Focused M1-15 production-boundary translation tests.
m1-15-translation:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test translation --locked

# Focused M1-15 production ToolBridge terminal-outcome tests.
m1-15-adk-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test tool_bridge --locked

# Focused M1-15 ToolBridge authorization tests.
m1-15-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test m1_07_tool_bridge --locked

# Focused M1-15 checkpoint terminal-mapping tests.
m1-15-checkpoint:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m1_11_execution_checkpoints --locked

# Network-free M1-15 aggregate: adapter graph/events, approval, tool+sandbox, fault injection,
# checkpoint/resume (including destructive SIGKILL), artifact integrity, and its report contract.
conformance:
    report="${CONFORMANCE_REPORT:-target/m1-15-conformance.md}"; head="$(git rev-parse HEAD)"; tree="$(git write-tree)"; mkdir -p "$(dirname "$report")"; status=PASS; evidence="$(mktemp)"; trap 'rm -f "$evidence"' EXIT; run() { command="$1"; shift; if "$@"; then result=PASS; else result=FAIL; status=FAIL; fi; printf '%s\t%s\n' "$result" "$command" >> "$evidence"; }; run "ionice -c 3 cargo +1.98.0 test -p workflow-adk --test translation --locked" {{_io}} cargo +1.98.0 test -p workflow-adk --test translation --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-adk --test translation fan_in_state_conflict_is_executable --locked" {{_io}} cargo +1.98.0 test -p workflow-adk --test translation fan_in_state_conflict_is_executable --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-adk --test events --locked" {{_io}} cargo +1.98.0 test -p workflow-adk --test events --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-adk --test tool_bridge --locked" {{_io}} cargo +1.98.0 test -p workflow-adk --test tool_bridge --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-runtime --test m1_07_tool_bridge --locked" {{_io}} cargo +1.98.0 test -p workflow-runtime --test m1_07_tool_bridge --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-testkit --test fault_injection --locked" {{_io}} cargo +1.98.0 test -p workflow-testkit --test fault_injection --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-testkit --test code_investigation --locked" {{_io}} cargo +1.98.0 test -p workflow-testkit --test code_investigation --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-adk --test m1_11_execution_checkpoints --locked" {{_io}} cargo +1.98.0 test -p workflow-adk --test m1_11_execution_checkpoints --locked; run "ionice -c 3 cargo +1.98.0 test -p workflowctl --test m1_10_adk_run --locked" {{_io}} cargo +1.98.0 test -p workflowctl --test m1_10_adk_run --locked; run "ionice -c 3 cargo +1.98.0 test -p workflowctl --test m1_12_destructive_resume --locked" {{_io}} cargo +1.98.0 test -p workflowctl --test m1_12_destructive_resume --locked; run "ionice -c 3 cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance --locked" {{_io}} cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance --locked; {{_io}} cargo +1.98.0 run -p workflow-testkit --bin m1-15-report --locked -- "$report" "$head" "$tree" "$status" "$evidence"; test "$status" = PASS

# Opt in without inspecting credentials; the M1-14 dogfood either completes or safely abstains.
conformance-live:
    if test "${WORKFLOW_KIT_M1_15_LIVE:-0}" != 1; then echo "M1-15 live dogfood: SKIP (set WORKFLOW_KIT_M1_15_LIVE=1 to opt in)"; exit 0; fi; {{_io}} cargo +1.98.0 run -p workflow-testkit --bin m1-15-live --locked

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
