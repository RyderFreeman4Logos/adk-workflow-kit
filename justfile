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
    {{_io}} cargo +1.98.0 build -p workflowctl --locked
    {{_io}} cargo +1.98.0 test --workspace --exclude workflow-adk --locked
    {{_io}} cargo +1.98.0 test -p workflow-adk --locked -- --test-threads=1
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

# Focused M3-02 per-node binding tests.
m3-02-spec test_name:
    {{_io}} cargo +1.98.0 test -p workflow-spec --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

m3-02-compiler test_name:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

m3-02-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

# Focused #265 tool implementation registry tests.
issue-265-runtime test_name:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_265_tool_registry {{test_name}} --locked -- --exact --nocapture

issue-265-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_265_tool_registry {{test_name}} --locked -- --exact --nocapture --test-threads=1

# Focused M3-03 per-node multi-tool registry tests.
m3-03-spec test_name:
    {{_io}} cargo +1.98.0 test -p workflow-spec --test m3_03_multi_tool_registry {{test_name}} --locked -- --exact --nocapture

m3-03-compiler test_name:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test m3_03_multi_tool_registry {{test_name}} --locked -- --exact --nocapture

m3-03-runtime test_name:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test m3_03_multi_tool_registry {{test_name}} --locked -- --exact --nocapture

m3-03-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_03_multi_tool_registry {{test_name}} --locked -- --exact --nocapture

m3-04-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_04_model_tool_loop {{test_name}} --locked -- --exact --nocapture

# Focused M3-05 per-agent Skill runtime tests.
m3-05-spec test_name:
    {{_io}} cargo +1.98.0 test -p workflow-spec --test m3_05_skill_bindings {{test_name}} --locked -- --exact --nocapture

m3-05-ir test_name:
    {{_io}} cargo +1.98.0 test -p workflow-ir --test m3_05_skill_ir {{test_name}} --locked -- --exact --nocapture

m3-05-compiler test_name:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test m3_05_skill_runtime {{test_name}} --locked -- --exact --nocapture

m3-05-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_05_skill_runtime {{test_name}} --locked -- --exact --nocapture

# Focused M3-06 canonical code-investigation example tests.
m3-06-cli test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m3_06_code_investigation {{test_name}} --locked -- --exact --nocapture

# Focused M3-07 opt-in live OpenAI-compatible conformance tests.
m3-07-cli test_name="":
    {{_io}} cargo +1.98.0 test -p workflowctl --test m3_07_live_conformance {{test_name}} --locked -- --nocapture

# Opt in without inspecting credentials; SKIP unless explicitly requested.
m3-07-live profile="":
    if test "${WORKFLOW_KIT_M3_07_LIVE:-0}" != 1; then echo "M3-07 live conformance: SKIP (set WORKFLOW_KIT_M3_07_LIVE=1 to opt in)"; exit 0; fi; if test -z "{{profile}}"; then echo "M3-07 live conformance: FAIL (missing profile)"; exit 2; fi; {{_io}} cargo +1.98.0 build -p workflowctl --locked; {{_io}} cargo +1.98.0 run -p workflow-testkit --bin m3-07-live --locked -- ./target/debug/workflowctl "{{profile}}"

# Focused #267 deterministic validator, approval, and write tests.
issue-267-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_267_deterministic_nodes --locked -- --nocapture

# Focused #224 reference-workflow package and runner contract tests.
m3-08-reference:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m3_08_reference_workflow --locked -- --nocapture

m3-04-unit test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk {{test_name}} --lib --locked -- --exact --nocapture

m3-04-cli test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m1_12_destructive_resume {{test_name}} --locked -- --exact --nocapture

m1-10-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m1_10_adk_run {{test_name}} --locked -- --exact --nocapture

# Focused M1-15 conformance contract tests.
m1-15-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance --locked

# Focused M1-15 production-boundary translation tests.
m1-15-translation:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test translation --locked

# Focused #223 ADK-Rust 2.1.0 production-path probe.
adk-2-1-probe:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test adk_2_1_compat --locked -- --nocapture

# Focused M1-15 production ToolBridge terminal-outcome tests.
m1-15-adk-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test tool_bridge --locked

# Focused M1-15 ToolBridge authorization tests.
m1-15-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test m1_07_tool_bridge --locked

# Focused M1-15 checkpoint terminal-mapping tests.
m1-15-checkpoint:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m1_11_execution_checkpoints --locked

# Focused M1-16 README, CLI decomposition, and secure-open regression tests.
m1-16-test:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m1_16_readme_cli_decompose --locked
    {{_io}} cargo +1.98.0 test -p workflowctl --test cli_contracts --locked
    {{_io}} cargo +1.98.0 test -p workflowctl --test skill_commands --locked

# TDD evidence for the #187 recipes-consumer create/no-create decision.
m2-02-red:
    python3 scripts/test_m2_02_recipes_consumer.py

m2-02-green:
    python3 scripts/test_m2_02_recipes_consumer.py

# Validate the machine-readable ADK-Rust pattern catalog.
pattern-catalog-test:
    python3 scripts/test_pattern_catalog.py

# Run one static matrix selector through the Just-only Cargo boundary.
conformance-contract selector:
    set -- {{selector}}; test "$#" -eq 4; test "$2" = --test; M1_15_FIXTURE_RECEIPT_SELECTOR="{{selector}}" env -u M1_15_PROBE_SELECTOR {{_io}} cargo +1.98.0 test -p "$1" --test "$3" "$4" --locked -- --exact --nocapture

# Run a selected contract through its test-owned structured receipt boundary.
conformance-probe selector:
    set -- {{selector}}; test "$#" -eq 4; test "$2" = --test; M1_15_PROBE_SELECTOR="{{selector}}" {{_io}} cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance conformance_probe_emits_structured_receipt --locked -- --exact --nocapture

# Network-free M1-15 aggregate: the report binary executes and formats verified receipts.
conformance:
    report="${CONFORMANCE_REPORT:-target/m1-15-conformance.md}"; mkdir -p "$(dirname "$report")"; {{_io}} cargo +1.98.0 run -p workflow-testkit --bin m1-15-report --locked -- "$report"

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

pre-commit-fast: check-branch fmt-check lock-check check clippy dependency-audit pattern-catalog-test m2-02-green test-local-gates

_quality-gates: fmt-check check clippy dependency-audit pattern-catalog-test m2-02-green test test-local-gates

quality-gates:
    scripts/local-gates.sh produce

pre-push:
    scripts/local-gates.sh pre-push

# Install the repository's Lefthook-managed local gates after cloning.
install-hooks:
    lefthook install
