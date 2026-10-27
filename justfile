set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

_io := "ionice -c 3"

default: pre-commit-fast

fmt:
    {{_io}} cargo fmt --all

fmt-check:
    {{_io}} cargo fmt --all -- --check

check:
    {{_io}} cargo +1.98.0 check --workspace --all-targets --locked

# Compile the release CLI consumer with debug assertions disabled.
issue-323-release-consumer:
    {{_io}} cargo +1.98.0 build -p workflowctl --release --locked

clippy:
    {{_io}} cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings

test: issue-233-worker-binaries
    {{_io}} cargo +1.98.0 build -p workflowctl --locked
    ADK_WORKER_INHERITED_CANARY=issue-233-fixed-test-only {{_io}} cargo +1.98.0 test --workspace --exclude workflow-adk --locked -- --test-threads=2
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

# Focused skill frontmatter compatibility during the YAML parser migration.
issue-332-compiler test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test skill_contracts {{test_name}} --locked -- --nocapture

# Preserve specification, canonical IR, and compiler contracts across the private facade split.
issue-376-contracts:
    {{_io}} cargo +1.98.0 test -p workflow-spec -p workflow-ir -p workflow-compiler --locked -- --test-threads=2

m3-00-cli test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m3_00_runtime_smoke --locked {{quote(test_name)}} -- --exact --nocapture --test-threads=1

# Focused M3-02 per-node binding tests.
m3-02-spec test_name:
    {{_io}} cargo +1.98.0 test -p workflow-spec --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

m3-02-compiler test_name:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

m3-02-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_02_node_bindings {{test_name}} --locked -- --exact --nocapture

# Focused #240 durable effect ledger and ToolBridge recovery tests.
issue-240-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_240_effect_ledger {{test_name}} --locked -- --nocapture

issue-240-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_240_durable_effect {{test_name}} --locked -- --nocapture

# Focused #251 deterministic IssueCard foundation tests.
issue-251-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_251_card_score {{test_name}} --locked -- --nocapture

# Focused #252 explicit dependency-plan tests.
issue-252-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_252_dependency_plan {{test_name}} --locked -- --nocapture

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

# Private retained-evidence generation contracts, without a model provider.
m3-07-evidence:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --lib live_conformance::evidence::tests --locked -- --nocapture

# Disposable subprocess ownership regressions, without a model provider.
issue-337-owner test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_337_live_owner {{test_name}} --locked -- --nocapture

# Private fault-path ownership contracts, without providers.
issue-337-faults:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --lib live_conformance::child::tests --locked -- --nocapture

# Sealed-profile unit contract, without providers.
issue-337-profile:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --lib live_conformance::profile::tests --locked -- --nocapture

# Opt in without inspecting credentials; SKIP unless explicitly requested.
m3-07-live profile="":
    if test "${WORKFLOW_KIT_M3_07_LIVE:-0}" != 1; then echo "M3-07 live conformance: SKIP (set WORKFLOW_KIT_M3_07_LIVE=1 to opt in)"; exit 0; fi; if test -z {{quote(profile)}}; then echo "M3-07 live conformance: FAIL (missing profile)"; exit 2; fi; {{_io}} cargo +1.98.0 build -p workflowctl --locked; {{_io}} cargo +1.98.0 run -p workflow-testkit --bin m3-07-live --locked -- ./target/debug/workflowctl {{quote(profile)}}

# Focused #267 deterministic validator, approval, and write tests.
issue-267-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_267_deterministic_nodes --locked -- --nocapture

# Focused #268 offline fake-profile provider/model compatibility matrix.
issue-268-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_268_compatibility_matrix --locked -- --nocapture

# Focused #227 durable node-result cache tests.
issue-227-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_227_node_cache {{test_name}} --locked -- --nocapture

issue-227-wait test_name:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib {{test_name}} --locked -- --exact --nocapture

issue-227-sandbox test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test sandbox_execution_contracts {{test_name}} --locked -- --nocapture

issue-227-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_227_node_cache {{test_name}} --locked -- --nocapture --test-threads=1

issue-227-test:
    just issue-227-runtime
    just issue-227-adk

# Focused #289 provider-error envelopes through the public invocation boundary.
issue-289-adk:
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib model_invocation::tests:: --locked -- --nocapture

# Default-feature package coverage must remain separate from workspace feature unification.
adk-default-test:
    {{_io}} cargo +1.98.0 test -p workflow-adk --locked -- --test-threads=1

adk-model-profiles test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test model_profiles {{test_name}} --locked

runtime-hot-reload:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib hot_reload::tests:: --locked

# Focused #311 offline ordered model-route snapshot and fallback boundary.
issue-311-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_311_model_routes {{test_name}} --locked -- --nocapture --test-threads=1

# Caller-owned ADK conversations through the production invocation/route boundaries.
issue-325-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_325_model_sessions {{test_name}} --locked -- --nocapture --test-threads=1

# Focused #314 ToolCall Debug privacy regression.
issue-314-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_314_tool_call_debug {{test_name}} --locked -- --exact --nocapture

# Focused #228 compact typed-output protocol tests.
issue-228-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_228_typed_outputs {{test_name}} --locked -- --nocapture

issue-228-test:
    just issue-228-runtime

# Focused #243 deterministic source-addressed relation contract.
issue-243-ir test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-ir --test issue_243_relation_contract {{test_name}} --locked -- --nocapture

# Focused #243 renderer work-bound regression.
issue-243-ir-renderer:
    {{_io}} cargo +1.98.0 test -p workflow-ir --lib compact_state::tests::render_does_not_rebuild_relations_for_sparse_history --locked -- --exact --nocapture

# Focused #243 continuation categories and trusted renderer tests.
issue-243-ir-continuation test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-ir --test issue_243_continuation_categories {{test_name}} --locked -- --nocapture

# Focused #243 authored compact-state exchange -> typed compiler IR tests.
issue-243-compiler test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test issue_243_compact_state_ir {{test_name}} --locked -- --nocapture

# Focused #243 compiled-IR-driven runtime artifact exchange integration test.
issue-243-compiler-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test issue_243_compact_state_runtime {{test_name}} --locked -- --nocapture

# Focused #243 runtime artifact-backed compact-state exchange tests.
issue-243-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_243_compact_state {{test_name}} --locked -- --nocapture

# Focused #231 canonical untrusted-data preparation tests.
issue-231-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_231_sentinel_envelope {{test_name}} --locked -- --nocapture

# Pinned language asset rejection and bounded production preparation resources.
issue-231-language-unit:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib sentinel_language --locked -- --nocapture --test-threads=1

# Focused #231 versioned compiler and production execution integration.
issue-231-compiler:
    {{_io}} cargo +1.98.0 test -p workflow-compiler --test issue_231_workflow --locked -- --nocapture

issue-231-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_231_workflow {{test_name}} --locked -- --nocapture --test-threads=1

# Focused #232 executed semantic probes (offline fake model only).
issue-232-semantics test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_232_semantics --test issue_226_prompt_protocol {{test_name}} --locked -- --nocapture --test-threads=1

issue-232-clippy:
    {{_io}} cargo +1.98.0 clippy -p workflow-adk --features test-support --all-targets --locked -- -D warnings

# Focused #232 source-only probe evidence through public ADK execution.
issue-232-adk:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_232_probes --locked -- --nocapture --test-threads=1
# Focused #233 inert scripted behavioral simulation (no live model or IO).
issue-233-runtime:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_233_behavioral --locked -- --nocapture

issue-233-adk:
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_233_behavioral --test issue_233_translation --locked -- --nocapture --test-threads=1

# Public host route, real compatible SDK wire, and sealed inert worker boundary.
issue-233-model-worker test_name="": issue-233-worker-binaries
    test ! -L target/debug/sentinel-probe-worker.sha256 && { test ! -e target/debug/sentinel-probe-worker.sha256 || test -f target/debug/sentinel-probe-worker.sha256; }
    sha256sum target/debug/sentinel-probe-worker > target/debug/sentinel-probe-worker.sha256
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_233_model_worker {{test_name}} --locked -- --nocapture --test-threads=1

issue-233-doc:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --doc behavioral --locked

# Snapshot the fixed OS-negative fixture before later Cargo graphs can rebuild its canonical binary.
issue-233-worker-binaries:
    {{_io}} cargo +1.98.0 build -p workflow-runtime --bin sentinel-probe-worker -p workflow-testkit --bin issue-233-boundary-child --locked
    test ! -L target/debug/sentinel-probe-worker.fixture && { test ! -e target/debug/sentinel-probe-worker.fixture || test -f target/debug/sentinel-probe-worker.fixture; } && test ! -L target/debug/sentinel-probe-worker.fixture.sha256 && { test ! -e target/debug/sentinel-probe-worker.fixture.sha256 || test -f target/debug/sentinel-probe-worker.fixture.sha256; }
    cp --no-dereference --no-target-directory --remove-destination -- target/debug/sentinel-probe-worker target/debug/sentinel-probe-worker.fixture
    sha256sum target/debug/sentinel-probe-worker.fixture > target/debug/sentinel-probe-worker.fixture.sha256
    test ! -L target/debug/issue-233-boundary-child.fixture && { test ! -e target/debug/issue-233-boundary-child.fixture || test -f target/debug/issue-233-boundary-child.fixture; } && test ! -L target/debug/issue-233-boundary-child.fixture.sha256 && { test ! -e target/debug/issue-233-boundary-child.fixture.sha256 || test -f target/debug/issue-233-boundary-child.fixture.sha256; }
    cp --no-dereference --no-target-directory --remove-destination -- target/debug/issue-233-boundary-child target/debug/issue-233-boundary-child.fixture
    sha256sum target/debug/issue-233-boundary-child.fixture > target/debug/issue-233-boundary-child.fixture.sha256

issue-233-worker test_name="": issue-233-worker-binaries
    ADK_WORKER_INHERITED_CANARY=issue-233-fixed-test-only {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_233_worker {{test_name}} --locked -- --nocapture --test-threads=1

# Existing authored shell/sandbox contracts must retain their own runtime view.
issue-233-worker-sandbox:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib bubblewrap::supervision::tests --locked -- --nocapture --test-threads=1
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test bubblewrap_backend_contracts --test bubblewrap_conformance --locked -- --nocapture --test-threads=1

# Bounded child/pipe settlement and FIFO failure-path ownership regressions.
issue-380-runtime test_name="bubblewrap::lifecycle::tests":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib {{test_name}} --locked -- --nocapture --test-threads=1

issue-378-fifo test_name="":
    {{_io}} cargo +1.98.0 test -p workflowctl --test cli003_run_explain_run {{test_name}} --locked -- --nocapture --test-threads=1

# Focused #234 default-off canonical trajectory observer (offline fixtures only).
issue-234-runtime:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_234_trajectory --locked -- --nocapture

issue-234-authored:
    {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_233_translation trajectory_authored:: --locked -- --nocapture --test-threads=1

# Process-local capture access/owner controls; the regular test gate also runs them.
issue-234-capture-unit: issue-233-worker-binaries
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib behavioral:: --locked -- --nocapture --test-threads=1

issue-234-capture-doc:
    {{_io}} cargo +1.98.0 test -p workflow-adk --doc reasoning_capture --locked -- --nocapture

# Deny before dependencies/build/private inputs. Admission is separately reviewed.
issue-234-live:
    @test "${ADK_ISSUE234_LIVE:-}" = YES && [[ "${ADK_ISSUE234_ADMISSION:-}" = /* ]] && [[ "${ADK_ISSUE234_ADMISSION_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || { echo 'DENIED: explicit live opt-in and external admission required' >&2; exit 2; }
    just issue-233-worker-binaries
    timeout --signal=TERM --kill-after=5s 175s {{_io}} cargo +1.98.0 test -p workflow-adk --features test-support --test issue_233_model_worker --locked -- capture::live::admitted_real_pair --ignored --exact --nocapture --test-threads=1

# Focused #238 deterministic Firewall policy and workflow boundary tests.
issue-238-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_238_firewall {{test_name}} --locked -- --nocapture

issue-238-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_238_firewall {{test_name}} --locked -- --nocapture --test-threads=1

issue-238-concurrent:
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib firewall::tests:: --locked -- --nocapture

# Focused #239 semantic Firewall contracts and production integration.
issue-239-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_239_semantic {{test_name}} --locked -- --nocapture

issue-239-adk test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_239_semantic {{test_name}} --locked -- --nocapture --test-threads=1

issue-239-invocation-regression:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test issue_226_prompt_protocol --locked -- --nocapture

issue-239-isolation:
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib semantic_firewall::tests:: --locked -- --nocapture

# Focused #230 benchmark harness tests.
issue-230-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_benchmark_harness {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-modes test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_modes {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-comparison test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_comparison {{test_name}} --locked -- --nocapture --test-threads=2
    {{_io}} cargo +1.98.0 test -p workflow-testkit --lib execution230::policy::comparison::tests:: --locked -- --nocapture --test-threads=2

issue-230-cache test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_cache {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-telemetry test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_telemetry {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-telemetry-adk:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test model_profiles --locked -- --nocapture --test-threads=1
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib events:: --locked -- --nocapture --test-threads=1
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib model_profiles::retry_admission_tests:: --locked -- --nocapture --test-threads=1

issue-230-test:
    just issue-230-telemetry
    just issue-230-cache
    just issue-230-comparison
    just issue-230-modes
    just issue-230-runtime
    just issue-230-execution
    just issue-230-resume
    just issue-230-execution-unit
    just issue-230-telemetry-adk

issue-230-execution test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_execution {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-resume test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_230_resume {{test_name}} --locked -- --nocapture --test-threads=2

issue-230-execution-unit test_name="execution230::":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --lib {{test_name}} --locked -- --nocapture --test-threads=2

# One-command scripted smoke for every registered workflow. No live model.
issue-230-smoke:
    {{_io}} cargo +1.98.0 run -p workflow-testkit --bin bench-230 --locked -- scripted

# Synthetic values for deterministic golden reports, not measured execution.
issue-230-fixture:
    {{_io}} cargo +1.98.0 run -p workflow-testkit --bin bench-230 --locked -- fixture

# Four-source Sentinel adapters; public API controls plus private native parsers.
issue-236-runtime:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_236_dataset_adapters --locked -- --nocapture
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib dataset::dataset_sentinel::tests:: --locked -- --nocapture

# Explicit local raw-source acceptance; never fetches or runs a model.
issue-236-offline source_dir cache_dir:
    ADK_DATASET_SOURCE_DIR={{quote(source_dir)}} ADK_DATASET_CACHE_DIR={{quote(cache_dir)}} {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_236_dataset_adapters actual_sources_and_two_cache_only_reruns --locked -- --exact --ignored --nocapture

# Focused #229 pinned dataset registry tests.
issue-229-http test_name="dataset::dataset_http::":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib {{test_name}} --locked -- --nocapture

issue-229-parquet test_name="dataset::dataset_parquet::tests::":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib {{test_name}} --locked -- --nocapture

issue-229-live:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib dataset::dataset_http::tests::futurehouse_pinned_product_source_to_cases --locked -- --exact --ignored --nocapture

issue-229-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_229_dataset_registry {{test_name}} --locked -- --nocapture

# Focused #249 metadata-first GitHub intake tests.
issue-249-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_249_metadata_intake {{test_name}} --locked -- --nocapture

issue-249-graphql test_name="github_graphql::tests::":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --lib {{test_name}} --locked -- --nocapture

# Focused #250 offline canonical admitted-issue artifact tests.
issue-250-runtime test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test issue_250_issue_artifact {{test_name}} --locked -- --nocapture

issue-229-test:
    just issue-229-runtime

issue-229-product-test test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_229_product {{test_name}} --locked -- --nocapture

# Opt-in real shipping CLI test with a public pinned, verified linked cache.
issue-229-cli-links:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test issue_229_product shipped_cli_supports_verified_root_link --locked -- --exact --ignored --nocapture

# Public, pinned FutureHouse product path (report is CACHE_DIR/ether0-report.json).
issue-229-product cache license mode cases:
    {{_io}} cargo +1.98.0 run -p workflow-testkit --bin ether0-eval --locked -- {{quote(cache)}} {{quote(license)}} {{quote(mode)}} {{quote(cases)}}

# Focused #224 reference-workflow package and runner contract tests.
m3-08-reference:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m3_08_reference_workflow --locked -- --nocapture

m3-04-unit test_name:
    {{_io}} cargo +1.98.0 test -p workflow-adk {{test_name}} --lib --locked -- --exact --nocapture

# Authored Shared history plus adjacent isolated, cancellation and durable replay contracts.
issue-361:
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib session_policy_tests --locked -- --nocapture
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib execution::shared --locked -- --nocapture
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib execution::isolated --locked -- --nocapture
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_04_model_tool_loop --locked -- --nocapture

# Real-owner deadline/cancellation classification and the unchanged replay contracts.
issue-306:
    {{_io}} cargo +1.98.0 test -p workflow-adk --lib execution::effect_fence_tests --locked -- --nocapture --test-threads=1
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m3_04_model_tool_loop --locked -- --nocapture --test-threads=1

m3-04-cli test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m1_12_destructive_resume {{test_name}} --locked -- --exact --nocapture

m1-10-adk test_name:
    {{_io}} cargo +1.98.0 test -p workflowctl --test m1_10_adk_run {{test_name}} --locked -- --exact --nocapture --test-threads=2

m1-12-effect-journal:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test m1_12_effect_journal --locked

# Focused M1-15 conformance contract tests.
m1-15-test:
    {{_io}} cargo +1.98.0 test -p workflow-testkit --test m1_15_conformance --locked

# Focused M1-15 production-boundary translation tests.
m1-15-translation test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test translation {{test_name}} --locked

# Focused #223 compatibility probe against the current released ADK-Rust pin.
adk-2-1-probe:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test adk_2_1_compat --locked -- --nocapture

# Focused M1-15 production ToolBridge terminal-outcome tests.
m1-15-adk-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-adk --test tool_bridge --locked

# Focused M1-15 ToolBridge authorization tests.
m1-15-tool-bridge:
    {{_io}} cargo +1.98.0 test -p workflow-runtime --test m1_07_tool_bridge --locked

# Focused M1-15 checkpoint terminal-mapping tests.
m1-15-checkpoint test_name="":
    {{_io}} cargo +1.98.0 test -p workflow-adk --test m1_11_execution_checkpoints {{test_name}} --locked

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

# Verify the standalone exact-Git downstream consumer for #269.
issue-269-acceptance:
    python3 scripts/test_issue_269_downstream.py

issue-269-bootstrap-test:
    python3 scripts/test_issue_269_paths.py
    python3 scripts/test_issue_269_bootstrap.py

issue-269-semantics-test:
    python3 scripts/test_issue_269_semantics.py

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

# Refresh only workspace-driven dependency changes, retaining unrelated locked versions.
lock-refresh:
    {{_io}} cargo +1.98.0 update --workspace

# Update one locked dependency to an explicit version without refreshing the workspace.
lock-update $package $version:
    {{_io}} cargo +1.98.0 update --package "$package" --precise "$version"

# Verify Cargo.lock already matches the workspace manifests without rewriting it.
lock-check:
    {{_io}} cargo metadata --format-version 1 --locked > /dev/null

metadata:
    {{_io}} cargo metadata --format-version 1 --locked

# Resolve and compile the optional ADK action graph without changing default features.
adk-action-check:
    {{_io}} cargo +1.98.0 --version --verbose
    {{_io}} cargo +1.98.0 metadata --format-version 1 --features adk-rust/action --locked
    {{_io}} cargo +1.98.0 check -p workflow-adk --features adk-rust/action --locked
    {{_io}} cargo +1.98.0 test -p workflow-adk --test adk_action_identity --features adk-rust/action --locked

dependency-audit:
    {{_io}} cargo deny check licenses advisories

test-local-gates:
    bash scripts/test-local-gates-git-env.sh

test-releasing:
    bash scripts/test-releasing.sh

release-local:
    bash scripts/local-release.sh

test-release-local:
    bash scripts/test-local-release.sh

check-branch:
    scripts/local-gates.sh check-branch

pre-commit-fast: check-branch fmt-check lock-check check clippy dependency-audit pattern-catalog-test m2-02-green test-local-gates

_quality-gates: fmt-check issue-323-release-consumer check clippy dependency-audit pattern-catalog-test m2-02-green issue-269-bootstrap-test issue-269-acceptance issue-269-semantics-test test issue-233-adk issue-311-adk issue-325-adk adk-action-check test-local-gates issue-233-model-worker (issue-229-http "dataset::dataset_sentinel::tests::canonical_order_ --features serde_json/preserve_order --offline")

quality-gates:
    scripts/local-gates.sh produce

pre-push:
    scripts/local-gates.sh pre-push

# Install the repository's Lefthook-managed local gates after cloning.
install-hooks:
    lefthook install
