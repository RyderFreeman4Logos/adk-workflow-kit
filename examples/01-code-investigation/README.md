# Code investigation example

This canonical example is the self-contained, provider-free code-investigation
package. One declarative workflow binds the checked-in Skill, prompts, schemas,
read-only tools, and fake profile. Domain validators and read-only code tools
remain registered Rust implementations. It is not a live provider-conformance
test.

## Run it

Start the commands at the repository root and run the single authoritative
block below with Bash. It requires Bash, Python 3, and an installed or built
`workflowctl` executable on `PATH`. The block establishes the example
directory, uses one caller-overridable temporary workdir, and performs
`validate → graph --format mermaid → lock → run --profile → inspect → resume
→ replay` in that order. When `WORKDIR` is not provided, the block creates and
removes a temporary directory; a caller-provided `WORKDIR` is created if
needed and is not removed.

```bash
set -eu
if [ -z "${BASH_VERSION:-}" ]; then
    printf '%s\n' 'prerequisite missing: Bash' >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'prerequisite missing: python3' >&2
    exit 1
fi
if ! command -v workflowctl >/dev/null 2>&1; then
    printf '%s\n' 'prerequisite missing: workflowctl' >&2
    exit 1
fi
EXAMPLE="$(pwd)/examples/01-code-investigation"
test -d "$EXAMPLE"
cd "$EXAMPLE"

if [ -n "${WORKDIR:-}" ]; then
    mkdir -p "$WORKDIR"
    CLEANUP_WORKDIR=0
else
    WORKDIR="$(mktemp -d)"
    CLEANUP_WORKDIR=1
fi
cleanup_workdir() {
    if [ "$CLEANUP_WORKDIR" -eq 1 ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup_workdir EXIT

INPUT="$(<input.example.json)"
workflowctl validate workflow.toml
workflowctl graph workflow.toml --format mermaid
workflowctl lock workflow.toml
RUN_JSON="$(workflowctl --json run workflow.toml --profile profiles/fake.json --input "$INPUT" --workdir "$WORKDIR")"
printf '%s\n' "$RUN_JSON"
RUN_ID="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["run_id"])' <<<"$RUN_JSON")"
test -n "$RUN_ID"
workflowctl --json inspect --run-id "$RUN_ID" --workdir "$WORKDIR"
workflowctl --json resume --run-id "$RUN_ID" --workdir "$WORKDIR"
workflowctl --json replay replay.json
```

The block uses Python 3 only to parse the captured JSON run receipt; it does
not rerun `run`. The JSON `run` receipt, `inspect`, and `resume` outputs share
one `run_id`; `resume` reuses the plan and resume identities and increments
`resume_count`. The JSON `replay` output is a separate committed-bundle
receipt with a nonzero fixture/event count and no dynamic run ID.

The `validate`, graph, and lock commands read the committed workflow. The
profile-backed `run` is provider-free and performs no network access. `inspect`
and `resume` exercise the dynamic run directory selected by `WORKDIR`.

`replay` is deliberately separate: it validates the independent committed
redacted replay bundle and does not read, mutate, or replay the dynamic ADK run
root. The bundle contains only bounded structural events and digested fixture
bytes, so its validation also performs no network access.

## What this proves

- deterministic workflow validation, Mermaid graphing, and lock generation;
- provider-free fake-profile execution covering planner, investigation, search,
  read, evidence, review, revision, publish, and valid abstention;
- fresh-process inspection and resume using the selected workdir; and
- offline validation of the committed redacted replay bundle.

## Model-facing contracts and evidence

All twelve agent nodes bind an instruction, an explicit input-state whitelist,
an output schema and state key, and isolated model history. Tool turns within
one node invocation retain their own conversation; a later graph visit receives
its current whitelisted state rather than the earlier visit's transcript.
Review receives the selected draft/revision and source evidence, without the
planner's private transcript. Shared-session policy is separate from this example.

Coverage emits the JSON string `"sufficient"`, `"insufficient"`, or `"impossible"`.
Grounding and review use their own finite string enums. Search and inspection
publish structured source evidence; draft and revision publish an
`InvestigationAnswer`, not a placeholder string. These contracts are supplied to
the provider and checked locally before downstream routing.

`input.example.json` carries the canonical question and `src` path plus the
checked-in repository's Snapshot ID and whole-file digests. The opt-in
conformance runner checks the question and path and recomputes the source facts
from `repo/` before starting the child; a mismatch fails with `invalid_snapshot`
and no provider call.
After publication it reads the actual selected `node:revise` or `node:draft` from
the retained checkpoint and applies `validate_answer`: Snapshot identity, claim
binding, contained path, whole-file digest, inclusive range and exact source text.
Every citation must also fall within a real successful `read_source_range` result
in the integrity-checked event log, including protected artifact-backed results.
The canonical question additionally requires a cited `default_retry` finding in
`src/retry.rs`; this finite expected-finding check does not evaluate arbitrary prose.
Source changes require updating the Snapshot facts and evidence together. A
model's `"valid"` verdict or reaching `publish` alone cannot earn conformance `PASS`.
Invalid retained evidence is `FAIL` with `invalid_evidence`; valid abstention stays
`ABSTAIN`, and the default, non-opted-in runner stays `SKIP` without I/O. Ordinary
`workflowctl run` remains a graph execution receipt, not this semantic quality gate.

## Deterministic node contract

`workflow-deterministic.toml` is the model-free companion fixture for the
canonical package. `just issue-267-test` compiles it with the exact Rust
validator `code.investigation.evidence@v1` at `1.0.0`, gates approval and the
idempotent `write_effect` before `publish`, and exercises approval, timeout,
SIGKILL resume, duplicate-commit, and manual-recovery paths.

Keep credentials and machine-specific paths out of every checked-in fixture.

## Opt-in live OpenAI-compatible conformance

Copy `profiles/openai-compatible.template.json`, replace `USER_SUPPLIED_MODEL`
and `http://example.invalid/v1` with a local profile, and export the credential
handle named in `credential_env`. Then from the repository root:

```bash
WORKFLOW_KIT_M3_07_LIVE=1 just m3-07-live path/to/profile.json
```

Without that opt-in the recipe prints `SKIP` and does not start a provider
session. Ordinary `just test` never requires the network.
