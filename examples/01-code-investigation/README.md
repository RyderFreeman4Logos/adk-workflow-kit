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

Keep credentials and machine-specific paths out of every checked-in fixture.
