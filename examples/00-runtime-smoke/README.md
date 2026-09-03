# Runtime smoke example

This runtime smoke example is the smallest provider-free ADK execution path:
a deterministic `agent` entry node flows to one `terminal` node. The node binds
the checked-in fake worker model and `echo:1` tool explicitly; the profile has
one deterministic response/result and no sandbox capabilities. It is not a
model-directed multi-tool workflow or a live provider-conformance test.

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
EXAMPLE="$(pwd)/examples/00-runtime-smoke"
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
- provider-free, explicitly bound fake-profile execution with persisted receipt, checkpoint,
  events, effects, manifest, and bounded terminal artifact;
- fresh-process inspection and resume using the selected workdir; and
- offline validation of the committed redacted replay bundle.

The example intentionally does not claim model-directed multi-tool behavior,
Skill execution, code investigation, or live provider conformance. Keep
credentials and machine-specific paths out of every checked-in fixture.

## Reference package contract

A reference workflow package keeps these roles together:

- `workflow.toml` and `workflow.lock.toml`: the workflow and sealed plan;
- `input.example.json`: the bounded example input;
- `profiles/fake.json`: the provider-free scripted profile;
- `profiles/openai-compatible.template.json`: a credential-free live profile template;
- `traces/scripted.json`: the checked-in deterministic model/tool trace;
- `replay.json`: the redacted offline replay bundle; and
- `run.sh`: the one runner entry point.

Run `bash examples/00-runtime-smoke/run.sh --scripted` for the deterministic,
network-free path. Run `.../run.sh --replay` to validate only the recorded
bundle; it does not re-execute a model or tool. Live mode is an explicit opt-in:
`.../run.sh --live` requires `WORKFLOW_KIT_LIVE_BASE_URL` and
`WORKFLOW_KIT_LIVE_API_KEY`, rejects a non-HTTP(S) endpoint, and reports the
missing variable names without retaining credential values. Set
`WORKFLOW_KIT_LIVE_MODEL` only when the local OpenAI-compatible server needs a
model name other than `local-model`.
