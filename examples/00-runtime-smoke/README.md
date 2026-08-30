# Runtime smoke example

This runtime smoke example is the smallest provider-free ADK execution path:
a deterministic `agent` entry node flows to one `terminal` node. The checked-in
fake profile has one deterministic response, an `echo` tool/result, and no
sandbox capabilities. It is not a model-directed multi-tool workflow, a
per-node configuration example, or a live provider-conformance test.

## Run it

The command sequence is `validate → graph --format mermaid → lock → run --profile → inspect → resume → replay`.

Choose one temporary workdir and keep it outside the repository. The commands
below use the same caller-selected workdir for the dynamic run, inspection, and
resume; replace `<WORKDIR>` with that directory and `<RUN_ID>` with the ID
printed by `run`.

```sh
WORKDIR=<caller-selected-workdir>
mkdir -p "$WORKDIR"
INPUT=$(python3 -c 'import pathlib; print(pathlib.Path("input.example.json").read_text().strip())')

workflowctl validate workflow.toml
workflowctl graph workflow.toml --format mermaid
workflowctl lock workflow.toml
workflowctl run workflow.toml --profile profiles/fake.json --input "$INPUT" --workdir "$WORKDIR"
workflowctl inspect --run-id <RUN_ID> --workdir "$WORKDIR"
workflowctl resume --run-id <RUN_ID> --workdir "$WORKDIR"
workflowctl replay replay.json
```

The `validate`, graph, and lock commands read the committed workflow. The
profile-backed `run` is provider-free and performs no network access. `inspect`
and `resume` exercise the dynamic run directory selected by `<WORKDIR>`;
`resume` reuses the original run ID and checkpoint identity.

`replay` is deliberately separate: it validates the independent committed
redacted replay bundle and does not read, mutate, or replay the dynamic ADK run
root. The bundle contains only bounded structural events and digested fixture
bytes, so its validation also performs no network access.

## What this proves

- deterministic workflow validation, Mermaid graphing, and lock generation;
- provider-free fake-profile execution with persisted receipt, checkpoint,
  events, effects, manifest, and bounded terminal artifact;
- fresh-process inspection and resume using the selected workdir; and
- offline validation of the committed redacted replay bundle.

The example intentionally does not claim model-directed multi-tool behavior,
per-node agent configuration, Skill execution, code investigation, or live
provider conformance. Keep credentials and machine-specific paths out of every
checked-in fixture.
