# Expected output shape

The exact IDs, hashes, artifact IDs, and run root are generated at runtime and
must not be copied into documentation. The authoritative README shell block
prints these outputs in this order:

1. `valid` from `validate`.
2. A non-empty Mermaid graph containing `planner`, `search_code`, `review`,
   `publish`, and `abstain`.
3. The deterministic TOML lock for `workflow.toml`.
4. Exactly one JSON `run` receipt with `run_id`, `workflow_id`, `status`,
   `artifact_id`, `run_root`, `resume_count: 0`, `plan_hash`, and
   `resume_identity`.
5. A JSON `inspect` receipt with the same run fields and values as `run`.
6. A JSON `resume` receipt with the same `run_id`, `workflow_id`, `artifact_id`,
   `run_root`, `plan_hash`, and `resume_identity`, with `status: "succeeded"`
   and `resume_count: 1`.
7. A separate JSON `replay` receipt with `disposition: "replay_run"`, a
   nonzero `fixture_count`, and `payload_len`; it has no `run_id` and does not
   identify or depend on the dynamic `run_root`.

The generated values are intentionally represented here as `<run-id>`,
`<run-root>`, `<plan-hash>`, `<resume-identity>`, and `<artifact-id>` when
shown schematically.

The agent state contains a structured answer at `node:draft`, or at `node:revise`
after a revision. Its `snapshot_id` matches the host facts in the example input;
claims reference `src/retry.rs` with exact line ranges, source text, and whole-file
digests. The fake profile selects the insufficient-coverage retry branch before
publishing. Revision fixtures preserve the same answer shape. Agent verdicts
remain advisory; terminal routing alone is not semantic citation validation.

The opt-in conformance report separately awards `PASS` only after validating that
actual selected checkpoint answer against host Snapshot facts and successful
read-tool evidence. Wrong input facts fail before child admission; invalid final
citations fail even if the graph's run receipt says `succeeded`. A revision replaces
the draft for this quality decision. `ABSTAIN` and `SKIP` are separate outcomes.
