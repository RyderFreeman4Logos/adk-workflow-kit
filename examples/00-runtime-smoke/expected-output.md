# Expected output shape

The exact IDs, hashes, artifact IDs, and run root are generated at runtime and
must not be copied into documentation. The authoritative README shell block
prints these outputs in this order:

1. `valid` from `validate`.
2. A non-empty Mermaid graph containing `agent` and `terminal`.
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
shown schematically. The replay receipt's `fixture_count` is the number of
validated committed replay events, not a count of dynamic ADK run files.
