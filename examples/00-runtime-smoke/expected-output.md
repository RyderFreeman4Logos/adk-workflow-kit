# Expected output shape

The exact IDs, hashes, artifact IDs, and run root are generated at runtime and
must not be copied into documentation. A successful run has this bounded shape:

```text
run_id=<run-id> status=succeeded root=<run-root>
```

A successful `inspect` returns the same `<run-id>`, status, `<run-root>`, plan
hash, resume identity, and artifact `<artifact-id>` as the original receipt. A
completed `resume` keeps those identities and increments `resume_count`.

The committed `replay.json` validates independently and reports a nonzero
fixture/event count. Its result does not identify or depend on `<run-root>`.
