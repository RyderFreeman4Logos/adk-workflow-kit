# Node-result cache

Production ADK execution (`FencedModel` / `build_profile_agent`) memoizes successful agent node outputs in a durable store at `<workdir>.node-result-cache/` (sibling of the run-root base, not a child of it). The store is fail-closed: hash or schema mismatch is a miss, never a silent hit.

## Identity

A cache key binds:

- workflow id and version
- node id and node version
- `InvocationProvenance` (protocol, tokenizer, model, tool schema, output schema, inference budget, provider route, trust-domain salt)
- input artifact hashes
- policy digest (allowed tools, instruction/schema paths)

Run ids and timestamps are not part of the key.

## Replay

`node_completed` events carry `payload.cache_disposition`:

- `recorded` — first durable write after a real model call
- `reused` — valid durable hit; `FencedModel` is skipped (zero fake-model calls)
- `reexecuted` — prior entry was invalid or negative; the node ran again

Resume of a succeeded run is a finish/no-op: it does not re-execute a completed cached node or issue another fake-model call. Inspect/GC/export/import operate on the same filesystem store. Fake/offline models only; live SuperQwen is not claimed.
