# Node-result cache

Production ADK execution (`FencedModel` / `build_profile_agent`) memoizes successful agent node outputs in a durable store at `<workdir>/.node-result-cache/` (reserved child of the run-root base, excluded from run-root cardinality). The store is fail-closed: hash or schema mismatch is a miss, never a silent hit.

## Identity

A cache key binds:

- workflow id and version
- node id and node version
- `InvocationProvenance` (protocol, tokenizer, model, tool schema, output schema, inference budget, provider route, trust-domain salt), including actual instruction bytes or their verified digest
- input artifact hashes of the executed node request (actual node input plus consumed upstream results)
- policy digest (allowed tools, instruction bytes/digest, schema, budget, route)

Run ids and timestamps are not part of the key.

## Replay

`node_completed` events carry `payload.cache_disposition`:

- `recorded` — first durable write after a real model call
- `reused` — valid durable hit; `FencedModel::generate_content` returns the cached response with zero inner model calls
- `reexecuted` — prior entry was invalid or negative; the node ran again

Resume of a succeeded run is a finish/no-op: it does not re-execute a completed cached node or issue another fake-model call. Inspect/GC/export/import operate on the same filesystem store. Fake/offline models only; live SuperQwen is not claimed.
