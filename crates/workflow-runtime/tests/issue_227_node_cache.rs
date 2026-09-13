use std::{
    fs,
    sync::{Arc, Barrier},
    thread,
};

use serde_json::{Value, json};
use workflow_runtime::{
    CacheDisposition, CacheProvenance, NODE_CACHE_SCHEMA_VERSION, NodeCacheEntry,
    NodeCacheInvalidationReason, NodeCacheKey, NodeCacheKeyMaterial, NodeCacheLookup,
    NodeCacheOutcome, NodeCacheRetention, NodeResultCache, node_cache_dir_syncs,
    reset_node_cache_dir_syncs,
};

fn bind_case(
    workflow_version: &str,
    node_version: &str,
    invocation_identity: &str,
    input_hashes: &[&str],
    policy_digest: &str,
) -> NodeCacheKey {
    let hashes = input_hashes
        .iter()
        .map(|hash| (*hash).to_owned())
        .collect::<Vec<_>>();
    NodeCacheKey::bind(NodeCacheKeyMaterial {
        workflow_id: "wf-cache",
        workflow_version,
        node_id: "work",
        node_version,
        invocation_identity,
        input_artifact_hashes: &hashes,
        policy_digest,
    })
    .expect("valid cache key")
}

fn base_key() -> NodeCacheKey {
    bind_case(
        "1",
        "work:1",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )
}

fn provenance(key: &NodeCacheKey) -> CacheProvenance {
    CacheProvenance::from_key(key)
}

fn cache_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "issue-227-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("cache root");
    root
}

#[test]
fn node_cache_schema_is_versioned() {
    assert_eq!(NODE_CACHE_SCHEMA_VERSION, 1);
}

#[test]
fn key_mutation_matrix_covers_every_identity_field() {
    let baseline = base_key();
    let mutations = [
        bind_case(
            "2",
            "work:1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        bind_case(
            "1",
            "work:2",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        bind_case(
            "1",
            "work:1",
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        bind_case(
            "1",
            "work:1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        bind_case(
            "1",
            "work:1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];
    for mutated in mutations {
        assert_ne!(
            baseline.digest(),
            mutated.digest(),
            "security-relevant identity change must invalidate the cache key"
        );
    }
    let with_run_metadata = NodeCacheKey::bind(NodeCacheKeyMaterial {
        workflow_id: "wf-cache",
        workflow_version: "1",
        node_id: "work",
        node_version: "work:1",
        invocation_identity:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        input_artifact_hashes: &[
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        ],
        policy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    })
    .expect("valid cache key");
    assert_eq!(
        baseline.digest(),
        with_run_metadata.digest(),
        "run IDs and timestamps must not be part of the key material"
    );
}

#[test]
fn durable_put_then_get_returns_complete_entry() {
    let root = cache_root("put-get");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    let payload = json!({"answer": "cached"});
    cache
        .put(NodeCacheEntry::success(key.clone(), payload.clone(), provenance(&key)).unwrap())
        .expect("put");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Hit(entry) => {
            assert_eq!(entry.schema_version(), NODE_CACHE_SCHEMA_VERSION);
            assert_eq!(entry.payload(), &payload);
            assert_eq!(entry.outcome(), &NodeCacheOutcome::Success);
            assert_eq!(
                entry.provenance().invocation_identity(),
                key.invocation_identity()
            );
        }
        other => panic!("expected hit, got {other:?}"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn concurrent_writers_never_publish_a_partial_entry() {
    let root = cache_root("concurrent");
    let cache = Arc::new(NodeResultCache::open(&root).expect("open cache"));
    let key = base_key();
    let payload = json!({"answer": "shared"});
    let entry =
        NodeCacheEntry::success(key.clone(), payload.clone(), provenance(&key)).expect("entry");
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let entry = entry.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                cache.put(entry)
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().expect("thread").expect("put");
    }
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Hit(entry) => assert_eq!(entry.payload(), &payload),
        other => panic!("expected complete hit, got {other:?}"),
    }
    let inspect = cache.inspect().expect("inspect is read-only");
    assert_eq!(inspect.entry_count(), 1);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_during_write_does_not_return_partial_data() {
    let root = cache_root("crash");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    fs::write(
        root.join(format!(".tmp-{}-1", key.digest().replace(':', "-"))),
        b"{",
    )
    .expect("leftover temp");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Hit(_) => panic!("partial crash debris must not be a hit"),
        NodeCacheLookup::Miss | NodeCacheLookup::Invalid { .. } => {}
    }
    cache
        .put(
            NodeCacheEntry::success(
                key.clone(),
                json!({"answer": "after-crash"}),
                provenance(&key),
            )
            .unwrap(),
        )
        .expect("stale numeric tmp suffix must not block a later process");
    match cache.lookup(&key).expect("lookup after put") {
        NodeCacheLookup::Hit(entry) => {
            assert_eq!(entry.payload(), &json!({"answer": "after-crash"}))
        }
        other => panic!("expected hit after reclaiming crash debris, got {other:?}"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn put_replaces_divergent_existing_entry() {
    let root = cache_root("replace");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    cache
        .put(
            NodeCacheEntry::success(key.clone(), json!({"answer": "old"}), provenance(&key))
                .unwrap(),
        )
        .expect("seed");
    cache
        .put(
            NodeCacheEntry::success(key.clone(), json!({"answer": "new"}), provenance(&key))
                .unwrap(),
        )
        .expect("replace divergent bytes");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Hit(entry) => assert_eq!(entry.payload(), &json!({"answer": "new"})),
        other => panic!("expected replaced hit, got {other:?}"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_payload_hash_and_schema_fail_closed() {
    let root = cache_root("corrupt");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    cache
        .put(
            NodeCacheEntry::success(key.clone(), json!({"answer": "ok"}), provenance(&key))
                .unwrap(),
        )
        .expect("put");
    let path = cache
        .inspect()
        .expect("inspect")
        .entry_path(&key)
        .expect("path");
    let mut raw = serde_json::from_slice::<Value>(&fs::read(&path).expect("read")).expect("json");
    raw["payload"] = json!({"answer": "tampered"});
    fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("tamper payload");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::HashMismatch,
        } => {}
        other => panic!("tampered payload must fail closed, got {other:?}"),
    }

    raw["schema_version"] = json!(99);
    raw["payload"] = json!({"answer": "ok"});
    fs::write(&path, serde_json::to_vec(&raw).expect("encode")).expect("tamper schema");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::SchemaMismatch,
        } => {}
        other => panic!("schema mismatch must fail closed, got {other:?}"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn negative_result_is_cached_with_explicit_reason() {
    let root = cache_root("negative");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    cache
        .put(
            NodeCacheEntry::negative(
                key.clone(),
                NodeCacheInvalidationReason::InvalidOutput,
                provenance(&key),
            )
            .unwrap(),
        )
        .expect("put negative");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Hit(entry) => {
            assert_eq!(
                entry.outcome(),
                &NodeCacheOutcome::Negative {
                    reason: NodeCacheInvalidationReason::InvalidOutput
                }
            );
        }
        other => panic!("expected negative hit, got {other:?}"),
    }
    cache
        .invalidate(&key, NodeCacheInvalidationReason::ExplicitInvalidate)
        .expect("invalidate");
    match cache.lookup(&key).expect("lookup") {
        NodeCacheLookup::Miss | NodeCacheLookup::Invalid { .. } => {}
        NodeCacheLookup::Hit(_) => panic!("explicit invalidation must drop the entry"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn export_import_and_gc_are_deterministic() {
    let root = cache_root("export");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let first = base_key();
    let second = bind_case(
        "1",
        "work:2",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    cache
        .put(NodeCacheEntry::success(first.clone(), json!({"n": 1}), provenance(&first)).unwrap())
        .unwrap();
    cache
        .put(NodeCacheEntry::success(second.clone(), json!({"n": 2}), provenance(&second)).unwrap())
        .unwrap();
    let exported = cache.export().expect("export");
    let again = cache.export().expect("export again");
    assert_eq!(exported, again);

    let imported_root = cache_root("import");
    let imported = NodeResultCache::open(&imported_root).expect("open");
    assert_eq!(imported.import(&exported).expect("import"), 2);
    assert_eq!(imported.export().expect("re-export"), exported);

    assert_eq!(
        cache
            .gc(NodeCacheRetention {
                max_entries: Some(1)
            })
            .expect("gc"),
        1
    );
    assert_eq!(cache.inspect().expect("inspect").entry_count(), 1);
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(imported_root);
}

#[test]
fn replay_disposition_names_are_stable() {
    assert_eq!(CacheDisposition::Reused.as_str(), "reused");
    assert_eq!(CacheDisposition::Recorded.as_str(), "recorded");
    assert_eq!(CacheDisposition::Reexecuted.as_str(), "reexecuted");
}

#[test]
fn open_fsyncs_parent_that_owns_the_cache_name() {
    let parent = cache_root("open-parent");
    let root = parent.join(".node-result-cache");
    reset_node_cache_dir_syncs();
    NodeResultCache::open(&root).expect("open cache");
    assert!(
        node_cache_dir_syncs() >= 3,
        "first open must fsync entries, root, and the parent that owns the cache name"
    );
    let _ = fs::remove_dir_all(parent);
}

#[test]
fn equal_existing_put_and_absent_invalidate_fsync_entries() {
    let root = cache_root("idempotent-sync");
    let cache = NodeResultCache::open(&root).expect("open cache");
    let key = base_key();
    let entry = NodeCacheEntry::success(key.clone(), json!({"answer": "shared"}), provenance(&key))
        .unwrap();
    cache.put(entry.clone()).expect("seed");

    reset_node_cache_dir_syncs();
    cache.put(entry).expect("equal existing bytes");
    assert!(
        node_cache_dir_syncs() >= 1,
        "equal-existing put must fsync entries before returning success"
    );

    cache
        .invalidate(&key, NodeCacheInvalidationReason::ExplicitInvalidate)
        .expect("drop present entry");
    reset_node_cache_dir_syncs();
    cache
        .invalidate(&key, NodeCacheInvalidationReason::ExplicitInvalidate)
        .expect("already absent");
    assert!(
        node_cache_dir_syncs() >= 1,
        "already-absent invalidate must fsync entries before returning success"
    );
    let _ = fs::remove_dir_all(root);
}
