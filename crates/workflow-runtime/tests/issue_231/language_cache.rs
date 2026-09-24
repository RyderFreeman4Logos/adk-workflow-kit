use super::prepared;
use sha2::{Digest, Sha256};
use workflow_runtime::{
    CacheProvenance, ContentObject, ContentProvenance, LanguagePolicy, NodeCacheEntry,
    NodeCacheKeyMaterial, NodeCacheLookup, NodeResultCache, NormalizationLimits,
    SENTINEL_LANGUAGE_POLICY_VERSION, SegmentationLimits, TrustPolicy,
};

fn material(policy_digest: &str) -> NodeCacheKeyMaterial<'_> {
    NodeCacheKeyMaterial {
        workflow_id: "workflow",
        workflow_version: "1",
        node_id: "sentinel",
        node_version: "1",
        invocation_identity: "synthetic-offline-binding",
        input_artifact_hashes: &[],
        request_input_digest: "request",
        policy_digest,
    }
}
fn provenance(author: &str) -> ContentProvenance {
    TrustPolicy::new("scope", ["maintainer"])
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "231",
            author,
        })
        .unwrap()
}
fn policy_hash(version: &str) -> String {
    let mut hash = Sha256::new();
    for field in [
        b"outer-policy".as_slice(),
        version.as_bytes(),
        b"language-attribution-untrusted",
        &[1, 1, 1],
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    format!("sha256:{:x}", hash.finalize())
}

#[test]
fn language_cache_binds_real_stage_version_every_allowlist_bit_and_prior_stages() {
    assert_eq!(
        SENTINEL_LANGUAGE_POLICY_VERSION,
        "sentinel-language-policy-v1"
    );
    let text = prepared(b"This is a message", NormalizationLimits::default());
    let limits = SegmentationLimits::default();
    let segments = text.segment_language(limits).unwrap();
    let analysis = segments.assess_language(LanguagePolicy::default()).unwrap();
    let key = analysis
        .bind_cache_key(material("outer-policy"), &provenance("unknown"))
        .unwrap();
    let expected = segments
        .bind_cache_key(
            material(&policy_hash(SENTINEL_LANGUAGE_POLICY_VERSION)),
            &provenance("unknown"),
        )
        .unwrap();
    assert_eq!(key, expected, "independent stage framing must match");
    let root =
        std::env::temp_dir().join(format!("issue-231-language-cache-{}", std::process::id()));
    let cache = NodeResultCache::open(&root).unwrap();
    cache
        .put(
            NodeCacheEntry::success(
                key.clone(),
                serde_json::to_value(analysis.attribution()).unwrap(),
                CacheProvenance::from_key(&key),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        cache.lookup(&expected).unwrap(),
        NodeCacheLookup::Hit(_)
    ));
    let mut misses = vec![
        segments
            .bind_cache_key(material("outer-policy"), &provenance("unknown"))
            .unwrap(),
        text.bind_cache_key(material("outer-policy"), &provenance("unknown"))
            .unwrap(),
        segments
            .bind_cache_key(
                material(&policy_hash("future-version")),
                &provenance("unknown"),
            )
            .unwrap(),
        analysis
            .bind_cache_key(material("other-policy"), &provenance("unknown"))
            .unwrap(),
        analysis
            .bind_cache_key(material("outer-policy"), &provenance("maintainer"))
            .unwrap(),
        analysis
            .bind_cache_key(
                NodeCacheKeyMaterial {
                    request_input_digest: "other-request",
                    ..material("outer-policy")
                },
                &provenance("unknown"),
            )
            .unwrap(),
    ];
    let mut identities = std::collections::BTreeSet::new();
    for en in [false, true] {
        for zh in [false, true] {
            for ja in [false, true] {
                let policy = LanguagePolicy { en, zh, ja };
                let changed = segments
                    .assess_language(policy)
                    .unwrap()
                    .bind_cache_key(material("outer-policy"), &provenance("unknown"))
                    .unwrap();
                identities.insert(changed.digest().to_owned());
                if policy != LanguagePolicy::default() {
                    misses.push(changed);
                }
            }
        }
    }
    assert_eq!(identities.len(), 8);
    let reordered: LanguagePolicy =
        serde_json::from_str(r#"{"ja":true,"zh":true,"en":true}"#).unwrap();
    let repeated = segments
        .assess_language(reordered)
        .unwrap()
        .bind_cache_key(material("outer-policy"), &provenance("unknown"))
        .unwrap();
    assert!(matches!(
        cache.lookup(&repeated).unwrap(),
        NodeCacheLookup::Hit(_)
    ));
    for changed in [
        SegmentationLimits {
            max_bytes: 100,
            ..limits
        },
        SegmentationLimits {
            max_segments: 100,
            ..limits
        },
    ] {
        misses.push(
            text.segment_language(changed)
                .unwrap()
                .assess_language(LanguagePolicy::default())
                .unwrap()
                .bind_cache_key(material("outer-policy"), &provenance("unknown"))
                .unwrap(),
        );
    }
    let other_raw = prepared(b"Th\0is is a message", NormalizationLimits::default());
    assert_eq!(other_raw.normalized(), text.normalized());
    misses.push(
        other_raw
            .segment_language(limits)
            .unwrap()
            .assess_language(LanguagePolicy::default())
            .unwrap()
            .bind_cache_key(material("outer-policy"), &provenance("unknown"))
            .unwrap(),
    );
    for miss in misses {
        assert!(matches!(
            cache.lookup(&miss).unwrap(),
            NodeCacheLookup::Miss
        ));
    }
    assert!(
        analysis
            .bind_cache_key(material(""), &provenance("unknown"))
            .is_err()
    );
    assert!(
        analysis
            .bind_cache_key(
                NodeCacheKeyMaterial {
                    request_input_digest: "",
                    ..material("outer-policy")
                },
                &provenance("unknown")
            )
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}
