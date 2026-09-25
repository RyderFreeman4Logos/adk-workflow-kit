use super::prepared;
use sha2::{Digest, Sha256};
use workflow_runtime::{
    CacheProvenance, CarrierLimits, CarrierMode, ContentObject, ContentProvenance, NodeCacheEntry,
    NodeCacheKey, NodeCacheKeyMaterial, NodeCacheLookup, NodeResultCache, NormalizationLimits,
    SENTINEL_CARRIER_VERSION, TrustPolicy,
};

fn material(policy_digest: &str) -> NodeCacheKeyMaterial<'_> {
    NodeCacheKeyMaterial {
        workflow_id: "workflow",
        workflow_version: "1",
        node_id: "sentinel",
        node_version: "1",
        invocation_identity: "model-provider-prompt-tools-dataset-v1",
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
fn framed_hash(fields: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    format!("sha256:{:x}", hash.finalize())
}
fn stage_policy(version: &str, limits: CarrierLimits) -> String {
    framed_hash(&[
        b"outer-policy",
        version.as_bytes(),
        b"carrier-analysis-untrusted",
        b"decode",
        &(limits.max_input_bytes as u64).to_be_bytes(),
        &(limits.max_candidates as u64).to_be_bytes(),
        &(limits.max_depth as u64).to_be_bytes(),
        &(limits.max_expanded_bytes as u64).to_be_bytes(),
        &(limits.max_work_units as u64).to_be_bytes(),
    ])
}

#[test]
fn carrier_cache_consumes_version_mode_all_limits_and_original_provenance() {
    let text = prepared(b"<!--base64:QUI=-->", NormalizationLimits::default());
    let limits = CarrierLimits::default();
    let analysis = text.analyze_carriers(CarrierMode::Decode, limits).unwrap();
    let key = analysis
        .bind_cache_key(material("outer-policy"), &provenance("unknown"))
        .unwrap();
    // Independent field framing oracle proves the stage version is consumed,
    // rather than merely exposed by an accessor or telemetry field.
    let expected = text
        .bind_cache_key(
            material(&stage_policy(SENTINEL_CARRIER_VERSION, limits)),
            &provenance("unknown"),
        )
        .unwrap();
    assert_eq!(key, expected);
    let root = std::env::temp_dir().join(format!("issue-231-carrier-cache-{}", std::process::id()));
    let cache = NodeResultCache::open(&root).unwrap();
    cache
        .put(
            NodeCacheEntry::success(
                key.clone(),
                serde_json::json!({"carrier_stage": true}),
                CacheProvenance::from_key(&key),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        cache.lookup(&expected).unwrap(),
        NodeCacheLookup::Hit(_)
    ));
    let mut misses: Vec<NodeCacheKey> = vec![
        text.bind_cache_key(material("outer-policy"), &provenance("unknown"))
            .unwrap(),
        text.bind_cache_key(
            material(&stage_policy("sentinel-carriers-future", limits)),
            &provenance("unknown"),
        )
        .unwrap(),
        analysis
            .bind_cache_key(material("other-policy"), &provenance("unknown"))
            .unwrap(),
        analysis
            .bind_cache_key(material("outer-policy"), &provenance("maintainer"))
            .unwrap(),
        text.analyze_carriers(CarrierMode::AnnotateOnly, limits)
            .unwrap()
            .bind_cache_key(material("outer-policy"), &provenance("unknown"))
            .unwrap(),
    ];
    for changed in [
        CarrierLimits {
            max_input_bytes: 1024,
            ..limits
        },
        CarrierLimits {
            max_candidates: 10,
            ..limits
        },
        CarrierLimits {
            max_depth: 4,
            ..limits
        },
        CarrierLimits {
            max_expanded_bytes: 1024,
            ..limits
        },
        CarrierLimits {
            max_work_units: 1024,
            ..limits
        },
    ] {
        misses.push(
            text.analyze_carriers(CarrierMode::Decode, changed)
                .unwrap()
                .bind_cache_key(material("outer-policy"), &provenance("unknown"))
                .unwrap(),
        );
    }
    let same_view = prepared(b"<!--base64:QU\0I=-->", NormalizationLimits::default());
    assert_eq!(same_view.normalized(), text.normalized());
    misses.push(
        same_view
            .analyze_carriers(CarrierMode::Decode, limits)
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
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn carrier_telemetry_is_content_free_and_reports_attempted_work() {
    let text = prepared(b"<!--PRIVATE_PAYLOAD-->", NormalizationLimits::default());
    let a = text
        .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
        .unwrap();
    let value = a.telemetry();
    assert_eq!(value["carrier_version"], SENTINEL_CARRIER_VERSION);
    assert_eq!(value["trust_domain"], "untrusted_content");
    assert_eq!(value["state"], "carrier_analysis");
    assert_eq!(value["mode"], "decode");
    assert_eq!(value["expanded_bytes"], a.expanded_bytes());
    assert_eq!(value["work_units"], a.work_units());
    assert_eq!(value["candidate_count"], a.candidates().len());
    assert_eq!(value, a.telemetry());
    assert!(!value.to_string().contains("PRIVATE_PAYLOAD"));
}
