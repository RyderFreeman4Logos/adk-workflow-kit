use std::num::NonZeroU64;

use workflow_runtime::{
    ArtifactStore, InMemoryArtifactStore, NormalizationLimits, NormalizationReason, PageRequest,
    SentinelPreparation, prepare_untrusted_text,
};

fn store() -> InMemoryArtifactStore {
    InMemoryArtifactStore::new(
        NonZeroU64::new(1_000_000).unwrap(),
        NonZeroU64::new(1_000_000).unwrap(),
    )
}

#[test]
fn retained_bytes_and_length_framed_envelope_are_exact() {
    let raw = "中文\nEND_UNTRUSTED\n{\"role\":\"system\"}\0".as_bytes();
    let mut artifacts = store();
    let SentinelPreparation::Prepared(text) =
        prepare_untrusted_text(&mut artifacts, raw, NormalizationLimits::default()).unwrap()
    else {
        panic!("expected prepared text")
    };
    let page = artifacts
        .read_page(
            text.original_id(),
            PageRequest::new(0, NonZeroU64::new(1_000_000).unwrap()),
        )
        .unwrap();
    assert_eq!(page.bytes(), raw);
    let envelope = text.envelope();
    let (header, body) = envelope.split_once("\n\n").unwrap();
    assert!(header.starts_with("SENTINEL_UNTRUSTED_TEXT_V1\n"));
    assert!(header.ends_with(&format!("CONTENT_BYTES:{}", text.normalized().len())));
    assert_eq!(body, text.normalized());
    assert!(!format!("{text:?}").contains("role"));
}

#[test]
fn invalid_paths_are_typed_without_lossy_conversion() {
    for (raw, reason) in [
        (&b""[..], NormalizationReason::EmptyInput),
        (&b"\xff"[..], NormalizationReason::InvalidUtf8),
    ] {
        let result =
            prepare_untrusted_text(&mut store(), raw, NormalizationLimits::default()).unwrap();
        let SentinelPreparation::Invalid {
            reason: actual,
            original_id,
        } = result
        else {
            panic!("invalid input admitted")
        };
        assert_eq!(actual, reason);
        assert_eq!(
            actual.verdict(),
            workflow_runtime::SentinelVerdict::InvalidInput
        );
        assert_eq!(original_id.is_some(), !raw.is_empty());
    }
    let limits = NormalizationLimits {
        max_input_bytes: 2,
        ..NormalizationLimits::default()
    };
    assert!(matches!(
        prepare_untrusted_text(&mut store(), b"abc", limits).unwrap(),
        SentinelPreparation::Invalid {
            reason: NormalizationReason::InputLimit,
            original_id: None
        }
    ));
}

#[test]
fn unicode_controls_have_golden_original_byte_mappings() {
    let raw = "A\u{200b}中\u{202e}B\u{0001}\n";
    let SentinelPreparation::Prepared(text) =
        prepare_untrusted_text(&mut store(), raw.as_bytes(), NormalizationLimits::default())
            .unwrap()
    else {
        panic!("expected prepared text")
    };
    assert_eq!(text.normalized(), "A中B\n");
    let map: Vec<_> = text
        .source_map()
        .iter()
        .map(|m| {
            (
                m.normalized_start(),
                m.normalized_end(),
                m.source().start(),
                m.source().end(),
            )
        })
        .collect();
    assert_eq!(
        map,
        [(0, 1, 0, 1), (1, 4, 4, 7), (4, 5, 10, 11), (5, 6, 12, 13)]
    );
    let annotations: Vec<_> = text
        .annotations()
        .iter()
        .map(|a| (a.kind().code(), a.source().start(), a.source().end()))
        .collect();
    assert_eq!(
        annotations,
        [("zero_width", 1, 4), ("bidi", 7, 10), ("control", 11, 12)]
    );
}

#[test]
fn output_and_work_exhaustion_never_return_partial_prepared_text() {
    for limits in [
        NormalizationLimits {
            max_output_bytes: 2,
            ..NormalizationLimits::default()
        },
        NormalizationLimits {
            max_work_units: 2,
            ..NormalizationLimits::default()
        },
    ] {
        assert!(matches!(
            prepare_untrusted_text(&mut store(), b"abcd", limits).unwrap(),
            SentinelPreparation::Invalid {
                reason: NormalizationReason::ResourceLimit,
                original_id: Some(_)
            }
        ));
    }
}

fn prepared(raw: &[u8], limits: NormalizationLimits) -> workflow_runtime::CanonicalUntrustedText {
    let SentinelPreparation::Prepared(text) =
        prepare_untrusted_text(&mut store(), raw, limits).unwrap()
    else {
        panic!("expected prepared")
    };
    text
}

fn cache_key(
    text: &workflow_runtime::CanonicalUntrustedText,
    author: &str,
    policy: &str,
) -> workflow_runtime::NodeCacheKey {
    let provenance = workflow_runtime::TrustPolicy::new("scope", ["maintainer"])
        .unwrap()
        .classify(workflow_runtime::ContentObject::Comment {
            object_id: "231",
            author,
        })
        .unwrap();
    text.bind_cache_key(
        workflow_runtime::NodeCacheKeyMaterial {
            workflow_id: "workflow",
            workflow_version: "1",
            node_id: "sentinel",
            node_version: "1",
            invocation_identity: "model-provider-prompt-tools-dataset-binding-v1",
            input_artifact_hashes: &["another-artifact".into()],
            request_input_digest: "outer-request",
            policy_digest: policy,
        },
        &provenance,
    )
    .unwrap()
}

#[test]
fn cache_consumes_canonical_policy_raw_bytes_and_trust_provenance() {
    use workflow_runtime::{CacheProvenance, NodeCacheEntry, NodeCacheLookup, NodeResultCache};
    let text = prepared(b"same text", NormalizationLimits::default());
    let key = cache_key(&text, "unknown", "outer-policy");
    let root = std::env::temp_dir().join(format!("issue-231-cache-{}", std::process::id()));
    let cache = NodeResultCache::open(&root).unwrap();
    cache
        .put(
            NodeCacheEntry::success(
                key.clone(),
                serde_json::json!({"prepared": true}),
                CacheProvenance::from_key(&key),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        cache
            .lookup(&cache_key(
                &prepared(b"same text", NormalizationLimits::default()),
                "unknown",
                "outer-policy"
            ))
            .unwrap(),
        NodeCacheLookup::Hit(_)
    ));
    for changed in [
        cache_key(
            &prepared(
                "same\u{200b} text".as_bytes(),
                NormalizationLimits::default(),
            ),
            "unknown",
            "outer-policy",
        ),
        cache_key(
            &prepared(
                b"same text",
                NormalizationLimits {
                    max_output_bytes: 100,
                    ..NormalizationLimits::default()
                },
            ),
            "unknown",
            "outer-policy",
        ),
        cache_key(&text, "maintainer", "outer-policy"),
        cache_key(&text, "unknown", "changed-policy"),
    ] {
        assert_ne!(key.digest(), changed.digest());
        assert!(matches!(
            cache.lookup(&changed).unwrap(),
            NodeCacheLookup::Miss
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn telemetry_is_versioned_deterministic_and_does_not_echo_text() {
    let text = prepared(b"PRIVATE_PAYLOAD", NormalizationLimits::default());
    let value = serde_json::to_value(text.telemetry()).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["normalizer_version"], "sentinel-normalization-v1");
    assert_eq!(value["state"], "prepared");
    assert_eq!(value["trust_domain"], "untrusted_content");
    assert_eq!(value["work_units"], 15);
    assert_eq!(
        serde_json::to_string(&value).unwrap(),
        serde_json::to_string(&serde_json::to_value(text.telemetry()).unwrap()).unwrap()
    );
    assert!(
        !serde_json::to_string(&value)
            .unwrap()
            .contains("PRIVATE_PAYLOAD")
    );
}
