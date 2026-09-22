use std::sync::atomic::{AtomicU64, Ordering};

use super::support::{SMOKE_BYTES, SMOKE_SHA256, ScriptedSource, TestRoot};
use super::{Call, prepare};
use workflow_runtime::{
    ByteSource, DatasetError, DatasetErrorKind, DatasetManifest, DatasetSourceIdentity, EvalSuite,
};

const UPSTREAM_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const UPSTREAM_A: &str = "https://example.invalid/source-a";
const UPSTREAM_B: &str = "https://example.invalid/source-b";

#[derive(Default)]
struct MissingIdentitySource {
    reads: AtomicU64,
}

impl ByteSource for MissingIdentitySource {
    fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, DatasetError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(0)
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(0)
    }
}

fn upstream_toml(origin: &str) -> String {
    super::smoke_toml()
        .replace(
            "revision = \"1.0.0\"",
            &format!("revision = \"{UPSTREAM_REVISION}\""),
        )
        .replace(
            "url = \"memory://smoke-fixture\"",
            &format!("url = \"{origin}\""),
        )
}

#[test]
fn fetch_requires_the_selected_source_to_attest_the_requested_identity() {
    let manifest = DatasetManifest::parse_str(&upstream_toml(UPSTREAM_A)).expect("manifest");
    for (label, identity) in [
        (
            "origin",
            DatasetSourceIdentity::upstream(UPSTREAM_B, UPSTREAM_REVISION),
        ),
        (
            "revision",
            DatasetSourceIdentity::upstream(
                UPSTREAM_A,
                "abcdef0123456789abcdef0123456789abcdef0123",
            ),
        ),
        (
            "provenance",
            DatasetSourceIdentity::local_fixture(UPSTREAM_A, SMOKE_SHA256),
        ),
    ] {
        let root = TestRoot::new(label);
        let source = ScriptedSource::new(SMOKE_BYTES, 64).with_identity(identity);
        let error = prepare(
            &manifest,
            &root.0,
            &source,
            Call {
                id: "smoke-fixture",
                suite: EvalSuite::Regression,
                offline: false,
                license_accepted: false,
                manual_path: None,
            },
        )
        .expect_err("a different source identity must fail before reads");
        assert_eq!(error.kind(), DatasetErrorKind::SourceIdentityMismatch);
        assert!(source.served.lock().expect("served").is_empty());
    }

    let root = TestRoot::new("missing-identity");
    let source = MissingIdentitySource::default();
    let error = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Regression,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("a source without an identity must fail before reads");
    assert_eq!(error.kind(), DatasetErrorKind::SourceIdentityRequired);
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn cache_and_partial_metadata_cannot_cross_source_identities() {
    let manifest_a = DatasetManifest::parse_str(&upstream_toml(UPSTREAM_A)).expect("manifest A");
    let manifest_b = DatasetManifest::parse_str(&upstream_toml(UPSTREAM_B)).expect("manifest B");
    let source_a = ScriptedSource::new(SMOKE_BYTES, 64).with_identity(
        DatasetSourceIdentity::upstream(UPSTREAM_A, UPSTREAM_REVISION),
    );

    let cache_root = TestRoot::new("identity-cache");
    prepare(
        &manifest_a,
        &cache_root.0,
        &source_a,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Regression,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("identity A cache warm");
    let source_b = ScriptedSource::new(&[], 64).with_identity(DatasetSourceIdentity::upstream(
        UPSTREAM_B,
        UPSTREAM_REVISION,
    ));
    let error = prepare(
        &manifest_b,
        &cache_root.0,
        &source_b,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Regression,
            offline: true,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("identity B must not reuse identity A's cache entry");
    assert_eq!(error.kind(), DatasetErrorKind::OfflineMiss);
    assert!(source_b.served.lock().expect("served").is_empty());

    let partial_root = TestRoot::new("identity-partial");
    let interrupted = ScriptedSource::interrupt_after(SMOKE_BYTES, 8, 8).with_identity(
        DatasetSourceIdentity::upstream(UPSTREAM_A, UPSTREAM_REVISION),
    );
    let error = prepare(
        &manifest_a,
        &partial_root.0,
        &interrupted,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Regression,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("identity A interruption");
    assert_eq!(error.kind(), DatasetErrorKind::Interrupted);
    let source_b = ScriptedSource::new(SMOKE_BYTES, 64).with_identity(
        DatasetSourceIdentity::upstream(UPSTREAM_B, UPSTREAM_REVISION),
    );
    let error = prepare(
        &manifest_b,
        &partial_root.0,
        &source_b,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Regression,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("identity B must not resume identity A's partial");
    assert_eq!(error.kind(), DatasetErrorKind::SourceIdentityMismatch);
    assert!(source_b.served.lock().expect("served").is_empty());
}
