use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use workflow_runtime::{
    ByteSource, DatasetError, DatasetErrorKind, DatasetManifest, EvalSuite, PrepareRequest,
    prepare_dataset,
};

const SMOKE_BYTES: &[u8] = b"issue-229-smoke-fixture\n";
const SMOKE_SHA256: &str =
    "sha256:e543862e31a042f932ef3d2f34daa869537e5da06ad9ded1cbbd10885bd46959";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "issue-229-{}-{}-{}",
            label,
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("cache root");
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ScriptedSource {
    bytes: Vec<u8>,
    max_bytes: usize,
    interrupt_after: Option<u64>,
    served: Mutex<Vec<u64>>,
}

impl ScriptedSource {
    fn new(bytes: &[u8], max_bytes: usize) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            interrupt_after: None,
            served: Mutex::new(Vec::new()),
        }
    }

    fn interrupt_after(bytes: &[u8], max_bytes: usize, offset: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            interrupt_after: Some(offset),
            served: Mutex::new(Vec::new()),
        }
    }
}

impl ByteSource for ScriptedSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        if self.interrupt_after.is_some_and(|limit| offset >= limit) {
            return Err(DatasetError::from(DatasetErrorKind::Interrupted));
        }
        let start = usize::try_from(offset).expect("fixture offset");
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let available = self.bytes.len() - start;
        let take = available.min(buf.len()).min(self.max_bytes);
        buf[..take].copy_from_slice(&self.bytes[start..start + take]);
        self.served.lock().expect("served").push(offset);
        Ok(take)
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(u64::try_from(self.bytes.len()).expect("fixture len"))
    }
}

fn smoke_toml() -> String {
    format!(
        r#"
schema_version = 1

[[datasets]]
id = "smoke-fixture"
family = "synthetic"
language = "en"
revision = "1.0.0"
url = "memory://smoke-fixture"
sha256 = "{SMOKE_SHA256}"
license = "Apache-2.0"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["smoke", "regression"]
"#
    )
}

fn gated_toml(distribution: &str, revision: &str, license_required: bool) -> String {
    format!(
        r#"
schema_version = 1

[[datasets]]
id = "gated"
family = "agentdojo"
language = "en"
revision = "{revision}"
url = "memory://gated"
sha256 = "{SMOKE_SHA256}"
license = "research-only"
license_acceptance_required = {license_required}
distribution = "{distribution}"
adapter_version = "1"
derivation = "identity"
suites = ["final"]
"#
    )
}

struct Call<'a> {
    id: &'a str,
    suite: EvalSuite,
    offline: bool,
    license_accepted: bool,
    manual_path: Option<&'a Path>,
}

fn prepare(
    manifest: &DatasetManifest,
    cache_dir: &Path,
    source: &dyn ByteSource,
    call: Call<'_>,
) -> Result<workflow_runtime::PreparedDataset, DatasetError> {
    prepare_dataset(
        manifest,
        call.id,
        &PrepareRequest {
            cache_dir,
            source,
            suite: call.suite,
            offline: call.offline,
            license_accepted: call.license_accepted,
            manual_path: call.manual_path,
        },
    )
}

#[test]
fn committed_manifest_round_trips_and_pins_smoke_subset() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/datasets.toml");
    let text = fs::read_to_string(&path).expect("committed datasets.toml");
    let manifest = DatasetManifest::parse_str(&text).expect("parse committed manifest");
    let encoded = manifest.to_toml().expect("encode");
    let round_trip = DatasetManifest::parse_str(&encoded).expect("round-trip");
    assert_eq!(manifest, round_trip);
    let smoke = manifest
        .dataset("smoke-fixture")
        .expect("smoke subset is pinned");
    assert_eq!(smoke.revision(), "1.0.0");
    assert_eq!(smoke.sha256(), SMOKE_SHA256);
    assert_eq!(smoke.adapter_version(), "1");
    assert!(!smoke.license_acceptance_required());
}

#[test]
fn interrupted_download_resumes_from_partial_cache() {
    let root = TestRoot::new("resume");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::interrupt_after(SMOKE_BYTES, 8, 8);
    let first = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    );
    assert!(
        first.is_err(),
        "first pass must stop before the full artifact is cached"
    );
    assert_eq!(source.served.lock().expect("served")[0], 0);

    let source = ScriptedSource::new(SMOKE_BYTES, SMOKE_BYTES.len());
    let prepared = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("resume must complete");
    assert_eq!(source.served.lock().expect("served")[0], 8);
    assert_eq!(prepared.checksum(), SMOKE_SHA256);
    assert!(!prepared.from_cache());
}

#[test]
fn checksum_mismatch_rejects_changed_upstream_bytes() {
    let root = TestRoot::new("checksum");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::new(b"changed-upstream-bytes\n", 64);
    let error = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("checksum must fail closed");
    assert_eq!(error.kind(), DatasetErrorKind::ChecksumMismatch);
    let debug = format!("{error:?}");
    assert!(!debug.contains("changed-upstream-bytes"));
    assert!(!debug.contains(SMOKE_SHA256));
}

#[test]
fn unpinned_revision_is_rejected_for_formal_suites() {
    let root = TestRoot::new("unpin");
    let manifest =
        DatasetManifest::parse_str(&gated_toml("fetch", "main", false)).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let error = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: true,
            manual_path: None,
        },
    )
    .expect_err("moving branch must not enter formal suites");
    assert_eq!(error.kind(), DatasetErrorKind::UnpinnedRevision);
}

#[test]
fn offline_cache_hit_reuses_identical_adapter_hash() {
    let root = TestRoot::new("offline");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let first = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("warm cache");
    let online_hash = first.derivation_hash().to_owned();
    let report = first.report();
    assert_eq!(report.source_revision(), "1.0.0");
    assert_eq!(report.checksum(), SMOKE_SHA256);
    assert_eq!(report.adapter_version(), "1");
    assert_eq!(report.derivation_hash(), online_hash);
    assert_eq!(first.case_ids(), &["smoke-fixture/synthetic/en/0000"]);

    let empty = ScriptedSource::new(&[], 64);
    let cached = prepare(
        &manifest,
        &root.0,
        &empty,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: true,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("offline reuse");
    assert!(cached.from_cache());
    assert_eq!(cached.derivation_hash(), online_hash);
    assert_eq!(cached.case_ids(), first.case_ids());
}

#[test]
fn license_gated_dataset_cannot_be_fetched_silently() {
    let root = TestRoot::new("license");
    let manifest =
        DatasetManifest::parse_str(&gated_toml("fetch", "1.0.0", true)).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let silent = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("silent fetch is forbidden");
    assert_eq!(silent.kind(), DatasetErrorKind::LicenseRequired);

    let accepted = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: true,
            manual_path: None,
        },
    )
    .expect("explicit acceptance is required");
    assert_eq!(accepted.checksum(), SMOKE_SHA256);
}

#[test]
fn manual_path_is_required_for_non_distributable_sources() {
    let root = TestRoot::new("manual");
    let manifest =
        DatasetManifest::parse_str(&gated_toml("manual", "9f3c1aa", true)).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let missing = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: true,
            manual_path: None,
        },
    )
    .expect_err("manual sources must not auto-fetch");
    assert_eq!(missing.kind(), DatasetErrorKind::ManualPathRequired);

    let file = root.0.join("provided.txt");
    fs::write(&file, SMOKE_BYTES).expect("manual artifact");
    let prepared = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: true,
            manual_path: Some(&file),
        },
    )
    .expect("manual path");
    assert_eq!(prepared.checksum(), SMOKE_SHA256);
    assert_eq!(prepared.source_revision(), "9f3c1aa");
}

#[test]
fn offline_miss_fails_closed_without_network() {
    let root = TestRoot::new("offline-miss");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let error = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: true,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("offline miss must not fetch");
    assert_eq!(error.kind(), DatasetErrorKind::OfflineMiss);
    assert!(source.served.lock().expect("served").is_empty());
}

#[test]
fn formal_suite_rejects_committed_smoke_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/datasets.toml");
    let text = fs::read_to_string(&path).expect("committed datasets.toml");
    let manifest = DatasetManifest::parse_str(&text).expect("parse committed manifest");
    let root = TestRoot::new("formal-smoke");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let error = prepare(
        &manifest,
        &root.0,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("formal must not admit smoke-fixture");
    assert_eq!(error.kind(), DatasetErrorKind::SuiteNotAdmitted);
}

#[test]
fn debug_redacts_paths_and_checksums() {
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let debug = format!("{manifest:?}");
    assert!(!debug.contains(SMOKE_SHA256));
    assert!(!debug.contains("memory://smoke-fixture"));
}
