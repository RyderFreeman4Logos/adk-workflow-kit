use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
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
        let temp_root =
            fs::canonicalize(Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"))
                .expect("resolved HOME/tmp");
        let root = temp_root.join(format!(
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
    zero_after: Option<u64>,
    served: Mutex<Vec<u64>>,
}

impl ScriptedSource {
    fn new(bytes: &[u8], max_bytes: usize) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            interrupt_after: None,
            zero_after: None,
            served: Mutex::new(Vec::new()),
        }
    }

    fn interrupt_after(bytes: &[u8], max_bytes: usize, offset: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            interrupt_after: Some(offset),
            zero_after: None,
            served: Mutex::new(Vec::new()),
        }
    }

    fn short_eof_after(bytes: &[u8], max_bytes: usize, offset: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            interrupt_after: None,
            zero_after: Some(offset),
            served: Mutex::new(Vec::new()),
        }
    }
}

impl ByteSource for ScriptedSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        if self.interrupt_after.is_some_and(|limit| offset >= limit) {
            return Err(DatasetError::from(DatasetErrorKind::Interrupted));
        }
        if self.zero_after.is_some_and(|limit| offset >= limit) {
            return Ok(0);
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

fn manifest_with_tokens(id: &str, revision: &str) -> String {
    smoke_toml()
        .replace("id = \"smoke-fixture\"", &format!("id = \"{id}\""))
        .replace(
            "revision = \"1.0.0\"",
            &format!("revision = \"{revision}\""),
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
fn manifest_rejects_dot_and_dotdot_path_tokens_without_cache_io() {
    for (id, revision) in [
        (".", "1.0.0"),
        ("..", "1.0.0"),
        ("smoke-fixture", "."),
        ("smoke-fixture", ".."),
    ] {
        let root = TestRoot::new("traversal");
        let outside = root.0.parent().expect("test root parent").join(format!(
            "issue-229-outside-{}-{}",
            id.replace('.', "dot"),
            revision.replace('.', "dot")
        ));
        assert!(!outside.exists(), "external witness must start absent");
        let error = DatasetManifest::parse_str(&manifest_with_tokens(id, revision))
            .expect_err("path traversal tokens must be rejected during parsing");
        assert_eq!(error.kind(), DatasetErrorKind::InvalidManifest);
        assert!(
            !outside.exists(),
            "invalid tokens must not touch the cache boundary"
        );
    }
}

#[test]
fn configured_cache_root_directory_symlink_preserves_storage_layout() {
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let root = TestRoot::new("root-symlink");
    let target = root.0.join("cache-target");
    fs::create_dir(&target).expect("cache target");
    let configured = root.0.join("cache-link");
    symlink(&target, &configured).expect("configured cache root symlink");

    let prepared = prepare(
        &manifest,
        &configured,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("verified configured root symlink must be supported");
    assert_eq!(prepared.checksum(), SMOKE_SHA256);
    assert!(
        fs::symlink_metadata(&configured)
            .expect("configured root")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(target.join("smoke-fixture/1.0.0/artifact")).expect("stored artifact"),
        SMOKE_BYTES
    );
}

#[test]
fn unsafe_existing_cache_descendants_fail_closed_without_witness_change() {
    for (label, unsafe_component, unsafe_mode) in [
        ("id-group", "id", 0o770),
        ("revision-world", "revision", 0o707),
    ] {
        let root = TestRoot::new(label);
        let cache = root.0.join("cache");
        fs::create_dir(&cache).expect("cache root");
        let id = cache.join("smoke-fixture");
        fs::create_dir(&id).expect("dataset directory");
        let revision = id.join("1.0.0");
        fs::create_dir(&revision).expect("revision directory");
        let unsafe_path = if unsafe_component == "id" {
            &id
        } else {
            &revision
        };
        fs::set_permissions(unsafe_path, fs::Permissions::from_mode(unsafe_mode))
            .expect("unsafe directory mode");
        let witness = root.0.join("external-witness");
        fs::write(&witness, b"witness-before").expect("external witness");

        let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
        let source = ScriptedSource::new(SMOKE_BYTES, 64);
        let error = prepare(
            &manifest,
            &cache,
            &source,
            Call {
                id: "smoke-fixture",
                suite: EvalSuite::Smoke,
                offline: false,
                license_accepted: false,
                manual_path: None,
            },
        )
        .expect_err("unsafe existing descendants must fail closed");
        assert_eq!(error.kind(), DatasetErrorKind::Io);
        assert!(!revision.join("artifact").exists());
        assert!(source.served.lock().expect("served").is_empty());
        assert_eq!(
            fs::read(&witness).expect("external witness"),
            b"witness-before"
        );
    }
}

#[test]
fn symlinked_cache_paths_and_existing_temps_fail_closed() {
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::new(SMOKE_BYTES, 64);
    let root = TestRoot::new("symlinks");

    let external_parent = root.0.join(format!(
        "issue-229-external-parent-{}",
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&external_parent).expect("external parent");
    let parent_cache = root.0.join("parent-cache");
    fs::create_dir_all(&parent_cache).expect("parent cache");
    symlink(&external_parent, parent_cache.join("smoke-fixture")).expect("cache parent symlink");
    let error = prepare(
        &manifest,
        &parent_cache,
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("symlinked cache parents must be rejected");
    assert_eq!(error.kind(), DatasetErrorKind::Io);
    assert!(!external_parent.join("1.0.0/artifact").exists());
    fs::remove_dir_all(&external_parent).expect("remove external parent");

    let external_artifact = root.0.join(format!(
        "issue-229-external-artifact-{}",
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&external_artifact, b"outside-artifact").expect("external artifact");
    let artifact_cache = root.0.join("artifact-cache/smoke-fixture/1.0.0");
    fs::create_dir_all(&artifact_cache).expect("artifact cache");
    symlink(&external_artifact, artifact_cache.join("artifact")).expect("artifact symlink");
    let error = prepare(
        &manifest,
        &root.0.join("artifact-cache"),
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("symlinked artifacts must be rejected");
    assert_eq!(error.kind(), DatasetErrorKind::Io);
    assert_eq!(
        fs::read(&external_artifact).expect("external artifact"),
        b"outside-artifact"
    );
    fs::remove_file(&external_artifact).expect("remove external artifact");

    let external_partial = root.0.join(format!(
        "issue-229-external-partial-{}",
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&external_partial, b"outside-partial").expect("external partial");
    let partial_cache = root.0.join("partial-cache/smoke-fixture/1.0.0");
    fs::create_dir_all(&partial_cache).expect("partial cache");
    symlink(&external_partial, partial_cache.join("artifact.partial")).expect("partial symlink");
    let error = prepare(
        &manifest,
        &root.0.join("partial-cache"),
        &source,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect_err("symlinked partials must be rejected");
    assert_eq!(error.kind(), DatasetErrorKind::Io);
    assert_eq!(
        fs::read(&external_partial).expect("external partial"),
        b"outside-partial"
    );
    fs::remove_file(&external_partial).expect("remove external partial");

    let external_temp = root.0.join(format!(
        "issue-229-external-temp-{}",
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&external_temp, b"outside-temp").expect("external temp");
    let temp_cache = root.0.join("temp-cache/gated/9f3c1aa");
    fs::create_dir_all(&temp_cache).expect("temp cache");
    symlink(&external_temp, temp_cache.join(".tmp-artifact-collision"))
        .expect("existing temp collision");
    let manual = root.0.join("manual.txt");
    fs::write(&manual, SMOKE_BYTES).expect("manual artifact");
    let manual_manifest = DatasetManifest::parse_str(&gated_toml("manual", "9f3c1aa", true))
        .expect("manual manifest");
    let error = prepare(
        &manual_manifest,
        &root.0.join("temp-cache"),
        &source,
        Call {
            id: "gated",
            suite: EvalSuite::Formal,
            offline: false,
            license_accepted: true,
            manual_path: Some(&manual),
        },
    )
    .expect_err("existing temp collisions must be rejected");
    assert_eq!(error.kind(), DatasetErrorKind::Io);
    assert_eq!(
        fs::read(&external_temp).expect("external temp"),
        b"outside-temp"
    );
    fs::remove_file(&external_temp).expect("remove external temp");
}

#[test]
fn manifest_rejects_duplicate_dataset_ids_deterministically() {
    let duplicate = format!(
        "{}\n[[datasets]]\nid = \"smoke-fixture\"\nfamily = \"synthetic\"\nlanguage = \"en\"\nrevision = \"1.0.0\"\nurl = \"https://example.invalid/smoke\"\nsha256 = \"{}\"\nlicense = \"CC-BY-4.0\"\nlicense_acceptance_required = false\ndistribution = \"fetch\"\nadapter_version = \"adapter-1\"\nderivation = \"fixture-v1\"\nsuites = [\"smoke\"]\n",
        smoke_toml(),
        SMOKE_SHA256
    );
    let first =
        DatasetManifest::parse_str(&duplicate).expect_err("duplicate dataset IDs must be invalid");
    let second = DatasetManifest::parse_str(&duplicate)
        .expect_err("duplicate dataset IDs must stay invalid");
    assert_eq!(first.kind(), DatasetErrorKind::InvalidManifest);
    assert_eq!(second.kind(), DatasetErrorKind::InvalidManifest);
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
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
fn early_zero_read_preserves_partial_cache_for_resumption() {
    let root = TestRoot::new("early-eof");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let source = ScriptedSource::short_eof_after(SMOKE_BYTES, 8, 8);
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
    .expect_err("short source EOF must remain resumable");
    assert_eq!(first.kind(), DatasetErrorKind::Interrupted);
    let partial = root.0.join("smoke-fixture/1.0.0/artifact.partial");
    assert_eq!(
        fs::read(&partial).expect("retained partial"),
        &SMOKE_BYTES[..8]
    );

    let corrected = ScriptedSource::new(SMOKE_BYTES, SMOKE_BYTES.len());
    let prepared = prepare(
        &manifest,
        &root.0,
        &corrected,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("corrected retry must resume the retained prefix");
    assert_eq!(corrected.served.lock().expect("served")[0], 8);
    assert_eq!(prepared.checksum(), SMOKE_SHA256);
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
    let source = ScriptedSource::new(b"changed-upstream-byte!!\n", 64);
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
    assert!(!debug.contains("changed-upstream-byte!!"));
    assert!(!debug.contains(SMOKE_SHA256));
}

#[test]
fn checksum_mismatch_discards_partial_before_retry() {
    let root = TestRoot::new("checksum-retry");
    let manifest = DatasetManifest::parse_str(&smoke_toml()).expect("manifest");
    let changed = ScriptedSource::new(b"changed-upstream-byte!!\n", 64);
    assert_eq!(changed.bytes.len(), SMOKE_BYTES.len());
    let error = prepare(
        &manifest,
        &root.0,
        &changed,
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
    let partial = root.0.join("smoke-fixture/1.0.0/artifact.partial");
    assert!(!partial.exists(), "bad partial must be discarded");

    let corrected = ScriptedSource::new(SMOKE_BYTES, 64);
    prepare(
        &manifest,
        &root.0,
        &corrected,
        Call {
            id: "smoke-fixture",
            suite: EvalSuite::Smoke,
            offline: false,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("corrected retry must start clean");
    assert_eq!(corrected.served.lock().expect("served")[0], 0);
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
