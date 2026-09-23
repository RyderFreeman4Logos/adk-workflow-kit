use parquet::{
    data_type::{ByteArray, ByteArrayType},
    file::writer::SerializedFileWriter,
    schema::parser::parse_message_type,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, sync::Arc};
use workflow_runtime::{ByteSource, DatasetError, DatasetManifest, DatasetSourceIdentity};
use workflow_testkit::run_dataset_product;

struct Source {
    bytes: Vec<u8>,
    url: String,
    revision: String,
    interrupt: bool,
}
impl ByteSource for Source {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(DatasetSourceIdentity::upstream(&self.url, &self.revision))
    }
    fn len(&self) -> Result<u64, DatasetError> {
        Ok(self.bytes.len() as u64)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        if self.interrupt && offset != 0 {
            return Ok(0);
        }
        let remainder = self.bytes.get(offset as usize..).unwrap_or_default();
        let n = remainder
            .len()
            .min(buf.len())
            .min(if self.interrupt { 20 } else { usize::MAX });
        buf[..n].copy_from_slice(&remainder[..n]);
        Ok(n)
    }
}

fn fixture() -> Vec<u8> {
    let columns = [
        "id",
        "problem",
        "solution",
        "ideal",
        "problem_type",
        "unformatted",
    ];
    let schema = Arc::new(
        parse_message_type(&format!(
            "message cases {{ {} }}",
            columns
                .iter()
                .map(|name| format!("REQUIRED BINARY {name} (UTF8);"))
                .collect::<String>()
        ))
        .unwrap(),
    );
    let mut bytes = Vec::new();
    {
        let mut writer = SerializedFileWriter::new(&mut bytes, schema, Default::default()).unwrap();
        let mut group = writer.next_row_group().unwrap();
        for (i, _) in columns.iter().enumerate() {
            let values = if i == 0 {
                ["row-1", "row-2", "row-3"]
            } else {
                ["question one", "question two", "question three"]
            };
            let mut col = group.next_column().unwrap().unwrap();
            col.typed::<ByteArrayType>()
                .write_batch(&values.map(ByteArray::from), None, None)
                .unwrap();
            col.close().unwrap();
        }
        group.close().unwrap();
        writer.close().unwrap();
    }
    bytes
}

#[test]
fn public_composition_evaluates_and_publishes_with_offline_parity() {
    let bytes = fixture();
    let revision = "c7d5e59960087f360bc32a5006bb994324b38c35";
    let url = format!(
        "https://huggingface.co/datasets/futurehouse/ether0-benchmark/resolve/{revision}/data/test-00000-of-00001.parquet"
    );
    let sha = format!("sha256:{:x}", Sha256::digest(&bytes));
    let manifest = DatasetManifest::parse_str(&format!(
        r#"schema_version = 1
[[datasets]]
id = "ether0"
family = "futurehouse"
language = "en"
revision = "{revision}"
url = "{url}"
sha256 = "{sha}"
license = "CC-BY-4.0"
license_acceptance_required = true
distribution = "fetch"
adapter_version = "1"
derivation = "first-rows"
suites = ["regression"]
"#
    ))
    .unwrap();
    let source = Source {
        bytes,
        url,
        revision: revision.into(),
        interrupt: false,
    };
    let cache = PathBuf::from(std::env::var("HOME").unwrap())
        .join("tmp")
        .canonicalize()
        .unwrap()
        .join(format!("issue-229-product-test-{}", std::process::id()));
    fs::create_dir(&cache).unwrap();
    let broken = cache.join("broken-root-link");
    std::os::unix::fs::symlink(cache.join("absent"), &broken).unwrap();
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &source, &broken, false, false, 3).unwrap_err(),
        "dataset license acceptance is required"
    );
    assert!(run_dataset_product(&manifest, "ether0", &source, &cache, false, false, 3).is_err());
    assert!(!cache.join("ether0-report.json").exists());
    let wrong_revision = Source {
        bytes: source.bytes.clone(),
        url: source.url.clone(),
        revision: "0000000000000000000000000000000000000000".into(),
        interrupt: false,
    };
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &wrong_revision, &cache, true, false, 3)
            .unwrap_err(),
        "dataset source identity mismatch"
    );
    let mut changed = source.bytes.clone();
    changed[0] ^= 1;
    let wrong_checksum = Source {
        bytes: changed,
        url: source.url.clone(),
        revision: source.revision.clone(),
        interrupt: false,
    };
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &wrong_checksum, &cache, true, false, 3)
            .unwrap_err(),
        "dataset checksum mismatch"
    );
    let interrupted = Source {
        bytes: source.bytes.clone(),
        url: source.url.clone(),
        revision: source.revision.clone(),
        interrupt: true,
    };
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &interrupted, &cache, true, false, 3).unwrap_err(),
        "dataset fetch interrupted"
    );
    assert_eq!(
        fs::metadata(cache.join("ether0").join(revision).join("artifact.partial"))
            .unwrap()
            .len(),
        20
    );
    assert!(!cache.join("ether0-report.json").exists());
    let first = run_dataset_product(&manifest, "ether0", &source, &cache, true, false, 3)
        .expect("online product report");
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["dataset"]["source_revision"], revision);
    assert_eq!(report["dataset"]["checksum"], sha);
    assert_eq!(report["dataset"]["family"], "futurehouse");
    assert_eq!(report["dataset"]["language"], "en");
    assert_eq!(report["cases"].as_array().unwrap().len(), 3);
    assert_eq!(report["cases"][0]["evaluation"]["transition"], "trajectory");
    assert!(
        report["dataset"]["derivation_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    let original = fs::read(&first).unwrap();
    let offline_source = Source {
        bytes: vec![],
        url: "https://example.invalid/never-egress".into(),
        revision: "main".into(),
        interrupt: false,
    };
    let second =
        run_dataset_product(&manifest, "ether0", &offline_source, &cache, true, true, 3).unwrap();
    assert_eq!(fs::read(&second).unwrap(), original);
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &offline_source, &cache, false, true, 3)
            .unwrap_err(),
        "dataset license acceptance is required"
    );
    assert_eq!(fs::read(&second).unwrap(), original);
    let configured = cache.with_file_name(format!("issue-229-product-link-{}", std::process::id()));
    std::os::unix::fs::symlink(&cache, &configured).unwrap();
    let linked = run_dataset_product(
        &manifest,
        "ether0",
        &offline_source,
        &configured,
        true,
        true,
        3,
    )
    .expect("report through trusted cache-root link");
    assert_eq!(linked, second);
    assert_eq!(fs::read(&linked).unwrap(), original);
    fs::remove_file(configured).unwrap();
    let protected = cache.join("protected.txt");
    fs::write(&protected, b"untouched").unwrap();
    fs::remove_file(&second).unwrap();
    std::os::unix::fs::symlink(&protected, &second).unwrap();
    assert_eq!(
        run_dataset_product(&manifest, "ether0", &offline_source, &cache, true, true, 3)
            .unwrap_err(),
        "unsafe report destination"
    );
    assert_eq!(fs::read(protected).unwrap(), b"untouched");
    fs::remove_dir_all(cache).unwrap();
}

#[test]
fn alternate_declared_license_is_rejected_before_cache_access() {
    let bytes = fixture();
    let revision = "c7d5e59960087f360bc32a5006bb994324b38c35";
    let url = format!(
        "https://huggingface.co/datasets/futurehouse/ether0-benchmark/resolve/{revision}/data/test-00000-of-00001.parquet"
    );
    let sha = format!("sha256:{:x}", Sha256::digest(&bytes));
    let manifest = DatasetManifest::parse_str(&format!(
        r#"schema_version = 1
[[datasets]]
id = "ether0"
family = "futurehouse"
language = "en"
revision = "{revision}"
url = "{url}"
sha256 = "{sha}"
license = "research-only"
license_acceptance_required = true
distribution = "fetch"
adapter_version = "1"
derivation = "first-rows"
suites = ["regression"]
"#
    ))
    .unwrap();
    let source = Source {
        bytes,
        url,
        revision: revision.into(),
        interrupt: false,
    };
    let cache = PathBuf::from(std::env::var("HOME").unwrap())
        .join("tmp")
        .canonicalize()
        .unwrap()
        .join(format!("issue-229-license-mismatch-{}", std::process::id()));
    assert!(!cache.exists());
    let cold =
        run_dataset_product(&manifest, "ether0", &source, &cache, true, false, 3).unwrap_err();
    assert!(cold.contains("license"), "{cold}");
    assert!(!cache.exists(), "cold mismatch must not create a cache");
    // The generic registry accepts this declared license; the specialized product must not.
    for offline in [false, true] {
        let prepared = workflow_runtime::prepare_dataset(
            &manifest,
            "ether0",
            &workflow_runtime::PrepareRequest {
                cache_dir: &cache,
                source: &source,
                suite: workflow_runtime::EvalSuite::Regression,
                offline,
                license_accepted: true,
                manual_path: None,
            },
        )
        .expect("verified generic cache for the alternate declared license");
        assert_eq!(prepared.from_cache(), offline);
    }
    let artifact = cache.join("ether0").join(revision).join("artifact");
    let before = fs::read(&artifact).unwrap();
    assert_eq!(format!("sha256:{:x}", Sha256::digest(&before)), sha);
    let warm =
        run_dataset_product(&manifest, "ether0", &source, &cache, true, true, 3).unwrap_err();
    assert!(warm.contains("license"), "{warm}");
    assert_eq!(fs::read(artifact).unwrap(), before);
    assert!(!cache.join("ether0-report.json").exists());
    fs::remove_dir_all(cache).unwrap();
}

#[test]
fn shipped_cli_refuses_unaccepted_license_without_a_report() {
    let root = PathBuf::from(std::env::var("HOME").unwrap())
        .join("tmp")
        .canonicalize()
        .unwrap()
        .join(format!("issue-229-denied-{}", std::process::id()));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ether0-eval"))
        .args([root.to_str().unwrap(), "deny", "online", "3"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("license acceptance is required"));
    assert!(!root.exists());
}

fn cli_root(label: &str) -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap())
        .join("tmp")
        .canonicalize()
        .unwrap()
        .join(format!("issue-229-cli-{label}-{}", std::process::id()))
}

fn run_cli(cache: &std::path::Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ether0-eval"))
        .arg(cache)
        .args(["accept-cc-by-4.0", "offline", "3"])
        .output()
        .expect("shipping CLI")
}

#[test]
#[ignore = "public pinned HTTPS fixture; invoke via just issue-229-cli-links"]
fn shipped_cli_supports_verified_root_link() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
    use workflow_runtime::{EvalSuite, HttpByteSource, PrepareRequest, prepare_dataset};
    let manifest = DatasetManifest::parse_str(include_str!("../../../config/datasets.toml"))
        .expect("committed manifest");
    let entry = manifest.dataset("ether0").unwrap();
    let source = HttpByteSource::new(entry.url(), entry.revision(), entry.sha256(), 100_000)
        .expect("public pinned source");
    let store = cli_root("verified-store");
    fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
    // Real pinned bytes, not a synthetic artifact or a shipping pin override.
    prepare_dataset(
        &manifest,
        "ether0",
        &PrepareRequest {
            cache_dir: &store,
            source: &source,
            suite: EvalSuite::Regression,
            offline: false,
            license_accepted: true,
            manual_path: None,
        },
    )
    .expect("verified warm cache");
    let artifact = store.join("ether0").join(entry.revision()).join("artifact");
    let bytes = fs::read(&artifact).unwrap();
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(&bytes)),
        entry.sha256()
    );
    let linked = cli_root("verified-link");
    symlink(&store, &linked).unwrap();
    let before = fs::metadata(&store).unwrap();
    let output = run_cli(&linked);
    let report = fs::read(store.join("ether0-report.json"));
    assert_eq!(fs::read_link(&linked).unwrap(), store);
    assert_eq!(linked.canonicalize().unwrap(), store);
    let after = fs::metadata(&linked).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(fs::read(&artifact).unwrap(), bytes);
    fs::remove_file(&linked).unwrap();
    fs::remove_dir_all(&store).unwrap();
    assert!(
        output.status.success(),
        "CLI refused verified linked cache: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        store.join("ether0-report.json").to_str().unwrap()
    );
    let report: serde_json::Value =
        serde_json::from_slice(&report.expect("published report")).unwrap();
    assert_eq!(report["dataset"]["checksum"], entry.sha256());
    assert_eq!(report["cases"].as_array().unwrap().len(), 3);
}

#[test]
fn shipped_cli_refuses_dangling_and_unsafe_links_and_nested_cache() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = cli_root("negative-store");
    fs::create_dir(&root).unwrap();
    let unsafe_target = root.join("unsafe-target");
    fs::create_dir(&unsafe_target).unwrap();
    fs::set_permissions(&unsafe_target, fs::Permissions::from_mode(0o777)).unwrap();
    let unsafe_hop = root.join("unsafe-hop");
    fs::create_dir(&unsafe_hop).unwrap();
    fs::set_permissions(&unsafe_hop, fs::Permissions::from_mode(0o777)).unwrap();
    let safe = root.join("safe");
    fs::create_dir(&safe).unwrap();
    symlink(&safe, unsafe_hop.join("hop")).unwrap();
    for (label, target) in [
        ("dangling", root.join("missing")),
        ("unsafe", unsafe_target.clone()),
        ("unsafe-chain", unsafe_hop.join("hop")),
    ] {
        let linked = cli_root(label);
        symlink(&target, &linked).unwrap();
        let output = run_cli(&linked);
        assert!(!output.status.success(), "{label} must fail");
        assert_eq!(
            fs::read_link(&linked).unwrap(),
            target,
            "preserve refused link"
        );
        fs::remove_file(&linked).unwrap();
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("dataset storage failed"),
            "{label}: shared validator must reject: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let nested = root.join("nested");
    let output = run_cli(&nested);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("direct child"));
    assert!(!nested.exists());
    assert!(!root.join("missing").exists());
    assert!(fs::read_dir(&unsafe_target).unwrap().next().is_none());
    assert!(fs::read_dir(&safe).unwrap().next().is_none());
    fs::remove_dir_all(root).unwrap();
}
