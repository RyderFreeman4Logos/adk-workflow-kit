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
