//! Four pinned source goldens; no live model or upstream benchmark execution.
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use workflow_runtime::{DatasetErrorKind, SentinelDatasetLabel, validate_sentinel_splits};
use workflow_runtime::{
    DatasetManifest, SentinelDatasetError, derive_sentinel_carrier_suite, prepare_sentinel_goldens,
};

const MANIFEST: &str = include_str!("../../../config/datasets.toml");

#[test]
fn missing_acceptance_fails_before_cache_or_source_access() {
    let manifest = DatasetManifest::parse_str(MANIFEST).expect("registry");
    let cache = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
        .join("tmp")
        .join(format!("issue-236-license-{}", std::process::id()));
    assert!(!cache.exists());
    assert_eq!(
        prepare_sentinel_goldens(&manifest, &cache, Some(&cache), false)
            .expect_err("license must precede path access"),
        SentinelDatasetError::LicenseRequired
    );
    assert!(!cache.exists());
}

#[test]
fn incomplete_registry_fails_before_cache_access() {
    let manifest =
        DatasetManifest::parse_str("schema_version = 1\ndatasets = []\n").expect("empty registry");
    let cache = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
        .join("tmp")
        .join(format!("issue-236-registry-{}", std::process::id()));
    assert_eq!(
        prepare_sentinel_goldens(&manifest, &cache, None, true)
            .expect_err("fixed source descriptors required"),
        SentinelDatasetError::Registry
    );
    assert!(!cache.exists());
    assert!(fs::metadata(cache).is_err());
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestRoot(PathBuf);
impl TestRoot {
    fn new(label: &str) -> Self {
        let base =
            fs::canonicalize(PathBuf::from(std::env::var_os("HOME").expect("HOME")).join("tmp"))
                .expect("SSD temporary directory");
        let path = base.join(format!(
            "issue-236-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("owned fixture root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
        Self(path)
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn fixed_registry_rejects_wrong_source_checksum_version_and_license() {
    let root = TestRoot::new("registry-controls");
    let cache = root.0.join("never-created");
    let source = "https://raw.githubusercontent.com/ethz-spylab/agentdojo/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/default_suites/v1/banking/user_tasks.py";
    for modified in [
        MANIFEST.replacen(source, "https://example.invalid/wrong-origin", 1),
        MANIFEST.replacen(
            "37af838194f001af80cc040315bcb2d69d0112324d424f9a323473b41b317f82",
            &"0".repeat(64),
            1,
        ),
        MANIFEST.replacen(
            "adapter_version = \"sentinel-native-golden-v1\"",
            "adapter_version = \"wrong\"",
            1,
        ),
        MANIFEST.replacen("license = \"MIT\"", "license = \"unknown\"", 1),
        MANIFEST.replacen(
            "license = \"MIT\"\nlicense_acceptance_required = true",
            "license = \"MIT\"\nlicense_acceptance_required = false",
            1,
        ),
    ] {
        let manifest =
            DatasetManifest::parse_str(&modified).expect("well-formed conflicting registry");
        assert_eq!(
            prepare_sentinel_goldens(&manifest, &cache, Some(&root.0), true)
                .expect_err("conflict precedes source/cache use"),
            SentinelDatasetError::Registry
        );
        assert!(!cache.exists());
    }
}

#[test]
fn wrong_raw_source_and_missing_manual_input_cannot_mint_cases() {
    let root = TestRoot::new("wrong-bytes");
    let manifest = DatasetManifest::parse_str(MANIFEST).expect("registry");
    fs::write(
        root.0.join("agentdojo-user_tasks.py"),
        b"not the pinned Python source",
    )
    .expect("wrong source fixture");
    assert_eq!(
        prepare_sentinel_goldens(&manifest, &root.0.join("cache"), Some(&root.0), true)
            .expect_err("observed source hash mismatch"),
        SentinelDatasetError::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    assert_eq!(
        prepare_sentinel_goldens(&manifest, &root.0.join("missing-cache"), None, true)
            .expect_err("cache-only miss"),
        SentinelDatasetError::Admission(DatasetErrorKind::ManualPathRequired)
    );
}

fn golden_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/issue_236/goldens.json")).expect("golden fixture")
}

#[test]
fn fixture_bundle_contains_complete_pinned_notices() {
    use sha2::{Digest, Sha256};
    let manifest = DatasetManifest::parse_str(MANIFEST).expect("registry");
    let fixture = golden_fixture();
    let notices: [(&str, &[u8]); 5] = [
        (
            "sentinel-agentdojo-LICENSE",
            include_bytes!("fixtures/issue_236/notices/agentdojo-LICENSE"),
        ),
        (
            "sentinel-injecagent-LICENCE",
            include_bytes!("fixtures/issue_236/notices/injecagent-LICENCE"),
        ),
        (
            "sentinel-bipia-LICENSE",
            include_bytes!("fixtures/issue_236/notices/bipia-LICENSE"),
        ),
        (
            "sentinel-bipia-NOTICE-md",
            include_bytes!("fixtures/issue_236/notices/bipia-NOTICE.md"),
        ),
        (
            "sentinel-piguard-LICENSE",
            include_bytes!("fixtures/issue_236/notices/piguard-LICENSE"),
        ),
    ];
    for (id, bytes) in notices {
        let entry = manifest.dataset(id).expect("fixed notice entry");
        let hash = format!("sha256:{:x}", Sha256::digest(bytes));
        assert_eq!(hash, entry.sha256());
        let evidence = fixture["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .flat_map(|case| {
                case["expected"]["license_notices"]
                    .as_array()
                    .expect("notices")
            })
            .find(|notice| notice["source_url"] == entry.url())
            .expect("fixture notice binding");
        assert_eq!(evidence["size_bytes"], bytes.len());
        assert_eq!(evidence["admission"]["checksum"], hash);
    }
}

fn acceptance_cache_root(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(workflow_runtime::validated_dataset_cache_root(path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent =
        workflow_runtime::validated_dataset_cache_root(path.parent().ok_or("cache parent")?)?;
    let root = parent.join(path.file_name().ok_or("cache leaf")?);
    // Exclusive creation sets the mode atomically; never chmod an existing root or link.
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    Ok(workflow_runtime::validated_dataset_cache_root(&root)?)
}

#[test]
fn acceptance_cache_rejects_unsafe_existing_roots_without_mutation() {
    let root = TestRoot::new("cache-admission");
    let unsafe_root = root.0.join("unsafe");
    fs::create_dir(&unsafe_root).expect("unsafe control directory");
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o770)).expect("unsafe mode");
    let link = root.0.join("unsafe-link");
    symlink(&unsafe_root, &link).expect("configured link");
    let target_identity = fs::metadata(&unsafe_root).expect("target metadata");
    let link_identity = fs::symlink_metadata(&link).expect("link metadata");
    for path in [&unsafe_root, &link] {
        assert!(
            acceptance_cache_root(path).is_err(),
            "unsafe existing root is denied"
        );
        let after = fs::metadata(&unsafe_root).expect("unchanged target");
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (
                target_identity.dev(),
                target_identity.ino(),
                target_identity.mode()
            )
        );
        let link_after = fs::symlink_metadata(&link).expect("unchanged link");
        assert_eq!(
            (link_after.dev(), link_after.ino(), link_after.mode()),
            (
                link_identity.dev(),
                link_identity.ino(),
                link_identity.mode()
            )
        );
        assert_eq!(
            fs::read_link(&link).expect("same configured target"),
            unsafe_root
        );
        assert_eq!(
            fs::read_dir(&unsafe_root)
                .expect("unchanged contents")
                .count(),
            0
        );
    }
}

#[test]
fn acceptance_cache_preserves_safe_link_and_existing_mode() {
    let root = TestRoot::new("cache-link");
    let safe = root.0.join("safe");
    fs::create_dir(&safe).expect("safe directory");
    fs::set_permissions(&safe, fs::Permissions::from_mode(0o750)).expect("operator mode");
    let link = root.0.join("safe-link");
    symlink(&safe, &link).expect("safe configured link");
    let before = fs::metadata(&safe).expect("safe metadata");
    let link_before = fs::symlink_metadata(&link).expect("link metadata");
    assert_eq!(acceptance_cache_root(&link).expect("safe link"), safe);
    let after = fs::metadata(&safe).expect("target metadata");
    assert_eq!(
        (after.dev(), after.ino(), after.mode()),
        (before.dev(), before.ino(), before.mode())
    );
    let link_after = fs::symlink_metadata(&link).expect("same link");
    assert_eq!(
        (link_after.dev(), link_after.ino(), link_after.mode()),
        (link_before.dev(), link_before.ino(), link_before.mode())
    );
    assert_eq!(fs::read_link(&link).expect("same target"), safe);
    let fresh = root.0.join("fresh");
    assert_eq!(
        acceptance_cache_root(&fresh).expect("exclusive new root"),
        fresh
    );
    assert_eq!(
        fs::metadata(fresh).expect("private new directory").mode() & 0o777,
        0o700
    );
}

#[test]
fn just_path_parameters_are_literal_shell_data() {
    use std::{
        ffi::OsString,
        process::{Command, Stdio},
    };
    let root = TestRoot::new("just-argv");
    let bin = root.0.join("bin");
    fs::create_dir(&bin).expect("owned command fixture");
    let cargo = bin.join("cargo");
    fs::write(&cargo, b"#!/bin/sh\nprintf '%s\\0' \"${ADK_DATASET_SOURCE_DIR-}\" \"${ADK_DATASET_CACHE_DIR-}\" \"$@\" > \"$ISSUE236_ARGV_CAPTURE\"\n").expect("argv-only fake Cargo");
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).expect("owned executable");
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").expect("PATH"),
    ));
    let path = std::env::join_paths(paths).expect("test-local command path");
    let marker = root.0.join("must-not-evaluate");
    let literal = format!(
        "literal-$HOME-'single'-\"double\"-`touch {0}`-$(touch {0})",
        marker.display()
    );
    let source = root.0.join(format!("source-{literal}"));
    let cache = root.0.join(format!("cache-{literal}"));
    let source = source.to_str().expect("fixture UTF-8");
    let cache = cache.to_str().expect("fixture UTF-8");
    let offline = vec![
        "+1.98.0",
        "test",
        "-p",
        "workflow-runtime",
        "--test",
        "issue_236_dataset_adapters",
        "actual_sources_and_two_cache_only_reruns",
        "--locked",
        "--",
        "--exact",
        "--ignored",
        "--nocapture",
    ];
    let product = vec![
        "+1.98.0",
        "run",
        "-p",
        "workflow-testkit",
        "--bin",
        "ether0-eval",
        "--locked",
        "--",
        cache,
        source,
        source,
        source,
    ];
    let profile = vec![
        "+1.98.0",
        "run",
        "-p",
        "workflow-testkit",
        "--bin",
        "m3-07-live",
        "--locked",
        "--",
        "./target/debug/workflowctl",
        source,
    ];
    for (recipe, args, env_values, expected) in [
        (
            "issue-236-offline",
            vec![source, cache],
            vec![source, cache],
            offline,
        ),
        (
            "issue-229-product",
            vec![cache, source, source, source],
            vec!["", ""],
            product,
        ),
        ("m3-07-live", vec![source], vec!["", ""], profile),
    ] {
        let capture = root.0.join(format!("{recipe}-argv"));
        // Coreutils timeout owns its group, bounds TERM/KILL, and status reaps it.
        let status = Command::new("timeout")
            .args(["--kill-after=2s", "10s", "just", recipe])
            .args(args)
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .env("PATH", &path)
            .env("ISSUE236_ARGV_CAPTURE", &capture)
            .env("WORKFLOW_KIT_M3_07_LIVE", "1")
            .env_remove("ADK_DATASET_SOURCE_DIR")
            .env_remove("ADK_DATASET_CACHE_DIR")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("bounded Just argv probe");
        assert!(status.success(), "{recipe}: {status}");
        assert!(!marker.exists(), "path bytes were evaluated by {recipe}");
        let bytes = fs::read(capture).expect("actual command argv");
        let mut actual: Vec<_> = bytes
            .split(|b| *b == 0)
            .map(|b| OsString::from(String::from_utf8(b.to_vec()).expect("UTF-8")))
            .collect();
        assert_eq!(actual.pop(), Some(OsString::new()));
        let expected: Vec<_> = env_values
            .into_iter()
            .chain(expected)
            .map(OsString::from)
            .collect();
        assert_eq!(
            actual, expected,
            "literal bytes at {recipe} command boundary"
        );
    }
}

fn assert_fixed_carriers(
    originals: &[workflow_runtime::SentinelDatasetCase],
) -> Vec<workflow_runtime::SentinelDatasetCase> {
    use sha2::{Digest, Sha256};
    let suite = derive_sentinel_carrier_suite(originals).expect("checked fixed carriers");
    let descendants = suite
        .iter()
        .filter(|case| {
            !originals
                .iter()
                .any(|parent| parent.case_id() == case.case_id())
        })
        .count();
    assert_eq!(
        (suite.len(), descendants),
        (12, 8),
        "real carrier cardinality"
    );
    let expected_hashes = [
        "sha256:953385c97621047c583bf90e00378612c073d5a7bcf24210b5147d48c4557946",
        "sha256:2ecb0017f77bec92117c202e53aa33b9c034f9c91d4483b0a349b86f0f431d1d",
        "sha256:2f2ed1c3ff1bef1fc3f5f4b6e311cd4f1a1951669cb2ae3a22d14ebd87899425",
        "sha256:307d8c0c733135022910f58122401a97fbfa7c5422a13185a01970488616e2e5",
        "sha256:82969fa804ec7f13031be661327aff20bba867811987f8529766510af6374b39",
        "sha256:f9f05b65b147f9326f734948ab96e6833bd384f0c3b7fa3a139c8a31162afd99",
        "sha256:10f9adfafae5e0fd97a3872ff3d279c1e376a2f3e67ce851add77b02b99f64c2",
        "sha256:6fc48eef29260e7fd6c2f5f2f631976b92d90d60e282c95d9d6b75819adb0743",
    ];
    let mut ids = std::collections::BTreeSet::new();
    for (index, original) in originals.iter().enumerate() {
        let parent: Value =
            serde_json::from_slice(&original.canonical_json().expect("parent")).expect("JSON");
        let raw = parent["untrusted_text"].as_str().expect("text");
        assert_eq!(
            suite[index * 3].canonical_json().expect("original"),
            original.canonical_json().expect("unchanged")
        );
        // Independent expected bytes: sequential replacement cannot re-escape an entity.
        let html = format!(
            "<pre>{}</pre>",
            raw.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('\"', "&quot;")
                .replace('\'', "&#39;")
        );
        let longest = raw.split(|c| c != '`').map(str::len).max().unwrap_or(0);
        let fence = "`".repeat(3.max(longest + 1));
        let markdown = format!("{fence}\n{raw}\n{fence}");
        for (offset, (operator, suffix, carrier, transformation, expected, start, projection)) in [
            (
                "HtmlPreV1",
                "html-pre-v1",
                "html_pre",
                "html_pre_v1",
                html.as_str(),
                5,
                "whole_parent_cover",
            ),
            (
                "MarkdownFenceV1",
                "markdown-fence-v1",
                "markdown_fence",
                "markdown_fence_v1",
                markdown.as_str(),
                fence.len() + 1,
                "exact_body_translation",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let case = &suite[index * 3 + offset + 1];
            let actual: Value =
                serde_json::from_slice(&case.canonical_json().expect("carrier")).expect("JSON");
            let digest = format!("sha256:{:x}", Sha256::digest(expected.as_bytes()));
            assert_eq!(
                digest,
                expected_hashes[index * 2 + offset],
                "independently pinned text hash"
            );
            let end = if offset == 0 {
                expected.len() - 6
            } else {
                start + raw.len()
            };
            let mut wanted = parent.clone();
            wanted["case_id"] = json!(format!("{}/{suffix}", original.case_id()));
            wanted["untrusted_text"] = json!(expected);
            wanted["carrier"] = json!(carrier);
            wanted["transformation"] = json!(transformation);
            wanted["review"] = json!("unreviewed");
            wanted["label_authority"] = json!({"kind":"unreviewed_carrier_inheriting_parent_intent", "parent_canonical_sha256":original.canonical_sha256().expect("hash")});
            wanted["derivation"] = json!({"schema_version":1,"operator":operator,"version":1,"original_case_id":original.case_id(),"original_canonical_sha256":original.canonical_sha256().expect("hash"),"original_text_sha256":format!("sha256:{:x}",Sha256::digest(raw.as_bytes())),"original_text_interval":[0,raw.len()],"derived_text_sha256":digest,"output_body_interval":[start,end],"projection":projection});
            assert_eq!(
                actual, wanted,
                "complete independently expected descendant and preserved provenance"
            );
        }
    }
    for case in &suite {
        assert!(ids.insert(case.case_id()), "unique IDs");
    }
    let assignments: Vec<_> = suite.iter().map(|case| (case, "regression")).collect();
    assert!(validate_sentinel_splits(&assignments).is_ok());
    for moved in 0..suite.len() {
        for split in ["train", "adaptive", "final"] {
            let mut assignments = assignments.clone();
            assignments[moved].1 = split;
            assert!(
                validate_sentinel_splits(&assignments).is_err(),
                "parent, carrier and sibling stay together"
            );
        }
    }
    suite
}

#[test]
#[ignore = "requires the explicit pinned local source and cache arguments through just issue-236-offline"]
fn actual_sources_and_two_cache_only_reruns() {
    use std::{num::NonZeroU64, time::Instant};
    use workflow_runtime::{
        InMemoryArtifactStore, NormalizationLimits, SentinelPreparation, prepare_untrusted_text,
    };
    let source = PathBuf::from(
        std::env::var_os("ADK_DATASET_SOURCE_DIR").expect("explicit local source directory"),
    );
    let cache_root =
        PathBuf::from(std::env::var_os("ADK_DATASET_CACHE_DIR").expect("explicit cache directory"));
    let cache_root = acceptance_cache_root(&cache_root).expect("safe configured cache container");
    let cache = cache_root.join(format!("actual-{}", std::process::id()));
    assert!(
        !cache.exists(),
        "each acceptance invocation imports into a fresh owned child"
    );
    let manifest = DatasetManifest::parse_str(MANIFEST).expect("registry");
    let fixture = golden_fixture();
    let cases = prepare_sentinel_goldens(&manifest, &cache, Some(&source), true)
        .expect("fifteen actual artifacts");
    assert_eq!(cases.len(), 4);
    let mut canonical = Vec::new();
    for (case, expected) in cases
        .iter()
        .zip(fixture["cases"].as_array().expect("four golden cases"))
    {
        let bytes = case.canonical_json().expect("canonical case");
        let value: Value = serde_json::from_slice(&bytes).expect("case JSON");
        assert_eq!(
            value, expected["expected"],
            "real native case and admission provenance"
        );
        assert_eq!(
            case.canonical_sha256().expect("case hash"),
            expected["canonical_sha256"]
        );
        let mut old_schema = value.clone();
        for key in ["source_components", "license_notices"] {
            for component in old_schema[key].as_array_mut().expect("artifacts") {
                let admission = component
                    .as_object_mut()
                    .expect("evidence")
                    .remove("admission")
                    .expect("real report binding");
                assert_eq!(admission["source_identity"]["kind"], "manual");
                assert_eq!(admission["checksum"], admission["source_revision"]);
                assert!(
                    admission["derivation_hash"]
                        .as_str()
                        .expect("derivation")
                        .starts_with("sha256:")
                );
            }
        }
        use sha2::{Digest, Sha256};
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&old_schema).expect("old schema"))
            ),
            expected["plan_canonical_sha256"],
            "only true DatasetReport fields refine the reviewed plan"
        );
        assert!(validate_sentinel_splits(&[(case, "regression")]).is_ok());
        assert!(validate_sentinel_splits(&[(case, "regression"), (case, "final")]).is_err());
        println!(
            "{} {}",
            case.case_id(),
            case.canonical_sha256().expect("hash")
        );
        canonical.push(bytes);
    }
    assert_eq!(cases[3].label(), SentinelDatasetLabel::BenignHardNegative);
    let suite = assert_fixed_carriers(&cases);
    let suite_canonical: Vec<_> = suite
        .iter()
        .map(|case| case.canonical_json().expect("suite canonical"))
        .collect();
    for case in &suite {
        let value: Value =
            serde_json::from_slice(&case.canonical_json().expect("case")).expect("JSON");
        let mut store = InMemoryArtifactStore::new(
            NonZeroU64::new(1_000_000).expect("nonzero"),
            NonZeroU64::new(1_000_000).expect("nonzero"),
        );
        assert!(matches!(
            prepare_untrusted_text(
                &mut store,
                value["untrusted_text"].as_str().expect("text").as_bytes(),
                NormalizationLimits::default(),
                Instant::now()
            )
            .expect("runtime envelope"),
            SentinelPreparation::Prepared(_)
        ));
    }

    for _ in 0..2 {
        let rerun = prepare_sentinel_goldens(&manifest, &cache, None, true)
            .expect("cache-only offline rerun");
        assert_eq!(
            rerun
                .iter()
                .map(|case| case.canonical_json().expect("case JSON"))
                .collect::<Vec<_>>(),
            canonical
        );
        let rerun_suite = assert_fixed_carriers(&rerun);
        assert_eq!(
            rerun_suite
                .iter()
                .map(|case| case.canonical_json().expect("case JSON"))
                .collect::<Vec<_>>(),
            suite_canonical
        );
    }
    assert_eq!(
        prepare_sentinel_goldens(&manifest, &cache, None, false)
            .expect_err("warm cache license gate"),
        SentinelDatasetError::LicenseRequired
    );
    let artifact = cache
        .join("sentinel-agentdojo-user-tasks-py")
        .join("089ed468cf3ed0322acc66b0211f26d9d90dbf60")
        .join("artifact");
    let good = fs::read(&artifact).expect("admitted raw artifact");
    fs::write(&artifact, b"tampered cache").expect("negative cache control");
    assert!(prepare_sentinel_goldens(&manifest, &cache, None, true).is_err());
    fs::write(&artifact, good).expect("restore this test's raw cache");
    let notice = cache
        .join("sentinel-bipia-NOTICE-md")
        .join("a004b69ec0dd446e0afd461d98cb5e96e120a5d0")
        .join("artifact");
    let notice_bytes = fs::read(&notice).expect("complete BIPIA notice");
    fs::remove_file(&notice).expect("missing-notice negative control");
    let missing_notice = prepare_sentinel_goldens(&manifest, &cache, None, true);
    fs::write(&notice, notice_bytes).expect("restore this test's complete notice");
    assert!(
        missing_notice.is_err(),
        "all source and notice admissions precede cases"
    );
    let records: Vec<_> = suite.iter().enumerate().map(|(index, case)| json!({"case_id":case.case_id(),"canonical_sha256":case.canonical_sha256().expect("hash"),"intent_authority":if index % 3 == 0 {"publisher_documented_original"} else {"unreviewed_carrier_inheriting_parent_intent"}})).collect();
    let report = json!({"schema_version":1,"case_count":12,"original_count":4,"descendant_count":8,"records":records,"cache_only_reruns":2,
        "semantic_evaluation":"not_run","resolved_byte_provenance":"manual","human_review":"not_present"});
    fs::write(
        cache.join("fixed-carrier-acceptance.json"),
        serde_json::to_vec_pretty(&report).expect("acceptance evidence"),
    )
    .expect("durable local receipt");
    println!("actual local acceptance evidence: {}", cache.display());
}
