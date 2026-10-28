//! Fixed AgentDojo admission and explicit local-source acceptance; no model or execution.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use workflow_runtime::firewall::{FirewallPolicy, FirewallReason, ToolProposal, TrustedGoal};
use workflow_runtime::{
    AgentDojoDatasetError as Error, AgentDojoEpisode, AgentDojoProjectionError, DatasetErrorKind,
    DatasetManifest, DatasetProvenance, FirewallDecision, prepare_agentdojo_episodes,
    validated_dataset_cache_root,
};

const MANIFEST: &str = include_str!("../../../config/datasets.toml");
const PIN: &str = "089ed468cf3ed0322acc66b0211f26d9d90dbf60";
const CLEAN: &str = "1a3ce69ea37b3869ca97aede045263ecd01437751b2c5c9cb476134dc4344273";
const NOTICE: &str = "sha256:4285a071f2d382338e52b4fb0a186d952984a34d43a33d8872e1a1d8cb43401e";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new(label: &str) -> Self {
        let base =
            fs::canonicalize(PathBuf::from(std::env::var_os("HOME").expect("HOME")).join("tmp"))
                .expect("SSD tmp");
        let path = base.join(format!(
            "issue-241-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private root");
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn manifest() -> DatasetManifest {
    DatasetManifest::parse_str(MANIFEST).expect("registry")
}
fn golden() -> Value {
    serde_json::from_str(include_str!("fixtures/issue_241/agentdojo_goldens.json"))
        .expect("independent metadata and host oracle")
}
fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn acceptance_cache_root(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(validated_dataset_cache_root(path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = validated_dataset_cache_root(path.parent().ok_or("cache parent")?)?;
    let root = parent.join(path.file_name().ok_or("cache leaf")?);
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    Ok(validated_dataset_cache_root(&root)?)
}

fn read_snapshot(path: &Path, checksum: &str) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Error::Admission(DatasetErrorKind::Io))?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Admission(DatasetErrorKind::Io))?;
    if bytes.len() > 1_048_576 {
        return Err(Error::Limit);
    }
    if sha(&bytes) != checksum {
        return Err(Error::Checksum);
    }
    Ok(bytes)
}

#[test]
fn acceptance_snapshots_reject_growth_and_same_size_identity_changes() {
    let root = Root::new("snapshots");
    let path = root.0.join("artifact");
    let original = b"admitted";
    let checksum = sha(original);
    fs::write(&path, original).expect("admitted fixture");
    assert_eq!(
        read_snapshot(&path, &checksum).expect("exact snapshot"),
        original
    );
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("owned growing fixture")
        .set_len(1_048_577)
        .expect("grow beyond cap");
    assert_eq!(read_snapshot(&path, &checksum), Err(Error::Limit));
    let changed = b"modified";
    assert_eq!(changed.len(), original.len());
    fs::write(&path, changed).expect("same-size replacement");
    assert_eq!(read_snapshot(&path, &checksum), Err(Error::Checksum));
}

#[test]
fn acceptance_cache_target_survives_configured_link_retarget() {
    let root = Root::new("retarget");
    let original = acceptance_cache_root(&root.0.join("original")).expect("private original");
    let other = acceptance_cache_root(&root.0.join("other")).expect("private other target");
    assert_eq!(
        fs::metadata(&original).expect("private mode").mode() & 0o777,
        0o700
    );
    let original_notice = b"original notice";
    let other_notice = b"other notice";
    fs::write(original.join("notice"), original_notice).expect("original notice");
    fs::write(other.join("notice"), other_notice).expect("other notice");
    let link = root.0.join("configured");
    symlink(&original, &link).expect("configured root");
    let before = fs::symlink_metadata(&link).expect("link identity");
    let captured = acceptance_cache_root(&link).expect("bind checked target");
    assert_eq!(captured, original);
    assert_eq!(
        fs::symlink_metadata(&link).expect("preserved link").ino(),
        before.ino()
    );
    let replacement = root.0.join("replacement");
    symlink(&other, &replacement).expect("controlled new target");
    fs::rename(&replacement, &link).expect("controlled root retarget");
    let retargeted = fs::symlink_metadata(&link).expect("retargeted link identity");
    let notice = captured.join("notice");
    let snapshot = read_snapshot(&notice, &sha(original_notice)).expect("original target snapshot");
    fs::write(&notice, b"altered notice").expect("owned notice control");
    assert_eq!(
        read_snapshot(&other.join("notice"), &sha(other_notice)).expect("other untouched"),
        other_notice
    );
    fs::write(&notice, &snapshot).expect("restore original target");
    fs::write(captured.join("acceptance.json"), b"owned receipt").expect("original receipt target");
    assert_eq!(
        read_snapshot(&notice, &sha(original_notice)).expect("restored notice"),
        original_notice
    );
    assert!(!other.join("acceptance.json").exists());
    assert_eq!(
        read_snapshot(&captured.join("acceptance.json"), &sha(b"owned receipt"))
            .expect("receipt stayed on original"),
        b"owned receipt"
    );
    let after = fs::symlink_metadata(&link).expect("same retargeted link");
    assert_eq!(
        (after.dev(), after.ino(), after.mode()),
        (retargeted.dev(), retargeted.ino(), retargeted.mode())
    );
    assert_eq!(
        fs::read_link(&link).expect("configured target unchanged"),
        other
    );
}

#[test]
fn license_and_registry_precede_all_paths() {
    let root = Root::new("early");
    let cache = root.0.join("absent");
    let source = root.0.join("also-absent");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache, Some(&source), false)
            .expect_err("explicit acceptance"),
        Error::LicenseRequired
    );
    let empty =
        DatasetManifest::parse_str("schema_version=1\ndatasets=[]").expect("empty registry");
    assert_eq!(
        prepare_agentdojo_episodes(&empty, &cache, Some(&source), true)
            .expect_err("fixed descriptors"),
        Error::Registry
    );
    assert!(!cache.exists());
}

#[test]
fn fixed_registry_rejects_source_pin_adapter_and_license_changes() {
    let root = Root::new("registry");
    let cache = root.0.join("absent");
    // Change only the new archive entry, retaining all existing Sentinel descriptors.
    let offset = MANIFEST
        .find("id = \"agentdojo-archive-clean\"")
        .expect("archive entry");
    let (prefix, tail) = MANIFEST.split_at(offset);
    for altered in [
        tail.replacen(CLEAN, &"0".repeat(64), 1),
        tail.replacen(PIN, &"1".repeat(40), 1),
        tail.replacen("agentdojo-archive-v1", "other", 1),
        tail.replacen("license = \"MIT\"", "license = \"unknown\"", 1),
        tail.replacen(
            "license_acceptance_required = true",
            "license_acceptance_required = false",
            1,
        ),
        tail.replacen("distribution = \"manual\"", "distribution = \"fetch\"", 1),
    ] {
        let changed = DatasetManifest::parse_str(&format!("{prefix}{altered}"))
            .expect("well-formed conflict");
        assert_eq!(
            prepare_agentdojo_episodes(&changed, &cache, Some(&root.0), true)
                .expect_err("fixed descriptor mismatch"),
            Error::Registry
        );
        assert!(!cache.exists());
    }
}

#[test]
fn acquisition_checksum_missing_manual_and_limit_refusals_are_distinct() {
    let root = Root::new("admission");
    let cache = root.0.join("cache");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache, None, true).expect_err("cold cache"),
        Error::Admission(DatasetErrorKind::ManualPathRequired)
    );
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache, Some(&root.0), true)
            .expect_err("missing archive"),
        Error::Admission(DatasetErrorKind::Io)
    );
    let path = root.0.join("agentdojo-clean.json");
    fs::write(&path, b"wrong pinned bytes").expect("wrong source");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache, Some(&root.0), true)
            .expect_err("source checksum"),
        Error::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    fs::write(path, vec![b' '; 1_048_577]).expect("over cap source");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache, Some(&root.0), true)
            .expect_err("acquisition cap"),
        Error::Limit
    );
}

#[test]
fn configured_directory_symlinks_keep_their_identity() {
    let root = Root::new("symlinks");
    let source = root.0.join("source");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&source)
        .expect("source");
    fs::write(source.join("agentdojo-clean.json"), b"wrong source").expect("source bytes");
    let link = root.0.join("source-link");
    symlink(&source, &link).expect("configured source link");
    let inode = fs::symlink_metadata(&link).expect("link metadata").ino();
    let cache = root.0.join("cache");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&cache)
        .expect("cache");
    let cache_link = root.0.join("cache-link");
    symlink(&cache, &cache_link).expect("configured cache link");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &cache_link, Some(&link), true)
            .expect_err("bytes still checked through links"),
        Error::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    assert_eq!(fs::read_link(&link).expect("source link preserved"), source);
    assert_eq!(
        fs::symlink_metadata(&link).expect("same source link").ino(),
        inode
    );
    assert_eq!(
        fs::read_link(&cache_link).expect("cache link preserved"),
        cache
    );
    let file = root.0.join("file");
    fs::write(&file, b"not a directory").expect("file");
    assert_eq!(
        prepare_agentdojo_episodes(&manifest(), &file, None, true)
            .expect_err("cache directory required"),
        Error::Admission(DatasetErrorKind::Io)
    );
}

#[test]
fn independent_oracle_has_only_metadata_and_complete_existing_notice_pin() {
    let oracle = golden();
    assert_eq!(oracle["episodes"].as_array().expect("two oracles").len(), 2);
    let notice = include_bytes!("fixtures/issue_236/notices/agentdojo-LICENSE");
    assert_eq!(sha(notice), NOTICE);
    for episode in oracle["episodes"].as_array().expect("oracles") {
        assert_eq!(episode["expected"]["message_count"], 7);
        assert_eq!(episode["expected"]["call_count"], 2);
        assert_eq!(episode["expected"]["bound_result_count"], 2);
        assert_eq!(episode["expected"]["license_admission"]["checksum"], NOTICE);
        assert_eq!(episode["expected"]["native_evaluator_polarity"], "unknown");
        let mut expected = episode["expected"].clone();
        expected.sort_all_objects();
        assert_eq!(
            sha(&serde_json::to_vec(&expected).expect("oracle canonical")),
            episode["canonical_sha256"]
        );
    }
}

fn evaluate(episodes: &[AgentDojoEpisode], oracle: &Value) -> Vec<Value> {
    let policy: FirewallPolicy =
        serde_json::from_value(oracle["host_policy"].clone()).expect("independent host policy");
    let goal: TrustedGoal =
        serde_json::from_value(oracle["host_goal"].clone()).expect("independent host goal");
    let mut records = Vec::new();
    let mut supported = 0;
    let mut unsupported = 0;
    for (episode, expected) in episodes
        .iter()
        .zip(oracle["episodes"].as_array().expect("episode goldens"))
    {
        let host: BTreeMap<String, ToolProposal> = expected["host_bindings"]
            .as_object()
            .expect("finite host bindings")
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    ToolProposal::decode(&serde_json::to_vec(value).expect("host wire"))
                        .expect("bounded host proposal"),
                )
            })
            .collect();
        for index in 0..episode.call_count() {
            let fingerprint = episode.call_fingerprint(index).expect("call fingerprint");
            assert_eq!(
                fingerprint,
                expected["expected"]["calls"][index]["fingerprint"]
            );
            if expected["host_expected"][index] == "unsupported_scalar" {
                assert_eq!(
                    episode.project_call(index, &host).err(),
                    Some(AgentDojoProjectionError::UnsupportedScalar)
                );
                unsupported += 1;
                records.push(json!({"fingerprint":fingerprint,"projection":"unsupported_scalar"}));
                continue;
            }
            let proposal = episode
                .project_call(index, &host)
                .expect("source-bound host projection");
            let decision = policy.evaluate(&goal, proposal);
            assert_eq!(
                (decision.decision(), decision.reason()),
                (FirewallDecision::Allow, FirewallReason::LowRisk)
            );
            let mut without_tool = policy.clone();
            without_tool.tools.remove(&proposal.intent.tool_id);
            let denied = without_tool.evaluate(&goal, proposal);
            assert_eq!(
                (denied.decision(), denied.reason()),
                (FirewallDecision::Deny, FirewallReason::Tool)
            );
            let mut without_target = policy.clone();
            without_target.targets.clear();
            let denied = without_target.evaluate(&goal, proposal);
            assert_eq!(
                (denied.decision(), denied.reason()),
                (FirewallDecision::Deny, FirewallReason::StaleTarget)
            );
            for output in [
                serde_json::to_string(proposal).expect("proposal wire"),
                decision.render_json().expect("compact decision"),
            ] {
                assert!(!output.contains("ATTACKER_NATIVE_MARKER"));
            }
            supported += 1;
            records.push(json!({"fingerprint":fingerprint,"decision":decision.render_json().expect("stable decision")}));
        }
    }
    assert_eq!((supported, unsupported), (3, 1));
    records
}

fn canonical(episodes: &[AgentDojoEpisode], oracle: &Value) -> Vec<Vec<u8>> {
    assert_eq!(episodes.len(), 2);
    assert_eq!(
        episodes
            .iter()
            .map(AgentDojoEpisode::message_count)
            .sum::<usize>(),
        14
    );
    assert_eq!(
        episodes
            .iter()
            .map(AgentDojoEpisode::call_count)
            .sum::<usize>(),
        4
    );
    assert_eq!(
        episodes
            .iter()
            .map(AgentDojoEpisode::bound_result_count)
            .sum::<usize>(),
        4
    );
    assert_eq!(episodes[0].family_group_id(), episodes[1].family_group_id());
    episodes
        .iter()
        .zip(oracle["episodes"].as_array().expect("goldens"))
        .map(|(episode, expected)| {
            for report in [episode.source_report(), episode.notice_report()] {
                assert_eq!(
                    report.source_identity().provenance(),
                    DatasetProvenance::Manual
                );
                assert_eq!(report.source_revision(), report.checksum());
                assert_eq!(report.source_identity().origin(), None);
            }
            assert_eq!(episode.notice_report().checksum(), NOTICE);
            let canonical = episode.canonical_json().expect("payload-free canonical");
            assert_eq!(
                serde_json::from_slice::<Value>(&canonical).expect("canonical JSON"),
                expected["expected"]
            );
            assert_eq!(
                episode.canonical_sha256().expect("canonical hash"),
                expected["canonical_sha256"]
            );
            canonical
        })
        .collect()
}

#[test]
#[ignore = "requires explicit retained source directory and private cache parent"]
fn actual_sources_and_two_cache_only_reruns() {
    let source =
        PathBuf::from(std::env::var_os("ADK_DATASET_SOURCE_DIR").expect("explicit local source"));
    let source = validated_dataset_cache_root(&source).expect("checked source target");
    let cache_parent =
        PathBuf::from(std::env::var_os("ADK_DATASET_CACHE_DIR").expect("explicit cache parent"));
    let cache_parent = acceptance_cache_root(&cache_parent).expect("checked cache target");
    let cache = cache_parent.join(format!("agentdojo-actual-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&cache)
        .expect("fresh private cache child");
    let cache = validated_dataset_cache_root(&cache).expect("checked private cache child");
    let registry = manifest();
    let oracle = golden();
    let episodes = prepare_agentdojo_episodes(&registry, &cache, Some(&source), true)
        .expect("actual fixed archives and complete notice admission");
    let first = canonical(&episodes, &oracle);
    let decisions = evaluate(&episodes, &oracle);
    let snapshots = [
        (
            "agentdojo-clean.json",
            "agentdojo-archive-clean",
            episodes[0].source_report().checksum(),
        ),
        (
            "agentdojo-attacked.json",
            "agentdojo-archive-attacked",
            episodes[1].source_report().checksum(),
        ),
        (
            "agentdojo-LICENSE",
            "sentinel-agentdojo-LICENSE",
            episodes[0].notice_report().checksum(),
        ),
    ]
    .map(|(name, id, checksum)| {
        let path = cache.join(id).join(PIN).join("artifact");
        (
            name,
            read_snapshot(&path, checksum).expect("bounded admitted snapshot"),
        )
    });
    // Reuse admitted bytes for privacy controls and negative fixtures; never reopen operator files.
    for (_, bytes) in &snapshots[..2] {
        let native: Value = serde_json::from_slice(bytes).expect("native JSON");
        for message in native["messages"].as_array().expect("native messages") {
            if let Some(calls) = message["tool_calls"].as_array() {
                for call in calls {
                    let id = call["id"].as_str().expect("native ID");
                    let private_strings = call["args"]
                        .as_object()
                        .expect("native args")
                        .values()
                        .filter_map(Value::as_str);
                    for raw in std::iter::once(id).chain(private_strings) {
                        if raw.len() > 4 {
                            for output in first
                                .iter()
                                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                                .chain(decisions.iter().map(Value::to_string))
                            {
                                assert!(!output.contains(raw), "raw native payload excluded");
                            }
                        }
                    }
                }
            }
        }
    }
    for _ in 0..2 {
        let cached = prepare_agentdojo_episodes(&registry, &cache, None, true)
            .expect("cache-only run, internal denied source count must remain zero");
        assert_eq!(canonical(&cached, &oracle), first);
        assert_eq!(evaluate(&cached, &oracle), decisions);
    }
    assert_eq!(
        prepare_agentdojo_episodes(&registry, &cache, None, false)
            .expect_err("warm acceptance still required"),
        Error::LicenseRequired
    );
    let negative = Root::new("actual-controls");
    for (name, bytes) in &snapshots {
        fs::write(negative.0.join(name), bytes).expect("owned exact negative fixture");
    }
    let clean = negative.0.join("agentdojo-clean.json");
    let mut changed = snapshots[0].1.clone();
    let position = changed
        .windows(4)
        .position(|w| w == b"true")
        .expect("native bool");
    changed[position] = b'T';
    fs::write(&clean, changed).expect("same-size changed native bool");
    assert_eq!(
        prepare_agentdojo_episodes(
            &registry,
            &negative.0.join("changed-source-cache"),
            Some(&negative.0),
            true
        )
        .expect_err("fixed source refuses changed label bytes"),
        Error::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    fs::write(&clean, &snapshots[0].1).expect("restore owned exact source");
    let notice = negative.0.join("agentdojo-LICENSE");
    fs::remove_file(&notice).expect("missing notice control");
    assert_eq!(
        prepare_agentdojo_episodes(
            &registry,
            &negative.0.join("missing-notice-cache"),
            Some(&negative.0),
            true
        )
        .expect_err("complete notice required"),
        Error::Admission(DatasetErrorKind::Io)
    );
    fs::write(&notice, b"altered notice").expect("altered notice control");
    assert_eq!(
        prepare_agentdojo_episodes(
            &registry,
            &negative.0.join("altered-notice-cache"),
            Some(&negative.0),
            true
        )
        .expect_err("pinned notice checksum"),
        Error::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    let cached_notice = cache
        .join("sentinel-agentdojo-LICENSE")
        .join(PIN)
        .join("artifact");
    let original = &snapshots[2].1;
    assert_eq!(sha(original), NOTICE);
    fs::write(&cached_notice, b"altered cached notice").expect("cache checksum control");
    assert_eq!(
        prepare_agentdojo_episodes(&registry, &cache, None, true)
            .expect_err("tampered cache refuses"),
        Error::Admission(DatasetErrorKind::ChecksumMismatch)
    );
    fs::write(&cached_notice, original).expect("restore owned admitted notice");
    let receipt = json!({"episodes":2,"messages":14,"calls":4,"bound_results":4,"supported":3,"unsupported_scalar":1,"cache_only_reruns":2,"source_calls":0,"provenance":"manual","canonical_sha256":episodes.iter().map(|episode|episode.canonical_sha256().expect("hash")).collect::<Vec<_>>(),"host_decisions":decisions});
    fs::write(
        cache.join("acceptance.json"),
        serde_json::to_vec_pretty(&receipt).expect("payload-free receipt"),
    )
    .expect("owned acceptance receipt");
    println!(
        "AgentDojo actual acceptance: 2 episodes / 14 messages / 4 calls / 4 results; 3 supported + 1 unsupported float; 2 full cache-only reruns"
    );
}
