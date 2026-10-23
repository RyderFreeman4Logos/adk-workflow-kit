//! Public offline experiment: runtime receipts, not synthetic cache labels.
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::PathBuf, process::Command};

fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cache230-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bench-230"))
}
fn read(path: impl AsRef<std::path::Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn run(root: &std::path::Path, resume: bool) -> std::process::Output {
    command()
        .arg(if resume {
            "cache-resume"
        } else {
            "cache-experiment"
        })
        .arg(root)
        .output()
        .unwrap()
}

fn run_ids(report: &Value) -> BTreeSet<&str> {
    report["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["case"]["admitted_run_id"].as_str().unwrap())
        .collect()
}

fn snapshot(root: &std::path::Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    files
}

#[test]
fn measured_cache_experiment_classifies_receipts_and_rejects_tampering() {
    let root = scratch();
    let output = run(&root, false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["evidence_kind"], "scripted_content_cache_execution");
    assert_eq!(report["live_executed"], false);
    assert!(report["kv_cache_hit"].is_null());
    let rows = report["observations"].as_array().unwrap();
    assert_eq!(rows.len(), 18);
    let ids: BTreeSet<_> = rows
        .iter()
        .map(|r| r["case"]["admitted_run_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids.len(),
        rows.len(),
        "every observation executes a distinct real run"
    );
    for row in rows {
        assert_eq!(row["case"]["status"], "succeeded");
        assert!(row["case"]["elapsed_ns"].as_u64().unwrap() > 0);
        let receipt = &row["case"]["receipt"];
        let expected = match receipt["cache_dispositions"]["agent"].as_str().unwrap() {
            "recorded" => "cold",
            "reused" => "warm",
            "reexecuted" => "reexecuted",
            other => panic!("unexpected disposition {other}"),
        };
        assert_eq!(row["content_cache_class"], expected);
        let events = fs::read_to_string(
            PathBuf::from(receipt["run_root"].as_str().unwrap()).join("events.jsonl"),
        )
        .unwrap();
        let turns = events
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|e| e["kind"] == "model_request_completed")
            .count();
        assert_eq!(
            receipt["event_counts"]["model_turns"].as_u64().unwrap(),
            turns as u64
        );
        if expected == "warm" {
            assert_eq!(turns, 0);
        } else {
            assert!(turns > 0);
        }
    }
    for (index, class) in [
        (0, "cold"),
        (1, "warm"),
        (2, "cold"),
        (3, "warm"),
        (4, "warm"),
        (15, "cold"),
        (16, "warm"),
        (17, "cold"),
    ] {
        assert_eq!(
            rows[index]["content_cache_class"], class,
            "observation {index}"
        );
    }
    assert_eq!(rows[0]["case"]["manifest"], rows[1]["case"]["manifest"]);
    assert_ne!(
        rows[0]["case"]["manifest"]["dataset_digest"],
        rows[2]["case"]["manifest"]["dataset_digest"]
    );
    assert!(rows[17]["removed_entries"].as_u64().unwrap() > 0);
    assert!(
        rows[5..15]
            .iter()
            .any(|r| r["removed_entries"].as_u64().unwrap() > 0)
    );
    assert!(
        rows[5..15]
            .iter()
            .all(|r| r["cache_entries_after"].as_u64().unwrap() <= 1)
    );
    let pairs = report["paired_comparisons"]
        .as_array()
        .expect("measured same-input arm comparisons");
    assert_eq!(pairs.len(), 10);
    for pair in pairs {
        let left = &rows[pair["control_step"].as_u64().unwrap() as usize];
        let right = &rows[pair["treatment_step"].as_u64().unwrap() as usize];
        assert_eq!(left["case"]["manifest"], right["case"]["manifest"]);
        assert_eq!(
            pair["elapsed_delta_ns"].as_i64().unwrap(),
            right["case"]["elapsed_ns"].as_i64().unwrap()
                - left["case"]["elapsed_ns"].as_i64().unwrap()
        );
    }
    assert_eq!(
        run(&root, true).stdout,
        output.stdout,
        "resume must preserve measured observations"
    );
    let saved = fs::read(root.join("observation-1.json")).unwrap();
    for (field, value) in [
        ("content_cache_class", json!("cold")),
        ("removed_entries", json!(999)),
    ] {
        let mut forged: Value = serde_json::from_slice(&saved).unwrap();
        forged[field] = value;
        fs::write(
            root.join("observation-1.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert!(!run(&root, true).status.success());
    }
    for pointer in [
        "/case/receipt/event_counts/model_turns",
        "/case/manifest/config_digest",
        "/case/manifest/model_digest",
        "/case/manifest/dataset_digest",
    ] {
        let mut forged: Value = serde_json::from_slice(&saved).unwrap();
        *forged.pointer_mut(pointer).unwrap() = if pointer.ends_with("model_turns") {
            json!(999)
        } else {
            json!("foreign")
        };
        fs::write(
            root.join("observation-1.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert!(!run(&root, true).status.success());
    }
    fs::write(root.join("observation-1.json"), saved).unwrap();
    let plan_path = root.join("experiment.json");
    let saved = fs::read(&plan_path).unwrap();
    let mut forged: Value = serde_json::from_slice(&saved).unwrap();
    forged["trust_domain"] = json!("foreign");
    fs::write(&plan_path, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(!run(&root, true).status.success());
    fs::write(plan_path, saved).unwrap();
    assert_eq!(run(&root, true).stdout, output.stdout);
    // A completed-prefix fixture exercises only-unstarted recovery. The separate
    // killed-child test proves real interruption is fail-closed, not replayable.
    let discarded = root.join("discarded-suffix");
    fs::create_dir(&discarded).unwrap();
    for arm in [
        "capacity-one-grouped",
        "capacity-one-interleaved",
        "explicit-invalidation",
    ] {
        fs::rename(root.join(arm), discarded.join(arm)).unwrap();
    }
    for index in 5..18 {
        for prefix in ["admission", "observation"] {
            let name = format!("{prefix}-{index}.json");
            fs::rename(root.join(&name), discarded.join(name)).unwrap();
        }
    }
    let recovered = run(&root, true);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    let recovered_rows = recovered["observations"].as_array().unwrap();
    assert_eq!(&recovered_rows[..5], &rows[..5]);
    assert!(
        recovered_rows[5..]
            .iter()
            .all(|r| !ids.contains(r["case"]["admitted_run_id"].as_str().unwrap()))
    );
    assert_eq!(recovered_rows.len(), rows.len());
    let cache =
        workflow_runtime::NodeResultCache::open(root.join("unbounded-grouped/.node-result-cache"))
            .unwrap();
    assert!(
        cache
            .gc(workflow_runtime::NodeCacheRetention {
                max_entries: Some(0)
            })
            .unwrap()
            > 0
    );
    let rejected = run(&root, true);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("cache state changed"));
}

#[test]
fn killed_cache_run_never_becomes_a_warm_observation_on_resume() {
    use std::os::unix::process::ExitStatusExt;
    let root = scratch();
    let output = command()
        .arg("cache-experiment")
        .arg(&root)
        .env(
            "WORKFLOW_KIT_TEST_CRASH_BARRIER",
            "after-model-ledger-persist#3",
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.signal(),
        Some(9),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let admission = read(root.join("admission-2.json"));
    assert!(admission["run_id"].as_str().unwrap().starts_with("run-"));
    assert!(!root.join("observation-2.json").exists());
    let runtime_before = snapshot(&root.join("unbounded-grouped"));
    let before = fs::read(root.join("admission-2.json")).unwrap();
    let resumed = run(&root, true);
    assert_eq!(resumed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("in-flight"));
    assert_eq!(fs::read(root.join("admission-2.json")).unwrap(), before);
    assert_eq!(
        snapshot(&root.join("unbounded-grouped")),
        runtime_before,
        "resume must not replay effects or write cache entries"
    );
    assert!(!root.join("admission-3.json").exists());
    assert_eq!(
        read(root.join("observation-0.json"))["content_cache_class"],
        "cold"
    );
    assert_eq!(
        read(root.join("observation-1.json"))["content_cache_class"],
        "warm"
    );
}

// Crash after the next arm directory exists and before its admission. The
// directory alone is not an in-flight run and must not trap resume.
#[test]
fn crash_after_unadmitted_arm_directory_resumes_without_duplicate_runs() {
    unadmitted_arm_resumes("after-cache-arm-dir-before-admission#2", false);
}

#[test]
fn crash_after_unadmitted_cache_open_resumes_without_duplicate_runs() {
    unadmitted_arm_resumes("after-cache-open-before-admission#2", true);
}

fn unadmitted_arm_resumes(barrier: &str, initialized: bool) {
    use std::os::unix::process::ExitStatusExt;
    let root = scratch();
    let output = command()
        .arg("cache-experiment")
        .arg(&root)
        .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier)
        .output()
        .unwrap();
    assert_eq!(
        output.status.signal(),
        Some(9),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let arm = root.join("capacity-one-grouped");
    assert!(
        arm.is_dir(),
        "crash must persist the unadmitted arm directory"
    );
    assert!(!root.join("admission-5.json").exists());
    assert_eq!(arm.join(".node-result-cache").exists(), initialized);
    if initialized {
        assert!(
            fs::read_dir(arm.join(".node-result-cache/entries"))
                .unwrap()
                .next()
                .is_none()
        );
    }
    let prefix: Vec<_> = (0..5)
        .map(|index| read(root.join(format!("observation-{index}.json"))))
        .collect();
    let prefix_report = json!({"observations": prefix});
    let prefix_ids = run_ids(&prefix_report);
    assert_eq!(prefix_ids.len(), 5);
    let recovered = run(&root, true);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    let rows = recovered["observations"].as_array().unwrap();
    assert_eq!(&rows[..5], prefix.as_slice());
    let ids = run_ids(&recovered);
    assert_eq!(ids.len(), rows.len());
    assert!(prefix_ids.is_subset(&ids));
    assert_eq!(rows.len(), 18);
    let fresh = scratch();
    let changed = command()
        .arg("cache-experiment")
        .arg(&fresh)
        .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier)
        .output()
        .unwrap();
    assert_eq!(changed.status.signal(), Some(9));
    let planted = fresh.join("capacity-one-grouped/foreign");
    fs::write(&planted, b"x").unwrap();
    let before = snapshot(&fresh);
    let rejected = run(&fresh, true);
    assert_eq!(rejected.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("unexpected"), "{stderr}");
    assert_eq!(
        snapshot(&fresh),
        before,
        "rejection must not mutate the experiment"
    );
    fs::remove_file(&planted).unwrap();
    if initialized {
        let arm = fresh.join("capacity-one-grouped");
        let cache = arm.join(".node-result-cache");
        let entries = cache.join("entries");
        let reject_unchanged = || {
            let before = snapshot(&fresh);
            let rejected = run(&fresh, true);
            assert_eq!(rejected.status.code(), Some(1));
            let stderr = String::from_utf8_lossy(&rejected.stderr);
            assert!(stderr.contains("unexpected"), "{stderr}");
            assert!(!fresh.join("admission-5.json").exists());
            assert_eq!(snapshot(&fresh), before);
        };
        // Real entry from the completed arm, not merely an arbitrary file.
        let source = fs::read_dir(fresh.join("unbounded-grouped/.node-result-cache/entries"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let planted = entries.join(source.file_name().unwrap());
        fs::copy(&source, &planted).unwrap();
        reject_unchanged();
        fs::remove_file(planted).unwrap();
        for directory in [&cache, &entries] {
            let foreign = directory.join("foreign");
            fs::write(&foreign, b"keep").unwrap();
            reject_unchanged();
            fs::remove_file(foreign).unwrap();
        }
        // No links at any scaffold level, even to an otherwise empty owned directory.
        for directory in [&arm, &cache, &entries] {
            let saved = scratch();
            fs::rename(directory, &saved).unwrap();
            std::os::unix::fs::symlink(&saved, directory).unwrap();
            reject_unchanged();
            assert!(
                fs::symlink_metadata(directory)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            fs::remove_file(directory).unwrap();
            fs::rename(saved, directory).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        for directory in [&arm, &cache, &entries] {
            let permissions = fs::metadata(directory).unwrap().permissions();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o777)).unwrap();
            reject_unchanged();
            fs::set_permissions(directory, permissions).unwrap();
        }
        // An interrupted create_dir_all may have created only the cache root.
        fs::remove_dir(entries).unwrap();
        let recovered = run(&fresh, true);
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
    }
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(fresh);
}
