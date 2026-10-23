//! Pure policy fixtures are not cross-revision execution evidence.
use super::*;

fn fixture(revision: &str) -> Campaign {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut registry = journal::registry(&repo).unwrap();
    for case in &mut registry {
        case.manifest.source_revision = revision.to_owned();
    }
    Campaign {
        config: None,
        split: Split {
            schema_version: 1,
            tuning: vec!["downstream-consumer".to_owned(), "runtime-smoke".to_owned()],
            holdout: vec![
                "code-investigation".to_owned(),
                "minimal-template".to_owned(),
            ],
        },
        registry,
    }
}
#[test]
fn threshold_is_strict_exact_and_overflow_safe() {
    assert!(!exceeds(10_000, 10_100, 100));
    assert!(exceeds(10_000, 10_101, 100));
    assert!(!exceeds(10_000, 9_999, 0));
    assert!(!exceeds(10_000, 10_000, 0));
    assert!(exceeds(10_000, 10_001, 0));
    assert!(!exceeds(u64::MAX, u64::MAX, u32::MAX));
    assert!(exceeds(1, u64::MAX, u32::MAX));
}
#[test]
fn fixture_pairs_reject_same_revision_and_every_control_mismatch() {
    let a = fixture("baseline-fixture");
    let mut b = fixture("candidate-fixture");
    assert!(compatible(&a, &b, false).is_ok());
    b.registry[0].manifest.source_revision = "baseline-fixture".to_owned();
    assert!(compatible(&a, &b, false).is_err());
    for field in [
        "workflow_digest",
        "config_digest",
        "model_digest",
        "dataset_digest",
    ] {
        let mut value = serde_json::to_value(fixture("candidate-fixture")).unwrap();
        value["registry"][0]["manifest"][field] = json!("foreign");
        let changed: Campaign = serde_json::from_value(value).unwrap();
        assert!(compatible(&a, &changed, false).is_err(), "{field}");
    }
    let mut b = fixture("candidate-fixture");
    b.split.tuning.swap(0, 1);
    assert!(compatible(&a, &b, false).is_err());
    b.split = Split {
        schema_version: 1,
        tuning: vec!["runtime-smoke".to_owned()],
        holdout: vec![
            "downstream-consumer".to_owned(),
            "code-investigation".to_owned(),
            "minimal-template".to_owned(),
        ],
    };
    assert!(compatible(&a, &b, false).is_err());
    b.registry[0].manifest.dataset_digest = b.registry[3].manifest.dataset_digest.clone();
    assert!(validate_split(&b.split, &b.registry).is_err());
}
#[test]
fn committed_source_checks_object_tree_contents_and_inputs_without_checkout() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let revision = git(&repo, &["rev-parse", "HEAD"]).unwrap();
    for malformed in [
        "HEAD",
        "-x",
        "../HEAD",
        "0000000000000000000000000000000000000000",
    ] {
        assert!(committed_files(&repo, malformed).is_err());
    }
    let files = committed_files(&repo, &revision).unwrap();
    let mut h = Sha256::new();
    for (name, bytes) in &files {
        h.update((name.len() as u64).to_le_bytes());
        h.update(name);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    let expected = format!("sha256:{:x}", h.finalize());
    // A source-proven identity fixture, not a report or measured execution.
    // Build the identity fixture from committed blobs, including workflows edited in this worktree.
    let mut campaign = fixture(&revision);
    for case in &mut campaign.registry {
        case.manifest.source_files_digest = expected.clone();
        case.manifest.workflow_digest = digest(files.get(&case.workflow.source).unwrap());
        case.manifest.config_digest = None;
        case.manifest.model_digest = None;
        case.manifest.dataset_digest = None;
        if let Some((profile, input)) = scripted_inputs_with(&case.workflow.source, |path| {
            serde_json::from_slice(files.get(path).unwrap()).map_err(error)
        })
        .unwrap()
        {
            bind_inputs(&mut case.manifest, &profile, &input).unwrap();
        }
    }
    source(&repo, &campaign).unwrap();
    let config: super::super::config::Config = serde_json::from_value(json!({"schema_version":1,"loop_policy":{"schema_version":1,"max_model_iterations":20,"max_total_tool_calls":20,"max_tool_calls_per_tool":20,"wall_time_ms":60000,"idle_time_ms":30000,"tool_time_ms":10000,"max_tool_output_bytes":65536}})).unwrap();
    let mut configured: Campaign =
        serde_json::from_value(serde_json::to_value(&campaign).unwrap()).unwrap();
    for case in &mut configured.registry {
        if let Some((mut profile, input)) = scripted_inputs_with(&case.workflow.source, |path| {
            serde_json::from_slice(files.get(path).unwrap()).map_err(error)
        })
        .unwrap()
        {
            config.apply(&mut profile).unwrap();
            bind_inputs(&mut case.manifest, &profile, &input).unwrap();
        }
    }
    configured.config = Some(config);
    source(&repo, &configured).expect("explicit config is reconstructed over committed profiles");
    let mut foreign = serde_json::to_value(&configured).unwrap();
    foreign["registry"][1]["manifest"]["source_revision"] = json!("foreign-later-row");
    assert!(source(&repo, &serde_json::from_value(foreign).unwrap()).is_err());
    let supported = campaign
        .registry
        .iter()
        .zip(&configured.registry)
        .filter(|(a, _)| a.manifest.config_digest.is_some())
        .collect::<Vec<_>>();
    assert!(!supported.is_empty());
    for (a, b) in supported {
        assert_ne!(a.manifest.config_digest, b.manifest.config_digest);
    }
    for field in [
        "source_tree",
        "source_files_digest",
        "workflow_digest",
        "config_digest",
        "model_digest",
        "dataset_digest",
    ] {
        let mut value = serde_json::to_value(&campaign).unwrap();
        value["registry"][0]["manifest"][field] = json!("foreign");
        let changed: Campaign = serde_json::from_value(value).unwrap();
        assert!(source(&repo, &changed).is_err(), "{field}");
    }
    for case in &mut campaign.registry {
        case.manifest.executable_digest.clear();
    }
    assert!(
        source(&repo, &campaign).is_err(),
        "missing executable identity"
    );
}
#[test]
fn config_only_fixtures_hold_source_binary_workload_and_split_fixed() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let build = |iterations| {
        let mut campaign = fixture("same-source-fixture");
        let config = serde_json::from_value(json!({"schema_version":1,"loop_policy":{"schema_version":1,"max_model_iterations":iterations,"max_total_tool_calls":20,"max_tool_calls_per_tool":20,"wall_time_ms":60000,"idle_time_ms":30000,"tool_time_ms":10000,"max_tool_output_bytes":65536}})).unwrap();
        campaign.registry = super::super::config::registry(&repo, Some(&config)).unwrap();
        campaign.config = Some(config);
        campaign
    };
    let a = build(20);
    let b = build(30);
    assert!(compatible(&a, &b, true).is_ok());
    assert!(compatible(&a, &b, false).is_err());
    assert!(compatible(&a, &a, true).is_err());
    assert!(compatible(&a, &fixture("same-source-fixture"), true).is_err());
    for field in [
        "source_revision",
        "source_tree",
        "source_files_digest",
        "executable_digest",
        "workflow_digest",
        "model_digest",
        "dataset_digest",
    ] {
        let mut value = serde_json::to_value(&b).unwrap();
        value["registry"][0]["manifest"][field] = json!("foreign");
        let changed: Campaign = serde_json::from_value(value).unwrap();
        assert!(compatible(&a, &changed, true).is_err(), "{field}");
    }
    let mut changed = build(30);
    changed.split.tuning.swap(0, 1);
    assert!(compatible(&a, &changed, true).is_err());
}

#[test]
fn plan_admission_is_one_shot_and_digest_bound() {
    let root = output_path().unwrap();
    fs::create_dir(&root).unwrap();
    let plan = Plan {
        schema_version: 1,
        baseline: root.with_extension("baseline"),
        candidate: root.clone(),
        baseline_campaign_digest: "fixture".to_owned(),
        candidate_campaign_digest: "fixture".to_owned(),
        baseline_cases_digest: "fixture".to_owned(),
        max_regression_bps: 100,
        config_only: false,
    };
    atomic(&root, "comparison.json", &plan).unwrap();
    let initial = admission(&root, SuiteMode::Regression, 0).unwrap();
    assert_eq!(initial, Some(hash(&plan).unwrap()));
    for mode in [SuiteMode::Adaptive, SuiteMode::Soak, SuiteMode::SealedFinal] {
        assert!(admission(&root, mode, 0).is_err());
    }
    assert!(admission(&root, SuiteMode::Regression, 1).is_err());
    let mut plan = plan;
    plan.config_only = true;
    atomic(&root, "comparison.json", &plan).unwrap();
    assert_ne!(admission(&root, SuiteMode::Regression, 0).unwrap(), initial);
    plan.config_only = false;
    plan.max_regression_bps += 1;
    atomic(&root, "comparison.json", &plan).unwrap();
    assert_ne!(admission(&root, SuiteMode::Regression, 0).unwrap(), initial);
    fs::remove_dir_all(root).unwrap();
}
