use super::*;

fn workflow(root: &Path) -> PathBuf {
    let prompt = b"Return only the routing decision from current mapped input.";
    fs::write(root.join("prompt.md"), prompt).unwrap();
    fs::write(root.join("output.json"), br#"{"type":"string"}"#).unwrap();
    let text = include_str!("../fixtures/issue_361_shared_cycle.toml");
    let path = root.join("workflow.toml");
    fs::write(&path, text).unwrap();
    path
}

fn start(root: &Path) -> Result<ExecutionReceipt, ExecutionError> {
    ExecutionBackend::run(
        workflow(root),
        profile_with(
            vec![
                finish(json!("insufficient")),
                finish(json!("new mapped evidence")),
                finish(json!("sufficient")),
            ],
            Some(loop_policy()),
        ),
        json!({"question":"current"}),
        root,
    )
}

fn assert_cycle(root: &Path) {
    let ledger: Value =
        serde_json::from_slice(&fs::read(root.join("loop-ledger.json")).unwrap()).unwrap();
    let work = &ledger["nodes"]["work"];
    let revise = &ledger["nodes"]["revise"];
    assert_eq!(work["model_iterations"], 2);
    assert_eq!(revise["model_iterations"], 1);
    assert_eq!(work["shared_turns"].as_array().unwrap().len(), 2);
    assert_eq!(revise["shared_turns"].as_array().unwrap().len(), 1);
    assert_eq!(work["shared_turns"][0]["ordinal"], 0);
    assert_eq!(revise["shared_turns"][0]["ordinal"], 1);
    assert_eq!(work["shared_turns"][1]["ordinal"], 2);
    let contents: Vec<adk_rust::Content> =
        serde_json::from_value(work["conversation"].clone()).unwrap();
    let cursor = work["invocation"]["conversation_start"].as_u64().unwrap() as usize;
    let current = &contents[cursor..];
    assert_eq!(
        current.len(),
        8,
        "current preamble + two public turns + new input + own answer"
    );
    let text = serde_json::to_string(current).unwrap();
    assert_eq!(text.matches("insufficient").count(), 1);
    assert_eq!(
        text.matches("new mapped evidence").count(),
        2,
        "prior public answer and current mapped input"
    );
    assert_eq!(current.last().unwrap().role, "assistant");
    assert_eq!(work["finished_output"], "sufficient");
}

#[test]
fn reentry_and_fresh_process_restore_exact_shared_history() {
    const SELECTOR: &str = "shared::reentry_and_fresh_process_restore_exact_shared_history";
    if let Ok(path) = env::var("M3_04_SHARED_CYCLE_ROOT") {
        let root = PathBuf::from(path);
        if env::var_os("M3_04_SHARED_CYCLE_RESUME").is_some() {
            let run_root = find_run(&root);
            let receipt = ExecutionBackend::resume(&root, &run_id(&run_root)).unwrap();
            assert_eq!(receipt.status(), "succeeded");
            return;
        }
        let result = start(&root);
        panic!("intentional barrier did not terminate child: {result:?}");
    }
    let baseline = root();
    let receipt = start(&baseline).unwrap();
    assert_cycle(receipt.run_root());
    for number in [1, 2, 3] {
        let root = root();
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", SELECTOR, "--nocapture"])
            .env("M3_04_SHARED_CYCLE_ROOT", &root.0)
            .env(
                "WORKFLOW_KIT_TEST_CRASH_BARRIER",
                format!("after-model-ledger-persist#{number}"),
            )
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", SELECTOR, "--nocapture"])
            .env("M3_04_SHARED_CYCLE_ROOT", &root.0)
            .env("M3_04_SHARED_CYCLE_RESUME", "1")
            .status()
            .unwrap();
        assert!(status.success(), "resume finish {number}");
        assert_cycle(&find_run(&root));
    }
}

fn find_run(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("run-manifest.json").is_file())
        .unwrap()
}

#[test]
fn shared_reentry_keeps_cumulative_budget_and_cancellation() {
    let root = root();
    let error = ExecutionBackend::run(
        workflow(&root),
        profile_with(
            vec![
                finish(json!("insufficient")),
                finish(json!("new mapped evidence")),
                finish(json!("sufficient")),
            ],
            Some(policy_with("max_model_iterations", 1)),
        ),
        json!({}),
        &root,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::ModelIterationsLimit);
    let ledger: Value = serde_json::from_slice(
        &fs::read(error.receipt().unwrap().run_root().join("loop-ledger.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["nodes"]["work"]["model_iterations"], 1);
    assert_eq!(
        ledger["nodes"]["work"]["shared_turns"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let error = ExecutionBackend::run_cancellable(
        workflow(&root),
        profile_with(vec![finish(json!("sufficient"))], Some(loop_policy())),
        json!({}),
        &root,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Cancelled);
    assert_eq!(effect_count(error.receipt().unwrap().run_root()), 0);
}

#[test]
fn tampered_shared_history_rejects_public_resume_before_effects() {
    let root = root();
    let receipt = start(&root).unwrap();
    let path = receipt.run_root().join("loop-ledger.json");
    let original = fs::read(&path).unwrap();
    for mutation in ["output", "ordinal", "missing"] {
        let mut ledger: Value = serde_json::from_slice(&original).unwrap();
        match mutation {
            "output" => ledger["nodes"]["work"]["shared_turns"][0]["output"] = json!("forged"),
            "ordinal" => ledger["nodes"]["work"]["shared_turns"][1]["ordinal"] = json!(0),
            _ => {
                ledger["nodes"]["work"]["shared_turns"] = json!([]);
            }
        }
        ledger["checkpoint_nodes"] = Value::Null;
        fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        let before = fs::read(receipt.run_root().join("events.jsonl")).unwrap();
        let error = ExecutionBackend::resume(&root, receipt.run_id()).unwrap_err();
        assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
        assert_eq!(effect_count(receipt.run_root()), 0);
        assert_eq!(
            before,
            fs::read(receipt.run_root().join("events.jsonl")).unwrap()
        );
    }
}

#[test]
fn shared_rejects_redacted_skill_history_before_creating_a_run() {
    let root = root();
    let package = root.join("private-skill");
    fs::create_dir(&package).unwrap();
    fs::write(package.join("SKILL.md"), b"---\nname: private-skill\ndescription: Private instructions.\n---\nPrivate skill canary.\n").unwrap();
    use sha2::{Digest, Sha256};
    fs::create_dir(package.join("references")).unwrap();
    let resource = b"Private resource canary.";
    fs::write(package.join("references/guide.txt"), resource).unwrap();
    fs::write(package.join("skill.runtime.toml"), format!("schema_version = 1\n[skill]\nid = \"private-skill\"\nversion = \"1\"\n[[resources]]\nid = \"references/guide.txt\"\nsha256 = \"sha256:{:x}\"\n", Sha256::digest(resource))).unwrap();
    let profile = || {
        ExecutionProfileV1::parse(
            &serde_json::to_vec(&json!({
                "schema_version":1,
                "model":{"provider":"fake","name":"worker","version":"1","model":"worker",
                    "responses":[finish(json!("sufficient"))]},
                "skills":[{"id":"private-skill","version":"1","root":package}],
                "sandbox":{"capabilities":[]}
            }))
            .unwrap(),
        )
        .unwrap()
    };
    let path = workflow(&root);
    let source = fs::read_to_string(&path).unwrap().replace(
        "kind = \"agent\"",
        "kind = \"agent\"\nskills = [{ id = \"private-skill\", version = \"1\" }]",
    );
    fs::write(&path, source).unwrap();
    let before = fs::read_dir(&root).unwrap().count();
    let error = ExecutionBackend::run(&path, profile(), json!({}), &root).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidProfile);
    assert!(error.receipt().is_none());
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        before,
        "reject before run/model/tool materialization"
    );
    // The same valid Skill profile remains supported for explicitly Isolated agents.
    let isolated = fs::read_to_string(&path)
        .unwrap()
        .replace("session = \"shared\"", "session = \"isolated\"");
    fs::write(&path, isolated).unwrap();
    assert_eq!(
        ExecutionBackend::run(path, profile(), json!({}), &root)
            .unwrap()
            .status(),
        "succeeded"
    );
}
