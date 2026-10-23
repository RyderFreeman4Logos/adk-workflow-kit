use super::*;

fn authored_workflow(root: &Path) -> PathBuf {
    let prompt = b"Use only mapped input and declared skill tools. Return the checked result.";
    fs::write(root.join("prompt.md"), prompt).unwrap();
    fs::write(root.join("output.json"), br#"{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}"#).unwrap();
    let workflow = WORKFLOW.replace(
        "skills = [{ id = \"code-investigation\", version = \"1\" }]",
        &format!("skills = [{{ id = \"code-investigation\", version = \"1\" }}]\ninstruction = {{ path = \"prompt.md\", sha256 = \"sha256:{:x}\" }}\ninput = {{ state_keys = [\"input\"] }}\noutput = {{ state_key = \"node:work\", schema = \"output.json\" }}\nsession = \"isolated\"", Sha256::digest(prompt)),
    );
    let workflow = format!(
        "{workflow}\n[state]\nschema_id = \"isolated-skill\"\nschema_version = \"1\"\nrequired_keys = [\"input\"]\n[state.keys.input]\nschema_id = \"json\"\nschema_version = \"1\"\n[state.keys.\"node:work\"]\nschema_id = \"json\"\nschema_version = \"1\"\n"
    );
    let path = root.join("workflow.toml");
    fs::write(&path, workflow).unwrap();
    path
}

#[test]
fn fresh_isolated_run_does_not_publish_resume() {
    let root = root();
    skill_package(&root);
    let receipt = ExecutionBackend::run(
        authored_workflow(&root),
        resume_profile(&root.join("code-investigation")),
        json!({"current":"mapped"}),
        &root,
    )
    .unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    let kinds = events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"].clone())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&json!("workflow_started")));
    assert!(
        !kinds.contains(&json!("workflow_resumed")),
        "a fresh run has no recovery to report: {kinds:?}"
    );
    cleanup_test_root(&root);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn isolated_skill_crash_reconstructs_current_admitted_turns() {
    const SELECTOR: &str = "isolated::isolated_skill_crash_reconstructs_current_admitted_turns";
    if let Ok(path) = env::var("M3_05_ISOLATED_SKILL_CRASH_ROOT") {
        let root = PathBuf::from(path);
        let workflow = authored_workflow(&root);
        let result = ExecutionBackend::run(
            &workflow,
            resume_profile(&root.join("code-investigation")),
            json!({"current":"mapped"}),
            &root,
        );
        panic!("intentional crash barrier did not terminate child: {result:?}");
    }
    for barrier in [
        "after-skill-call-admission",
        "after-skill-call-completion-read_skill_resource",
    ] {
        let root = root();
        skill_package(&root);
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", SELECTOR, "--nocapture"])
            .env("M3_05_ISOLATED_SKILL_CRASH_ROOT", &root)
            .env("WORKFLOW_KIT_TEST_CRASH_BARRIER", barrier)
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "expected intentional crash: {barrier}"
        );
        let run_root = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("run-manifest.json").is_file())
            .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).unwrap()).unwrap();
        let receipt =
            ExecutionBackend::resume(&root, manifest["run_id"].as_str().unwrap()).unwrap();
        assert_eq!(receipt.status(), "succeeded", "{barrier}");
        let ledger: serde_json::Value =
            serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
        let state = &ledger["nodes"]["work"];
        assert_eq!(
            state["model_iterations"], 4,
            "accepted model turns never repeat: {barrier}"
        );
        assert_eq!(state["total_tool_calls"], 3);
        assert_eq!(state["completed_calls"].as_array().unwrap().len(), 3);
        assert_eq!(
            state["conversation"],
            json!([]),
            "raw skill history remains private"
        );
        assert_eq!(state["invocation"]["model_iteration_start"], 0);
        assert_paired_skill_transcript(&ledger);
        cleanup_test_root(&root);
        fs::remove_dir_all(root).unwrap();
    }
}
