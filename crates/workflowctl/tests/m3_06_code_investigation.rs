use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};

#[path = "support/owned_tree.rs"]
mod owned_tree;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = owned_tree::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn example_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation")
}

fn command(args: &[&str]) -> Output {
    binary()
        .args(args)
        .output()
        .expect("workflowctl must execute")
}

fn temp_root() -> TempRoot {
    let path = std::env::temp_dir().join(format!(
        "m3-06-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).expect("temp root");
    TempRoot(path)
}

fn json_receipt(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "json receipt: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn load_profile() -> Value {
    serde_json::from_slice(&fs::read(example_root().join("profiles/fake.json")).expect("profile"))
        .expect("profile JSON")
}

fn finished(output: &str) -> Value {
    Value::String(format!(r#"{{"status":"finished","output":"{output}"}}"#))
}

fn input_json() -> String {
    fs::read_to_string(example_root().join("input.example.json")).expect("input")
}

fn write_profile(root: &Path, profile: &Value) -> PathBuf {
    let path = root.join("profile.json");
    fs::write(&path, serde_json::to_vec(profile).expect("profile bytes")).expect("write profile");
    path
}

fn run_workflow(workflow: &Path, profile: &Path, workdir: &Path) -> Output {
    command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        profile.to_str().unwrap(),
        "--input",
        input_json().trim(),
        "--workdir",
        workdir.to_str().unwrap(),
    ])
}

fn short_path_profile() -> Value {
    let mut profile = load_profile();
    let responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    let mut next = responses[..6].to_vec();
    next.push(finished("sufficient"));
    next.push(responses[12].clone());
    next.push(responses[13].clone());
    profile["model"]["responses"] = Value::Array(next);
    profile
}

fn event_node_ids(run_root: &Path) -> Vec<String> {
    fs::read_to_string(run_root.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            value.get("node_id")?.as_str().map(str::to_owned)
        })
        .collect()
}

#[test]
fn fake_profile_does_not_embed_tool_results() {
    let profile = load_profile();
    let tools = profile["tools"].as_array().expect("tools");
    assert!(!tools.is_empty(), "example must declare tools");
    for tool in tools {
        assert!(
            tool.get("result").is_none(),
            "runtime profile must not embed a fabricated successful result: {tool}"
        );
    }
}

#[test]
fn canonical_example_composes_skill_runtime() {
    let example = example_root();
    let workflow = fs::read_to_string(example.join("workflow.toml")).expect("workflow");
    let profile = load_profile();
    let runtime = fs::read_to_string(example.join("skills/code-investigation/skill.runtime.toml"))
        .expect("Skill runtime manifest");

    assert!(workflow.contains("skills = [{ id = \"code-investigation\", version = \"1\" }]"));
    assert_eq!(profile["skills"][0]["id"], "code-investigation");
    assert_eq!(profile["skills"][0]["version"], "1");
    assert_eq!(profile["skills"][0]["root"], "skills/code-investigation");
    assert!(runtime.contains("id = \"code-investigation\""));
    assert!(runtime.contains("path = \"scripts/digest.py\""));
    assert!(runtime.contains("input_schema = \"references/investigation-input.json\""));
    assert!(runtime.contains("output_schema = \"references/investigation-output.json\""));
}

#[test]
fn canonical_example_executes_declared_skill_runtime() {
    let mut profile = load_profile();
    profile["model"]["responses"][1] = json!({
        "calls": [
            {"id": "activate-code-investigation", "name": "activate_skill", "args": {"skill_id": "code-investigation"}},
            {"id": "read-grounding", "name": "read_skill_resource", "args": {"skill_id": "code-investigation", "resource_id": "references/grounding.md", "offset": 0, "limit": 4096}}
        ]
    });
    profile["model"]["responses"]
        .as_array_mut()
        .expect("fake model responses")
        .insert(2, json!("{\"status\":\"finished\",\"output\":\"planned\"}"));
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    let run = run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    );
    assert!(
        run.status.success(),
        "Skill runtime run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let receipt = json_receipt(&run);
    let events = fs::read_to_string(
        Path::new(receipt["run_root"].as_str().expect("run_root")).join("events.jsonl"),
    )
    .expect("runtime events");
    assert!(events.contains("activate_skill"));
    assert!(events.contains("read_skill_resource"));
}

fn assert_fail_closed(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("workflow.run.failed"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn canonical_package_validates_graphs_and_locks() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    for relative in [
        "README.md",
        "expected-output.md",
        "input.example.json",
        "profiles/fake.json",
        "replay.json",
        "workflow.toml",
        "prompts/planner.md",
        "prompts/reviewer.md",
        "prompts/reviser.md",
        "schemas/investigation-input.json",
        "schemas/investigation-output.json",
        "skills/code-investigation/SKILL.md",
        "skills/code-investigation/references/grounding.md",
        "skills/code-investigation/references/investigation-input.json",
        "skills/code-investigation/references/investigation-output.json",
        "skills/code-investigation/scripts/digest.py",
        "repo/Cargo.toml",
        "repo/src/lib.rs",
        "repo/src/retry.rs",
    ] {
        assert!(
            example.join(relative).is_file(),
            "missing canonical package file {relative}"
        );
    }

    let validate = command(&["validate", workflow.to_str().unwrap()]);
    assert!(
        validate.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert_eq!(validate.stdout, b"valid\n");

    let graph = command(&["graph", workflow.to_str().unwrap(), "--format", "mermaid"]);
    assert!(
        graph.status.success(),
        "graph failed: {}",
        String::from_utf8_lossy(&graph.stderr)
    );
    let mermaid = String::from_utf8(graph.stdout).expect("mermaid UTF-8");
    for node in [
        "planner",
        "search_code",
        "inspect_evidence",
        "review",
        "revise",
        "publish",
        "abstain",
    ] {
        assert!(mermaid.contains(node), "graph omits {node}");
    }

    let lock = command(&["lock", workflow.to_str().unwrap()]);
    assert!(
        lock.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let lock_toml = String::from_utf8(lock.stdout).expect("lock UTF-8");
    assert!(lock_toml.contains("workflow_id = \"code.investigation\""));
}

#[test]
fn fake_profile_covers_run_inspect_resume_and_replay() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    let profile = example.join("profiles/fake.json");
    let replay = example.join("replay.json");
    let input = fs::read_to_string(example.join("input.example.json")).expect("input");
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");

    let run = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        profile.to_str().unwrap(),
        "--input",
        input.trim(),
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let run_receipt = json_receipt(&run);
    assert_eq!(run_receipt["workflow_id"], "code.investigation");
    assert_eq!(run_receipt["status"], "succeeded");
    assert_eq!(run_receipt["resume_count"], 0);
    let run_id = run_receipt["run_id"].as_str().expect("run_id");

    let inspect = command(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_receipt = json_receipt(&inspect);
    assert_eq!(inspect_receipt["run_id"], run_id);
    assert_eq!(inspect_receipt["status"], "succeeded");

    let resume = command(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert!(
        resume.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let resume_receipt = json_receipt(&resume);
    assert_eq!(resume_receipt["run_id"], run_id);
    assert_eq!(resume_receipt["resume_count"], 1);
    assert_eq!(resume_receipt["status"], "succeeded");

    let replayed = command(&["--json", "replay", replay.to_str().unwrap()]);
    assert!(
        replayed.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_receipt = json_receipt(&replayed);
    assert_eq!(replay_receipt["disposition"], "replay_run");
    assert!(replay_receipt["fixture_count"].as_u64().unwrap() > 0);
}

#[test]
fn fake_profile_covers_revision() {
    let mut profile = short_path_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    responses.push(finished("revised"));
    responses.push(finished("valid"));
    profile["model"]["responses"] = Value::Array(responses);
    profile["reviewer_model"]["responses"] = json!([
        r#"{"status":"finished","output":"revise"}"#,
        r#"{"status":"finished","output":"pass"}"#
    ]);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    let run = run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    );
    assert!(
        run.status.success(),
        "revision run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let receipt = json_receipt(&run);
    assert_eq!(receipt["status"], "succeeded");
    let nodes = event_node_ids(Path::new(receipt["run_root"].as_str().expect("run_root")));
    assert!(nodes.iter().any(|node| node == "revise"), "nodes={nodes:?}");
    assert!(
        nodes.iter().any(|node| node == "publish"),
        "nodes={nodes:?}"
    );
}

#[test]
fn fake_profile_covers_valid_abstention() {
    let mut profile = load_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    responses.truncate(6);
    responses.push(finished("impossible"));
    profile["model"]["responses"] = Value::Array(responses);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    let run = run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    );
    assert!(
        run.status.success(),
        "abstention run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let receipt = json_receipt(&run);
    assert_eq!(receipt["status"], "succeeded");
    let nodes = event_node_ids(Path::new(receipt["run_root"].as_str().expect("run_root")));
    assert!(
        nodes.iter().any(|node| node == "abstain"),
        "nodes={nodes:?}"
    );
    assert!(
        !nodes.iter().any(|node| node == "publish"),
        "valid abstention must not publish, nodes={nodes:?}"
    );
}

#[test]
fn fake_profile_fails_closed_on_invalid_evidence() {
    let mut profile = short_path_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    *responses.last_mut().expect("grounding response") = finished("not-a-verdict");
    profile["model"]["responses"] = Value::Array(responses);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    assert_fail_closed(&run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    ));
}

#[test]
fn fake_profile_fails_closed_on_unknown_route() {
    let mut profile = load_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    responses.truncate(6);
    responses.push(finished("nope"));
    profile["model"]["responses"] = Value::Array(responses);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    assert_fail_closed(&run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    ));
}

#[test]
fn fake_profile_fails_closed_on_malformed_model_output() {
    let mut profile = load_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    responses.truncate(6);
    responses.push(Value::String("not-json{".to_owned()));
    profile["model"]["responses"] = Value::Array(responses);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    assert_fail_closed(&run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    ));
}

#[test]
fn fake_profile_fails_closed_on_denied_tools() {
    let mut profile = load_profile();
    profile["tools"][0]["required_capabilities"] = json!(["network"]);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    let run = run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    );
    assert_fail_closed(&run);
    assert!(
        fs::read_dir(&workdir).expect("workdir").next().is_none(),
        "denied tools must fail before allocating run state"
    );
}

#[test]
fn fake_profile_fails_closed_on_exhausted_review_loop() {
    let mut profile = short_path_profile();
    let mut responses = profile["model"]["responses"]
        .as_array()
        .expect("worker responses")
        .clone();
    responses.push(finished("revised"));
    responses.push(finished("valid"));
    responses.push(finished("revised"));
    responses.push(finished("valid"));
    profile["model"]["responses"] = Value::Array(responses);
    profile["reviewer_model"]["responses"] = json!([
        r#"{"status":"finished","output":"revise"}"#,
        r#"{"status":"finished","output":"revise"}"#
    ]);

    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile_path = write_profile(&root.0, &profile);
    assert_fail_closed(&run_workflow(
        &example_root().join("workflow.toml"),
        &profile_path,
        &workdir,
    ));
}

#[test]
fn fake_profile_fails_closed_on_corrupt_checkpoint() {
    let example = example_root();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let run = run_workflow(
        &example.join("workflow.toml"),
        &example.join("profiles/fake.json"),
        &workdir,
    );
    assert!(
        run.status.success(),
        "seed run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let receipt = json_receipt(&run);
    let run_id = receipt["run_id"].as_str().expect("run_id");
    let run_root = Path::new(receipt["run_root"].as_str().expect("run_root"));
    fs::remove_file(run_root.join("checkpoint.sqlite-wal")).ok();
    fs::remove_file(run_root.join("checkpoint.sqlite-shm")).ok();
    fs::write(run_root.join("checkpoint.sqlite"), b"corrupt checkpoint")
        .expect("corrupt checkpoint");
    let resumed = command(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        workdir.to_str().unwrap(),
    ]);
    assert_fail_closed(&resumed);
}
