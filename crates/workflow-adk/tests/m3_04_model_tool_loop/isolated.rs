use super::*;
use sha2::{Digest, Sha256};

fn workflow(root: &Path) -> PathBuf {
    let prompt = b"Return only the routing decision from current mapped input.";
    fs::write(root.join("prompt.md"), prompt).unwrap();
    fs::write(
        root.join("decision.json"),
        br#"{"type":"string","enum":["insufficient","sufficient","impossible"]}"#,
    )
    .unwrap();
    let contract = format!(
        "instruction = {{ path = \"prompt.md\", sha256 = \"sha256:{:x}\" }}\ninput = {{ state_keys = [\"input\", \"node:revise\"] }}\noutput = {{ state_key = \"node:work\", schema = \"decision.json\" }}\nsession = \"isolated\"",
        Sha256::digest(prompt)
    );
    let text = format!(
        r#"
schema_version = 1
[workflow]
id = "isolated-cycle"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = {{ role = "worker", id = "worker", version = "1" }}
max_visits = 3
{contract}
[[nodes]]
id = "revise"
kind = "agent"
model = {{ role = "worker", id = "worker", version = "1" }}
max_visits = 1
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "revise"
to = "work"
[[routes]]
from = "work"
predicate = {{ id = "coverage.decision@v1", version = "1.0.0" }}
cases = {{ insufficient = "revise", sufficient = "done", impossible = "done" }}
[state]
schema_id = "isolated-cycle"
schema_version = "1"
required_keys = ["input"]
[state.keys.input]
schema_id = "json"
schema_version = "1"
[state.keys."node:work"]
schema_id = "json"
schema_version = "1"
[state.keys."node:revise"]
schema_id = "json"
schema_version = "1"
"#
    );
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

fn assert_cycle(run_root: &Path) {
    let ledger: Value =
        serde_json::from_slice(&fs::read(run_root.join("loop-ledger.json")).unwrap()).unwrap();
    let state = &ledger["nodes"]["work"];
    assert_eq!(state["model_iterations"], 2, "accepted visits never repeat");
    assert_eq!(ledger["nodes"]["revise"]["model_iterations"], 1);
    assert_eq!(state["finished_output"], "sufficient");
    let contents: Vec<adk_rust::Content> =
        serde_json::from_value(state["conversation"].clone()).unwrap();
    let cursor = state["invocation"]["conversation_start"].as_u64().unwrap() as usize;
    assert!(cursor > 0, "cumulative proof keeps the first visit");
    let current = &contents[cursor..];
    // Official LlmAgent prepends instruction and schema as user Contents.
    assert_eq!(
        current.len(),
        4,
        "two preambles, current input and its answer"
    );
    assert!(current[..3].iter().all(|content| content.role == "user"));
    assert_eq!(current[3].role, "assistant");
    assert!(
        current
            .iter()
            .flat_map(|content| &content.parts)
            .all(|part| matches!(part, adk_rust::Part::Text { .. }))
    );
    let text = current[2].parts[0].text().unwrap();
    let mapped: Value = serde_json::from_str(text).unwrap();
    assert_eq!(mapped["node:revise"], "new mapped evidence");
    let answer: Value = serde_json::from_str(current[3].parts[0].text().unwrap()).unwrap();
    assert_eq!(answer, json!({"status":"finished", "output":"sufficient"}));
    assert_eq!(state["total_tool_calls"], 0);
    let events = fs::read_to_string(run_root.join("events.jsonl")).unwrap();
    assert!(
        events.lines().any(
            |line| serde_json::from_str::<Value>(line).unwrap()["kind"] == "workflow_completed"
        )
    );
}

#[test]
fn cycle_reentry_and_fresh_process_finish_recovery() {
    const SELECTOR: &str = "isolated::cycle_reentry_and_fresh_process_finish_recovery";
    if let Ok(path) = env::var("M3_04_ISOLATED_CYCLE_ROOT") {
        let root = PathBuf::from(path);
        if env::var_os("M3_04_ISOLATED_CYCLE_RESUME").is_some() {
            let run_root = fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.join("run-manifest.json").is_file())
                .unwrap();
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
    // First finish, the predecessor before reentry, then the repeated finish.
    for number in [1, 2, 3] {
        let root = root();
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", SELECTOR, "--nocapture"])
            .env("M3_04_ISOLATED_CYCLE_ROOT", &root.0)
            .env(
                "WORKFLOW_KIT_TEST_CRASH_BARRIER",
                format!("after-model-ledger-persist#{number}"),
            )
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", SELECTOR, "--nocapture"])
            .env("M3_04_ISOLATED_CYCLE_ROOT", &root.0)
            .env("M3_04_ISOLATED_CYCLE_RESUME", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "fresh process resumes accepted finish {number}"
        );
        let run_root = fs::read_dir(&root.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("run-manifest.json").is_file())
            .unwrap();
        assert_cycle(&run_root);
        let events = fs::read_to_string(run_root.join("events.jsonl")).unwrap();
        assert!(
            events
                .lines()
                .any(|line| serde_json::from_str::<Value>(line).unwrap()["kind"]
                    == "workflow_resumed")
        );
    }
}
