use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

const MAX_FIXTURE_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024;

struct TempRoot(PathBuf);

impl TempRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workflowctl"))
}

fn example_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/00-runtime-smoke")
}

fn temp_root(label: &str) -> TempRoot {
    let root = std::env::temp_dir().join(format!(
        "workflowctl-m3-00-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("test root must be unique");
    TempRoot(root)
}

fn command(args: &[&str]) -> Output {
    binary()
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("workflowctl must start: {error}"))
}

fn successful_json(args: &[&str]) -> Value {
    let output = command(args);
    assert!(
        output.status.success(),
        "workflowctl failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "workflowctl stdout must be JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn assert_fixture_safe(path: &Path) -> Vec<u8> {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(!bytes.is_empty(), "{} must not be empty", path.display());
    assert!(
        bytes.len() <= MAX_FIXTURE_BYTES,
        "{} exceeds fixture bound",
        path.display()
    );
    let text = String::from_utf8(bytes.clone()).expect("committed fixture must be UTF-8");
    for forbidden in [
        "/home/",
        "/tmp/",
        "/Users/",
        "C:\\\\",
        "Bearer ",
        "sk-",
        "api_key",
        "password",
        "authorization",
    ] {
        assert!(
            !text.contains(forbidden),
            "{} contains forbidden value {forbidden:?}",
            path.display()
        );
    }
    bytes
}

fn assert_receipt_shape(receipt: &Value) {
    for field in [
        "run_id",
        "workflow_id",
        "status",
        "artifact_id",
        "run_root",
        "plan_hash",
        "resume_identity",
    ] {
        assert!(
            receipt[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "receipt field {field} must be non-empty"
        );
    }
    assert_eq!(receipt["status"], "succeeded");
    assert_eq!(receipt["resume_count"], 0);
    assert!(receipt["run_id"].as_str().unwrap().starts_with("run-"));
    assert_eq!(receipt["workflow_id"], "m3-00-runtime-smoke");
}

fn assert_no_forbidden_bytes(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for forbidden in ["/home/", "/Users/", "Bearer ", "sk-", "api_key", "password"] {
        assert!(
            !text.contains(forbidden),
            "runtime output leaked {forbidden:?}"
        );
    }
}

#[test]
fn runtime_smoke_example_executes_full_provider_free_sequence() {
    let example = example_root();
    let workflow = example.join("workflow.toml");
    let input = example.join("input.example.json");
    let profile = example.join("profiles/fake.json");
    let replay = example.join("replay.json");
    let readme = fs::read_to_string(example.join("README.md")).expect("README");
    let expected = fs::read_to_string(example.join("expected-output.md")).expect("expected output");

    let workflow_bytes = assert_fixture_safe(&workflow);
    let input_bytes = assert_fixture_safe(&input);
    let profile_bytes = assert_fixture_safe(&profile);
    let replay_bytes = assert_fixture_safe(&replay);
    assert_fixture_safe(&example.join("README.md"));
    assert_fixture_safe(&example.join("expected-output.md"));

    assert_eq!(
        serde_json::from_slice::<Value>(&input_bytes).unwrap(),
        json!({"request": "runtime smoke"})
    );
    let profile_value: Value = serde_json::from_slice(&profile_bytes).expect("fake profile JSON");
    assert_eq!(profile_value["model"]["provider"], "fake");
    assert!(
        !profile_value["model"]["responses"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(profile_value["tool"]["name"], "echo");
    assert_eq!(profile_value["sandbox"]["capabilities"], json!([]));
    assert_eq!(
        workflow_bytes.iter().filter(|byte| **byte == b'[').count(),
        7
    );

    let lock_args = &["--json", "lock", workflow.to_str().unwrap()];
    let lock_a = command(lock_args);
    let lock_b = command(lock_args);
    assert!(lock_a.status.success() && lock_b.status.success());
    assert!(!lock_a.stdout.is_empty());
    assert_eq!(lock_a.stdout, lock_b.stdout);

    let replay_value: Value = serde_json::from_slice(&replay_bytes).expect("replay JSON");
    assert_eq!(replay_value["schema_version"], 1);
    assert!(!replay_value["events"].as_array().unwrap().is_empty());
    assert_eq!(replay_value["events"][0]["type"], "node_started");
    assert_eq!(
        replay_value["events"].as_array().unwrap().last().unwrap()["type"],
        "terminal"
    );
    assert_eq!(
        replay_value["workflow_lock"]["toml"],
        String::from_utf8(lock_a.stdout.clone()).unwrap()
    );
    assert_eq!(
        replay_value["workflow_lock"]["sha256"],
        format!("sha256:{:x}", Sha256::digest(&lock_a.stdout))
    );
    assert_eq!(
        replay_value["input_sha256"],
        format!("sha256:{:x}", Sha256::digest(&input_bytes))
    );

    let validate = command(&["--json", "validate", workflow.to_str().unwrap()]);
    assert!(validate.status.success());
    assert_eq!(String::from_utf8_lossy(&validate.stdout), "valid\n");

    let graph = command(&[
        "--json",
        "graph",
        workflow.to_str().unwrap(),
        "--format",
        "mermaid",
    ]);
    assert!(graph.status.success());
    let graph_text = String::from_utf8(graph.stdout).expect("Mermaid graph must be UTF-8");
    assert!(!graph_text.trim().is_empty());
    assert!(graph_text.contains("agent"));
    assert!(graph_text.contains("terminal"));

    let root = temp_root("run");
    let runs = root.path().join("runs");
    fs::create_dir(&runs).expect("run base");
    let input_text = String::from_utf8(input_bytes).expect("input UTF-8");
    let run = successful_json(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        profile.to_str().unwrap(),
        "--input",
        input_text.trim(),
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert_receipt_shape(&run);
    assert!(
        run["run_root"]
            .as_str()
            .unwrap()
            .starts_with(runs.to_str().unwrap())
    );

    let run_root = PathBuf::from(run["run_root"].as_str().unwrap());
    for surface in [
        "workflow.toml",
        "execution-profile.json",
        "execution-input.json",
        "events.jsonl",
        "checkpoint.sqlite",
        "effects.sqlite",
        "run-manifest.json",
    ] {
        assert!(
            run_root.join(surface).is_file(),
            "missing run surface {surface}"
        );
    }
    assert!(run_root.join("artifacts").is_dir());

    let manifest: Value =
        serde_json::from_slice(&fs::read(run_root.join("run-manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    for field in [
        "run_id",
        "status",
        "plan_hash",
        "resume_identity",
        "artifact_id",
    ] {
        assert_eq!(
            manifest[field], run[field],
            "manifest/receipt mismatch for {field}"
        );
    }

    let artifact_id = run["artifact_id"].as_str().unwrap();
    assert_eq!(artifact_id.len(), 64);
    assert!(artifact_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let artifact =
        fs::read(run_root.join("artifacts").join(artifact_id)).expect("terminal artifact");
    assert!(!artifact.is_empty() && artifact.len() <= MAX_ARTIFACT_BYTES);
    assert_eq!(format!("{:x}", Sha256::digest(&artifact)), artifact_id);
    assert_no_forbidden_bytes(&artifact);
    let events = fs::read(run_root.join("events.jsonl")).expect("events");
    assert!(!events.is_empty() && events.len() <= MAX_FIXTURE_BYTES);
    assert_no_forbidden_bytes(&events);

    let run_id = run["run_id"].as_str().unwrap();
    let inspect = successful_json(&[
        "--json",
        "inspect",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert_eq!(inspect, run);

    let resumed = successful_json(&[
        "--json",
        "resume",
        "--run-id",
        run_id,
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert_eq!(resumed["run_id"], run["run_id"]);
    assert_eq!(resumed["plan_hash"], run["plan_hash"]);
    assert_eq!(resumed["resume_identity"], run["resume_identity"]);
    assert_eq!(resumed["resume_count"], 1);
    assert_eq!(resumed["status"], "succeeded");

    let replay_result = successful_json(&["--json", "replay", replay.to_str().unwrap()]);
    assert_eq!(replay_result["disposition"], "replay_run");
    assert!(replay_result["fixture_count"].as_u64().unwrap() > 0);
    assert_eq!(
        replay_result["payload_len"].as_u64().unwrap(),
        replay_bytes.len() as u64
    );
    assert!(replay_result.get("run_id").is_none());

    let missing_profile = root.path().join("missing-profile.json");
    let missing = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        missing_profile.to_str().unwrap(),
        "--input",
        input_text.trim(),
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert!(!missing.status.success());

    let invalid_profile = root.path().join("invalid-profile.json");
    fs::write(&invalid_profile, b"{}").expect("invalid profile");
    let invalid = command(&[
        "--json",
        "run",
        workflow.to_str().unwrap(),
        "--profile",
        invalid_profile.to_str().unwrap(),
        "--input",
        input_text.trim(),
        "--workdir",
        runs.to_str().unwrap(),
    ]);
    assert!(!invalid.status.success());

    let required_sequence = [
        "validate",
        "graph --format mermaid",
        "lock",
        "run --profile",
        "inspect",
        "resume",
        "replay",
    ];
    let mut previous = 0;
    for step in required_sequence {
        let position = readme
            .find(step)
            .unwrap_or_else(|| panic!("README missing {step}"));
        assert!(
            position >= previous,
            "README command sequence is out of order"
        );
        previous = position;
    }
    assert!(readme.contains("runtime smoke example"));
    assert!(readme.contains("model-directed multi-tool"));
    assert!(readme.contains("committed redacted replay bundle"));
    assert!(expected.contains("<run-id>"));
    assert!(expected.contains("<run-root>"));
    assert!(expected.contains("<artifact-id>"));
}
