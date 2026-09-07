use std::{
    error::Error,
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
use workflow_compiler::{WorkflowLock, compile_file};
use workflow_runtime::{
    ArtifactId, ArtifactStore, EffectJournal, EffectKey, FilesystemArtifactStore, PageRequest,
    WorkflowRuntimeEventKindV1, WorkflowRuntimeEventV1, argument_fingerprint,
};
use workflow_testkit::ReplayBundle;

const PIN: &str = "026b883a58bab6cc2d0c8610b44e3983e6017cb8";

fn require(
    checks: &mut Vec<&'static str>,
    label: &'static str,
    condition: bool,
) -> Result<(), Box<dyn Error>> {
    if !condition {
        return Err(format!("check failed: {label}").into());
    }
    checks.push(label);
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn read(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)
}

fn field(receipt: &Value, name: &str) -> String {
    receipt
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("missing logical consumer root")?,
    );
    let workdir_base = PathBuf::from(
        std::env::args()
            .nth(2)
            .ok_or("missing prepared temporary base")?,
    );
    if !root.is_absolute()
        || fs::canonicalize(&root)? != fs::canonicalize(env!("CARGO_MANIFEST_DIR"))?
    {
        return Err("consumer root differs from compiled manifest root".into());
    }
    let expected_target = format!("/ssd/mirror-rootfs{}/target", root.display());
    let fixtures = root.join("fixtures");
    let assets = root.join("assets");
    let source = String::from_utf8(read(&root.join("src/main.rs"))?)?;
    let manifest = String::from_utf8(read(&root.join("Cargo.toml"))?)?;
    let mut checks = Vec::new();

    let direct_dependencies = [
        "workflow-compiler",
        "workflow-adk",
        "workflow-testkit",
        "workflow-runtime",
    ];
    let exact_revisions = direct_dependencies.iter().all(|dependency| {
        manifest
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{dependency} =")))
            .is_some_and(|line| {
                line.contains("git = \"https://github.com/RyderFreeman4Logos/adk-workflow-kit\"")
                    && line.contains(&format!("rev = \"{PIN}\""))
                    && !line.contains("path =")
            })
    });
    require(
        &mut checks,
        "exact identical Git revisions",
        exact_revisions,
    )?;
    require(
        &mut checks,
        "no path workspace private dependency",
        !manifest.contains("[workspace]")
            && !manifest.contains("path =")
            && !source.contains(&(String::from("workflow") + "ctl"))
            && source.contains("workflow_adk::execution::{"),
    )?;

    let target = root.join("target");
    require(
        &mut checks,
        "lexical target symlink",
        fs::symlink_metadata(&target)?.file_type().is_symlink()
            && fs::read_link(&target)?.to_string_lossy() == expected_target,
    )?;

    let required_assets = [
        "assets/prompt.txt",
        "assets/data/input.json",
        "assets/connectors/echo.json",
        "assets/skills/demo/SKILL.md",
        "assets/skills/demo/skill.runtime.toml",
        "assets/skills/demo/references/usage.md",
    ];
    require(
        &mut checks,
        "downstream prompt Skill connector data",
        required_assets.iter().all(|relative| {
            let path = root.join(relative);
            fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
                && fs::read(path).is_ok_and(|bytes| !bytes.is_empty())
        }),
    )?;

    let profile_bytes = read(&fixtures.join("profile.json"))?;
    let connector: Value = serde_json::from_slice(&read(&assets.join("connectors/echo.json"))?)?;
    let mut profile: Value = serde_json::from_slice(&profile_bytes)?;
    let skill_root = assets.join("skills/demo").to_string_lossy().into_owned();
    profile["skills"][0]["root"] = Value::String(skill_root);
    profile["tool"] = connector
        .get("tool")
        .cloned()
        .ok_or("connector missing tool")?;
    let profile_text = serde_json::to_string(&profile)?;
    require(
        &mut checks,
        "offline fake provider without credentials or endpoint",
        profile["model"]["provider"] == "fake"
            && !profile_text.contains("base_url")
            && !profile_text.contains("credential")
            && !profile_text.contains("api_key")
            && !profile_text.contains("OPENAI"),
    )?;
    let workflow = root.join("workflow.toml");
    let prompt = String::from_utf8(read(&assets.join("prompt.txt"))?)?;
    let data: Value = serde_json::from_slice(&read(&assets.join("data/input.json"))?)?;
    let resource = read(&assets.join("skills/demo/references/usage.md"))?;
    let expected_args = json!({
        "message": serde_json::to_string(&data)?,
        "resource": resource.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "resource_sha256": digest(&resource).trim_start_matches("sha256:"),
    });
    let calls = profile["model"]["responses"]
        .as_array_mut()
        .ok_or("missing fake responses")?;
    for response in calls {
        if let Some(calls) = response.get_mut("calls").and_then(Value::as_array_mut) {
            for call in calls {
                if call["name"] == "echo" {
                    call["args"]["message"] = expected_args["message"].clone();
                }
            }
        }
    }
    let profile_value = profile.clone();
    let profile: ExecutionProfileV1 = serde_json::from_value(profile)?;
    let input = json!({"prompt": prompt, "data": data, "connector": "echo"});
    require(
        &mut checks,
        "prompt data connector wired",
        input["prompt"]
            .as_str()
            .is_some_and(|prompt| !prompt.is_empty())
            && input["data"]["record"] == "downstream-input"
            && profile_value["tool"]["name"] == "echo",
    )?;
    let input_bytes = serde_json::to_vec(&input)?;

    let plan = compile_file(&workflow)?;
    let lock = WorkflowLock::try_from_plan(&plan)?;
    let lock_toml = lock.to_toml()?;
    require(
        &mut checks,
        "validate compile_file",
        lock.workflow_id() == "issue-269-downstream",
    )?;
    require(
        &mut checks,
        "lock v1 with IR hash",
        lock_toml.contains("lock_version = 1") && lock.ir_hash().starts_with("sha256:"),
    )?;

    if !workdir_base.is_absolute() || workdir_base.as_os_str().len() > 48 || !workdir_base.is_dir()
    {
        return Err("invalid prepared temporary base".into());
    }
    let existing = std::env::args().nth(3);
    let run = match &existing {
        Some(run_id) => ExecutionBackend::inspect(&workdir_base, run_id)?,
        None => ExecutionBackend::run(&workflow, profile, input, &workdir_base)?,
    };
    let run_json = serde_json::to_value(&run)?;
    let run_id = field(&run_json, "run_id");
    let run_root_from_receipt = PathBuf::from(field(&run_json, "run_root"));
    let canonical_workdir_base = fs::canonicalize(&workdir_base)?;
    let resume_identity = field(&run_json, "resume_identity");
    let events_path = run_root_from_receipt.join("events.jsonl");
    let events_after_run = read(&events_path)?;
    let events = parse_events(&events_after_run)?;
    let effect_key = EffectKey::new(&run_id, "echo", "echo", &expected_args);
    let journal = EffectJournal::open(run_root_from_receipt.join("effects.sqlite"))?;
    let effects_after_run = journal.committed_count()?;
    let expected_effect = json!({"echo": "connector-backed downstream effect"});
    let artifact = terminal_artifact(&run_root_from_receipt, &field(&run_json, "artifact_id"))?;
    require(
        &mut checks,
        "run fake profile with receipt and connector effect",
        !run_id.is_empty()
            && field(&run_json, "status") == "succeeded"
            && !field(&run_json, "artifact_id").is_empty()
            && run_root_from_receipt.parent() == Some(canonical_workdir_base.as_path())
            && !field(&run_json, "plan_hash").is_empty()
            && !resume_identity.is_empty()
            && effects_after_run == 1
            && journal.load(&effect_key)? == Some(expected_effect.clone())
            && artifact
                == json!({"status":"succeeded", "terminal":"terminal", "node_output_refs":{}})
            && has_tool(&events, "activate_skill", |payload| {
                payload["activated"] == true
            })
            && has_tool(&events, "read_skill_resource", |payload| {
                payload["result_ref"] == expected_args["resource_sha256"]
            })
            && has_tool(&events, "echo", |payload| payload == &expected_effect)
            && events.iter().any(|event| {
                event.kind() == WorkflowRuntimeEventKindV1::ToolRequested
                    && event.payload()["structured_output"]
                        .as_array()
                        .is_some_and(|calls| {
                            calls.iter().any(|call| {
                                call["tool_name"] == "echo"
                                    && call["argument_fingerprint"]
                                        == argument_fingerprint(&expected_args)
                            })
                        })
            })
            && has_output(&events),
    )?;

    let inspected = ExecutionBackend::inspect(&workdir_base, &run_id)?;
    let inspected_json = serde_json::to_value(&inspected)?;
    require(
        &mut checks,
        "inspect preserves identity and root",
        inspected_json == run_json
            && terminal_artifact(
                &run_root_from_receipt,
                &field(&inspected_json, "artifact_id"),
            )? == artifact,
    )?;

    let resumed = ExecutionBackend::resume(&workdir_base, &run_id)?;
    let resumed_json = serde_json::to_value(&resumed)?;
    let events_after_resume = read(&events_path)?;
    let resumed_events = parse_events(&events_after_resume)?;
    let effects_after_resume = journal.committed_count()?;
    require(
        &mut checks,
        "resume preserves identity without duplicate effect",
        [
            "run_id",
            "workflow_id",
            "status",
            "artifact_id",
            "run_root",
            "plan_hash",
            "resume_identity",
        ]
        .iter()
        .all(|name| resumed_json[name] == run_json[name])
            && resumed_json["resume_count"].as_u64()
                == run_json["resume_count"]
                    .as_u64()
                    .and_then(|count| count.checked_add(1))
            && effects_after_resume == effects_after_run
            && journal.load(&effect_key)? == Some(expected_effect.clone())
            && terminal_artifact(&run_root_from_receipt, &field(&resumed_json, "artifact_id"))?
                == artifact
            && has_output(&resumed_events)
            && resumed_events
                .iter()
                .filter(|event| {
                    matches!(
                        event.kind(),
                        WorkflowRuntimeEventKindV1::ToolCompleted
                            | WorkflowRuntimeEventKindV1::ModelRequestCompleted
                    )
                })
                .collect::<Vec<_>>()
                == events
                    .iter()
                    .filter(|event| {
                        matches!(
                            event.kind(),
                            WorkflowRuntimeEventKindV1::ToolCompleted
                                | WorkflowRuntimeEventKindV1::ModelRequestCompleted
                        )
                    })
                    .collect::<Vec<_>>()
            && serde_json::to_value(ExecutionBackend::inspect(&workdir_base, &run_id)?)?
                == resumed_json,
    )?;

    let replay = ReplayBundle::from_json(&read(&fixtures.join("replay.json"))?)?;
    let trace = replay.replay();
    require(
        &mut checks,
        "replay validates structural trace",
        !trace.events().is_empty() && trace.events().len() == 5,
    )?;

    if checks.len() != 12 {
        return Err(format!("expected 12 checks, got {}", checks.len()).into());
    }
    println!(
        "ISSUE_269_RECEIPT={}",
        serde_json::json!({
            "revision": PIN,
            "operations": if existing.is_some() { vec!["inspect", "resume"] } else { vec!["validate", "lock", "run", "inspect", "resume", "replay"] },
            "checks_passed": checks.len(),
            "workflow_id": lock.workflow_id(),
            "ir_hash": lock.ir_hash(),
            "run_id": run_id,
            "status": "succeeded",
            "connector_effects": effects_after_run,
            "replay_events": trace.events().len(),
            "input_sha256": digest(&input_bytes),
            "run_root": run_root_from_receipt,
            "run_receipt": run_json,
            "inspect_receipt": inspected_json,
            "resume_receipt": resumed_json,
            "terminal_artifact": artifact,
            "effect_key": effect_key.as_str(),
            "effect_result": expected_effect,
            "arguments_sha256": argument_fingerprint(&expected_args),
            "events_before_sha256": digest(&events_after_run),
            "events_after_sha256": digest(&events_after_resume),
        })
    );
    // Retain this small owned run as durable acceptance evidence.
    Ok(())
}

fn parse_events(bytes: &[u8]) -> Result<Vec<WorkflowRuntimeEventV1>, Box<dyn Error>> {
    String::from_utf8(bytes.to_vec())?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn has_tool(events: &[WorkflowRuntimeEventV1], name: &str, check: impl Fn(&Value) -> bool) -> bool {
    events
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
        .filter_map(|event| event.payload()["structured_output"].as_array())
        .flatten()
        .any(|item| item["tool_name"] == name && check(&item["response"]["payload"]))
}

fn has_output(events: &[WorkflowRuntimeEventV1]) -> bool {
    events
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ModelRequestCompleted)
        .filter_map(|event| event.payload()["structured_output"]["parts"].as_array())
        .flatten()
        .filter_map(|part| part["text"].as_str())
        .any(|text| {
            serde_json::from_str::<Value>(text).is_ok_and(|value| {
                value == json!({"status":"finished", "output":"downstream proof complete"})
            })
        })
}

fn terminal_artifact(root: &Path, reference: &str) -> Result<Value, Box<dyn Error>> {
    let limit = NonZeroU64::new(65_536).ok_or("invalid artifact limit")?;
    let store = FilesystemArtifactStore::try_new(root.join("artifacts"), limit, limit)?;
    let id = ArtifactId::parse(reference).ok_or("invalid terminal artifact id")?;
    let page = store.read_page(&id, PageRequest::new(0, limit))?;
    if page.next_offset().is_some() || digest(page.bytes()) != format!("sha256:{reference}") {
        return Err("terminal artifact identity mismatch".into());
    }
    Ok(serde_json::from_slice(page.bytes())?)
}
