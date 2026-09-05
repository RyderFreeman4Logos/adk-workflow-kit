use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
use workflow_compiler::{WorkflowLock, compile_file};
use workflow_testkit::ReplayBundle;

const PIN: &str = "026b883a58bab6cc2d0c8610b44e3983e6017cb8";
const EXPECTED_TARGET: &str =
    "/ssd/mirror-rootfs/home/obj/project/downstream/adk-workflow-kit-269/target";

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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("fixtures");
    let assets = root.join("assets");
    let source = String::from_utf8(read(&root.join("src/main.rs"))?)?;
    let manifest = String::from_utf8(read(&root.join("Cargo.toml"))?)?;
    let mut checks = Vec::new();

    let direct_dependencies = ["workflow-compiler", "workflow-adk", "workflow-testkit"];
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
            && fs::read_link(&target)?.to_string_lossy() == EXPECTED_TARGET,
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
    let profile_value = profile.clone();
    let profile: ExecutionProfileV1 = serde_json::from_value(profile)?;

    let workflow = fixtures.join("workflow.toml");
    let prompt = String::from_utf8(read(&assets.join("prompt.txt"))?)?;
    let data: Value = serde_json::from_slice(&read(&assets.join("data/input.json"))?)?;
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

    let workdir_base = fs::canonicalize("/home/obj/tmp")?;
    let run = ExecutionBackend::run(&workflow, profile, input, &workdir_base)?;
    let run_json = serde_json::to_value(&run)?;
    let run_id = field(&run_json, "run_id");
    let run_root_from_receipt = PathBuf::from(field(&run_json, "run_root"));
    let canonical_workdir_base = fs::canonicalize(&workdir_base)?;
    let resume_identity = field(&run_json, "resume_identity");
    let events_path = run_root_from_receipt.join("events.jsonl");
    let events_after_run = String::from_utf8(read(&events_path)?)?;
    let effects_after_run = events_after_run.matches("tool_completed").count();
    require(
        &mut checks,
        "run fake profile with receipt and connector effect",
        !run_id.is_empty()
            && field(&run_json, "status") == "succeeded"
            && !field(&run_json, "artifact_id").is_empty()
            && run_root_from_receipt.parent() == Some(canonical_workdir_base.as_path())
            && !field(&run_json, "plan_hash").is_empty()
            && !resume_identity.is_empty()
            && effects_after_run > 0
            && events_after_run.contains("echo"),
    )?;

    let inspected = ExecutionBackend::inspect(&workdir_base, &run_id)?;
    let inspected_json = serde_json::to_value(&inspected)?;
    require(
        &mut checks,
        "inspect preserves identity and root",
        field(&inspected_json, "run_id") == run_id
            && field(&inspected_json, "run_root") == run_root_from_receipt.to_string_lossy(),
    )?;

    let resumed = ExecutionBackend::resume(&workdir_base, &run_id)?;
    let resumed_json = serde_json::to_value(&resumed)?;
    let events_after_resume = String::from_utf8(read(&events_path)?)?;
    let effects_after_resume = events_after_resume.matches("tool_completed").count();
    require(
        &mut checks,
        "resume preserves identity without duplicate effect",
        field(&resumed_json, "run_id") == run_id
            && field(&resumed_json, "status") == "succeeded"
            && field(&resumed_json, "resume_identity") == resume_identity
            && field(&resumed_json, "run_root") == run_root_from_receipt.to_string_lossy()
            && effects_after_resume == effects_after_run,
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
            "operations": ["validate", "lock", "run", "inspect", "resume", "replay"],
            "checks_passed": checks.len(),
            "workflow_id": lock.workflow_id(),
            "ir_hash": lock.ir_hash(),
            "run_id": run_id,
            "status": "succeeded",
            "connector_effects": effects_after_run,
            "replay_events": trace.events().len(),
            "input_sha256": digest(&input_bytes),
        })
    );
    remove_run_root(&run_root_from_receipt)?;
    Ok(())
}

fn remove_run_root(path: &Path) -> Result<(), Box<dyn Error>> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        for entry in fs::read_dir(path)? {
            remove_run_root(&entry?.path())?;
        }
        Ok(fs::remove_dir(path)?)
    } else {
        Ok(fs::remove_file(path)?)
    }
}
