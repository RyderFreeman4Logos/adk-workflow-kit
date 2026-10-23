//! Measured offline smoke through the production compiler and ADK executor.
//!
//! Model replies (and the echo connector) are scripted, not live inference.
//! Only elapsed wall time and the executor's durable receipts are observations.
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use serde::{Deserialize, Serialize};

pub(crate) mod cache;
mod journal;
pub(crate) mod measurement;
pub(crate) mod policy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1, ExecutionReceipt};
use workflow_compiler::compile_file;

/// A shipped package. Unknown packages remain visible as unsupported cases.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptedWorkflow {
    pub case_id: String,
    pub source: String,
}

/// Discover all shipped workflow packages, not test fixtures or planning examples.
pub fn scripted_workflows(repo: &Path) -> Result<Vec<ScriptedWorkflow>, String> {
    for source in [
        "examples/00-runtime-smoke/workflow.toml",
        "examples/01-code-investigation/workflow.toml",
        "examples/02-downstream-consumer-269/workflow.toml",
        "templates/minimal/workflow.toml",
    ] {
        if !repo.join(source).is_file() {
            return Err(format!("registered workflow missing: {source}"));
        }
    }
    let mut workflows = Vec::new();
    for parent in ["examples", "templates"] {
        for entry in fs::read_dir(repo.join(parent)).map_err(error)? {
            let entry = entry.map_err(error)?;
            if !entry.file_type().map_err(error)?.is_dir() {
                if entry.path().join("workflow.toml").is_file() {
                    return Err("symlinked workflow package is not admitted".to_owned());
                }
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 package name")?;
            let source = format!("{parent}/{name}/workflow.toml");
            if !repo.join(&source).is_file() {
                continue;
            }
            let case_id = match source.as_str() {
                "examples/00-runtime-smoke/workflow.toml" => "runtime-smoke",
                "examples/01-code-investigation/workflow.toml" => "code-investigation",
                "examples/02-downstream-consumer-269/workflow.toml" => "downstream-consumer",
                "templates/minimal/workflow.toml" => "minimal-template",
                _ => &source,
            }
            .to_owned();
            workflows.push(ScriptedWorkflow { case_id, source });
        }
    }
    workflows.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    if workflows.is_empty() {
        return Err("no shipped workflows found".to_owned());
    }
    Ok(workflows)
}

/// Exact observed source inputs, executable, and scripted model/config/data identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionManifest {
    pub source_revision: String,
    pub source_tree: String,
    pub source_files_digest: String,
    pub executable_digest: String,
    pub workflow_source: String,
    pub workflow_digest: String,
    pub config_digest: Option<String>,
    pub dataset_digest: Option<String>,
    pub model_digest: Option<String>,
}

/// Unsupported is not success and always makes the smoke exit nonzero.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptedStatus {
    Succeeded,
    Failed,
    Unsupported,
}

/// Measurements are absent unless observed. Raw receipt preserves cache semantics.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedCase {
    pub case_id: String,
    pub manifest: ExecutionManifest,
    pub status: ScriptedStatus,
    pub receipt: Option<ExecutionReceipt>,
    pub admitted_run_id: Option<String>,
    pub elapsed_ns: Option<u64>,
    pub events_digest: Option<String>,
    pub hard_invariant_failures: Vec<String>,
    pub unsupported_reason: Option<String>,
}

/// Scripted production execution, deliberately separate from synthetic report fixtures.
#[derive(Debug, Serialize)]
pub struct ExecutionReport {
    pub schema_version: u32,
    pub evidence_kind: &'static str,
    pub live_executed: bool,
    pub output_directory: PathBuf,
    pub cases: Vec<ExecutedCase>,
    pub hard_invariant_failed: bool,
}

/// Executes every discovered package, recording admission before runtime effects.
/// `output` must be fresh. Interrupted cases require explicit recovery, not replay.
pub fn run_registered_smoke(repo: &Path, output: &Path) -> Result<ExecutionReport, String> {
    journal::run(repo, output, false)
}

/// Resume only unstarted cases after validating the complete immutable suite identity.
/// Any admitted case without a completion fails closed; no automatic runtime resume.
pub fn resume_registered_smoke(repo: &Path, output: &Path) -> Result<ExecutionReport, String> {
    journal::run(repo, output, true)
}

/// Mark one ambiguous admission as failed without executing or resuming it.
/// The caller must verify the original process has exited; this cannot undo effects.
pub fn abandon_registered_case(
    repo: &Path,
    output: &Path,
    case_id: &str,
    run_id: &str,
) -> Result<(), String> {
    journal::abandon(repo, output, case_id, run_id)
}

fn manifests(repo: &Path) -> Result<Vec<(ScriptedWorkflow, ExecutionManifest)>, String> {
    let source_revision = git(repo, &["rev-parse", "HEAD"])?;
    let source_tree = git(repo, &["rev-parse", "HEAD^{tree}"])?;
    let source_files_digest = source_digest(repo)?;
    let executable_digest =
        digest(&fs::read(std::env::current_exe().map_err(error)?).map_err(error)?);
    scripted_workflows(repo)?
        .into_iter()
        .map(|workflow| {
            let mut manifest = ExecutionManifest {
                source_revision: source_revision.clone(),
                source_tree: source_tree.clone(),
                source_files_digest: source_files_digest.clone(),
                executable_digest: executable_digest.clone(),
                workflow_source: workflow.source.clone(),
                workflow_digest: digest(&fs::read(repo.join(&workflow.source)).map_err(error)?),
                config_digest: None,
                dataset_digest: None,
                model_digest: None,
            };
            if let Some((profile, input)) = scripted_inputs(repo, &workflow.source)? {
                bind_inputs(&mut manifest, &profile, &input)?;
            }
            Ok((workflow, manifest))
        })
        .collect()
}

fn bind_inputs(
    manifest: &mut ExecutionManifest,
    profile: &Value,
    input: &Value,
) -> Result<(), String> {
    let models = json!({"worker": profile.get("model"), "reviewer": profile.get("reviewer_model")});
    manifest.model_digest = Some(digest(&serde_json::to_vec(&models).map_err(error)?));
    manifest.config_digest = Some(digest(&serde_json::to_vec(profile).map_err(error)?));
    manifest.dataset_digest = Some(digest(&serde_json::to_vec(input).map_err(error)?));
    Ok(())
}

#[cfg(test)]
fn execute_case(
    repo: &Path,
    runs: &Path,
    workflow: &ScriptedWorkflow,
    manifest: ExecutionManifest,
    admit: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<ExecutedCase, String> {
    execute_case_with_inputs(
        repo,
        runs,
        workflow,
        manifest,
        scripted_inputs(repo, &workflow.source)?,
        admit,
    )
}

// Scripted callers retain the offline-only admission boundary.
fn execute_case_with_inputs(
    repo: &Path,
    runs: &Path,
    workflow: &ScriptedWorkflow,
    manifest: ExecutionManifest,
    inputs: Option<(Value, Value)>,
    admit: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<ExecutedCase, String> {
    execute_bound_case(repo, runs, workflow, manifest, inputs, false, admit)
}

fn execute_bound_case(
    repo: &Path,
    runs: &Path,
    workflow: &ScriptedWorkflow,
    manifest: ExecutionManifest,
    inputs: Option<(Value, Value)>,
    allow_provider: bool,
    admit: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<ExecutedCase, String> {
    let mut case = ExecutedCase {
        case_id: workflow.case_id.clone(),
        manifest,
        status: ScriptedStatus::Unsupported,
        receipt: None,
        admitted_run_id: None,
        elapsed_ns: None,
        events_digest: None,
        hard_invariant_failures: Vec::new(),
        unsupported_reason: None,
    };
    let Some((profile, input)) = inputs else {
        case.unsupported_reason =
            Some("no admitted scripted profile/input adapter for package".to_owned());
        return Ok(case);
    };
    let semantic_admission = canonical_admission(repo, &workflow.source, &input)?;
    let original = case.manifest.clone();
    bind_inputs(&mut case.manifest, &profile, &input)?;
    if original.config_digest.is_some() && original != case.manifest {
        return Err("case input identity mismatch".to_owned());
    }
    // Scripted/cache adapters never admit provider egress. Measured callers validate explicit opt-in.

    for role in ["model", "reviewer_model"] {
        if !allow_provider
            && let Some(model) = profile.get(role)
            && (model.get("provider").and_then(Value::as_str) != Some("fake")
                || model.get("base_url").is_some())
        {
            case.hard_invariant_failures
                .push("non-scripted model profile".to_owned());
            case.status = ScriptedStatus::Failed;
            return Ok(case);
        }
    }
    let parsed =
        ExecutionProfileV1::parse(&serde_json::to_vec(&profile).map_err(error)?).map_err(error)?;
    let source = repo.join(&workflow.source);
    let started = Instant::now();
    let result = ExecutionBackend::run_admitted(&source, parsed, input, runs, |run_id| {
        admit(run_id)?;
        case.admitted_run_id = Some(run_id.to_owned());
        Ok(())
    });
    case.elapsed_ns = Some(u64::try_from(started.elapsed().as_nanos()).map_err(error)?);
    let receipt = match result {
        Ok(receipt) => Some(receipt),
        Err(failure) => {
            case.hard_invariant_failures.push(failure.to_string());
            failure.receipt().cloned()
        }
    };
    if let Some(receipt) = receipt {
        let events = fs::read(receipt.run_root().join("events.jsonl")).map_err(error)?;
        case.events_digest = Some(digest(&events));
        // Identity verification follows durable admission and execution; it must not precompile.
        let plan = compile_file(&source).map_err(error)?;
        let raw = serde_json::to_value(&receipt).map_err(error)?;
        if receipt.status() != "succeeded" || raw["workflow_id"] != plan.ir().workflow_id().as_str()
        {
            case.hard_invariant_failures
                .push("terminal or workflow identity mismatch".to_owned());
        }
        if digest(&fs::read(receipt.run_root().join("workflow.toml")).map_err(error)?)
            != case.manifest.workflow_digest
        {
            case.hard_invariant_failures
                .push("executed source digest mismatch".to_owned());
        }
        let kinds = String::from_utf8(events)
            .map_err(error)?
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).map_err(error))
            .collect::<Result<Vec<_>, _>>()?;
        if !kinds
            .iter()
            .any(|event| event["kind"] == "workflow_completed")
        {
            case.hard_invariant_failures
                .push("missing workflow completion event".to_owned());
        }
        if receipt.status() == "succeeded"
            && let Some(admission) = semantic_admission
            && admission.validate(receipt.run_root()).is_err()
        {
            case.hard_invariant_failures
                .push("canonical answer evidence rejected".to_owned());
        }
        case.receipt = Some(receipt);
    } else {
        case.hard_invariant_failures
            .push("no execution receipt".to_owned());
    }
    case.status = if case.hard_invariant_failures.is_empty() {
        ScriptedStatus::Succeeded
    } else {
        ScriptedStatus::Failed
    };
    Ok(case)
}

// The canonical task uses the same host facts and executed-answer validator as M3-07.
// Other registered workflows retain their own runtime contracts; no answer is fabricated here.
fn canonical_admission(
    repo: &Path,
    source: &str,
    input: &Value,
) -> Result<Option<crate::live_conformance::evidence::Admission>, String> {
    if source != "examples/01-code-investigation/workflow.toml" {
        return Ok(None);
    }
    let admission = crate::live_conformance::evidence::Admission::new(
        &repo.join("examples/01-code-investigation"),
    )
    .map_err(|_| "canonical input does not match host facts")?;
    let expected: Value = serde_json::from_str(admission.input()).map_err(error)?;
    if *input != expected {
        return Err("canonical input does not match host facts".to_owned());
    }
    Ok(Some(admission))
}

fn scripted_inputs(repo: &Path, source: &str) -> Result<Option<(Value, Value)>, String> {
    scripted_inputs_with(source, |path| read_json(&repo.join(path)))
}

fn scripted_inputs_with(
    source: &str,
    read: impl Fn(&str) -> Result<Value, String>,
) -> Result<Option<(Value, Value)>, String> {
    let (profile, input) = match source {
        "templates/minimal/workflow.toml" | "examples/00-runtime-smoke/workflow.toml" => (
            "examples/00-runtime-smoke/profiles/fake.json",
            "examples/00-runtime-smoke/input.example.json",
        ),
        "examples/01-code-investigation/workflow.toml" => (
            "examples/01-code-investigation/profiles/fake.json",
            "examples/01-code-investigation/input.example.json",
        ),
        "examples/02-downstream-consumer-269/workflow.toml" => (
            "examples/02-downstream-consumer-269/fixtures/profile.json",
            "examples/02-downstream-consumer-269/assets/data/input.json",
        ),
        _ => return Ok(None),
    };
    let mut profile = read(profile)?;
    let mut input = read(input)?;
    if source == "templates/minimal/workflow.toml" {
        let model = profile
            .get_mut("model")
            .and_then(Value::as_object_mut)
            .ok_or("scripted profile missing model")?;
        model.insert("name".to_owned(), json!("minimal-worker"));
        // This is a separate public case, not a renamed copy across tuning/holdout.
        input
            .as_object_mut()
            .ok_or("scripted input must be an object")?
            .insert(
                "request".to_owned(),
                json!("Run the explicitly bound minimal workflow."),
            );
    }
    if source == "examples/02-downstream-consumer-269/workflow.toml" {
        let tool = read("examples/02-downstream-consumer-269/assets/connectors/echo.json")?
            .get("tool")
            .cloned()
            .ok_or("connector missing tool")?;
        profile
            .as_object_mut()
            .ok_or("scripted profile must be an object")?
            .insert("tool".to_owned(), tool);
    }
    Ok(Some((profile, input)))
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(error)?).map_err(error)
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .map_err(error)?;
    if !output.status.success() {
        return Err("source identity command failed".to_owned());
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(error)?
        .trim()
        .to_owned())
}

fn source_digest(repo: &Path) -> Result<String, String> {
    let files = git(
        repo,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    let mut hasher = Sha256::new();
    for relative in files
        .split('\0')
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>()
    {
        let path = repo.join(relative);
        let bytes = match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => fs::read_link(path)
                .map_err(error)?
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
            Ok(_) => fs::read(path).map_err(error)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(error(e)),
        };
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Allocate a private smoke output directory beneath the explicitly selected temp root.
pub(crate) fn output_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("TMPDIR").ok_or("TMPDIR must name an SSD scratch directory")?;
    let base = fs::canonicalize(base).map_err(error)?;
    if base.starts_with("/tmp") || base.starts_with("/var/tmp") {
        return Err("unsafe scratch directory".to_owned());
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_nanos();
    Ok(base.join(format!("b230-{}-{stamp}", std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(source: &str) -> ExecutionManifest {
        ExecutionManifest {
            source_revision: "test".to_owned(),
            source_tree: "test".to_owned(),
            source_files_digest: "test".to_owned(),
            executable_digest: "test".to_owned(),
            workflow_source: source.to_owned(),
            workflow_digest: "deliberate-mismatch".to_owned(),
            config_digest: None,
            dataset_digest: None,
            model_digest: None,
        }
    }

    #[test]
    fn malformed_downstream_profile_is_an_error_not_a_panic() {
        let root = output_path().unwrap();
        let package = root.join("examples/02-downstream-consumer-269");
        fs::create_dir_all(package.join("fixtures")).unwrap();
        fs::create_dir_all(package.join("assets/data")).unwrap();
        fs::create_dir_all(package.join("assets/connectors")).unwrap();
        fs::write(package.join("fixtures/profile.json"), "[]").unwrap();
        fs::write(package.join("assets/data/input.json"), "{}").unwrap();
        fs::write(
            package.join("assets/connectors/echo.json"),
            r#"{"tool":{}}"#,
        )
        .unwrap();
        assert!(
            scripted_inputs(&root, "examples/02-downstream-consumer-269/workflow.toml").is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn admission_owner_rejects_canonical_host_fact_mismatch() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = "examples/01-code-investigation/workflow.toml";
        let workflow = ScriptedWorkflow {
            case_id: "code-investigation".to_owned(),
            source: source.to_owned(),
        };
        let (profile, mut input) = scripted_inputs(&repo, source).unwrap().unwrap();
        input["snapshot"]["id"] = json!("sha256:wrong-host-facts");
        let output = output_path().unwrap();
        fs::create_dir(&output).unwrap();
        let mut admitted = false;
        let result = execute_case_with_inputs(
            &repo,
            &output,
            &workflow,
            manifest(source),
            Some((profile, input)),
            |_| {
                admitted = true;
                Ok(())
            },
        );
        assert!(
            !admitted,
            "host facts must be rejected before run admission"
        );
        assert_eq!(
            result.unwrap_err(),
            "canonical input does not match host facts"
        );
        assert!(fs::read_dir(&output).unwrap().next().is_none());
    }

    #[test]
    fn non_fake_profile_is_denied_before_execution() {
        let root = output_path().unwrap();
        let package = root.join("examples/00-runtime-smoke");
        fs::create_dir_all(package.join("profiles")).unwrap();
        fs::write(
            package.join("profiles/fake.json"),
            r#"{"model":{"provider":"not-fake"}}"#,
        )
        .unwrap();
        fs::write(package.join("input.example.json"), "{}").unwrap();
        let workflow = ScriptedWorkflow {
            case_id: "runtime-smoke".to_owned(),
            source: "examples/00-runtime-smoke/workflow.toml".to_owned(),
        };
        let case = execute_case(&root, &root, &workflow, manifest(&workflow.source), |_| {
            Ok(())
        })
        .unwrap();
        assert_eq!(case.status, ScriptedStatus::Failed);
        assert_eq!(case.hard_invariant_failures, ["non-scripted model profile"]);
        assert!(case.elapsed_ns.is_none());
        assert!(case.receipt.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_adapter_is_typed_unsupported_without_fabricated_measurements() {
        let workflow = ScriptedWorkflow {
            case_id: "unknown".to_owned(),
            source: "examples/unknown/workflow.toml".to_owned(),
        };
        let case = execute_case(
            Path::new("."),
            Path::new("."),
            &workflow,
            manifest(&workflow.source),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(case.status, ScriptedStatus::Unsupported);
        assert!(case.unsupported_reason.is_some());
        assert!(case.receipt.is_none());
        assert!(case.elapsed_ns.is_none());
    }

    #[test]
    fn executed_source_mismatch_is_a_hard_failure_not_a_performance_target() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workflow = ScriptedWorkflow {
            case_id: "runtime-smoke".to_owned(),
            source: "examples/00-runtime-smoke/workflow.toml".to_owned(),
        };
        let output = output_path().unwrap();
        fs::create_dir(&output).unwrap();
        let case = execute_case(
            &repo,
            &output,
            &workflow,
            manifest(&workflow.source),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(case.status, ScriptedStatus::Failed);
        assert!(
            case.hard_invariant_failures
                .iter()
                .any(|failure| failure == "executed source digest mismatch")
        );
        assert_eq!(case.receipt.unwrap().status(), "succeeded");
    }
}
