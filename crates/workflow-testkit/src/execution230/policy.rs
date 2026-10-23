//! Frozen, private-directory offline campaigns. A seal is an execution boundary,
//! not secrecy for public examples or a statistical claim about model quality.
use super::journal::{CaseIdentity, atomic, read};
use super::*;
use crate::harness230::SuiteMode;
use std::os::unix::fs::DirBuilderExt;

mod comparison;
mod config;
pub(crate) use comparison::command as comparison_command;
pub(super) use config::inputs;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Split {
    schema_version: u32,
    tuning: Vec<String>,
    holdout: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Campaign {
    split: Split,
    registry: Vec<CaseIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<config::Config>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunIdentity {
    pub(super) campaign: PathBuf,
    operation: usize,
    campaign_digest: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    identity: RunIdentity,
    mode: SuiteMode,
    selected_case_ids: Vec<String>,
    repeats: usize,
    baseline: Option<usize>,
    measurement_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison_digest: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorKind {
    InvalidPolicy,
    IdentityMismatch,
    MissingMeasurement,
    UnsupportedMetric,
    InvalidEvidence,
    Sealed,
}

#[derive(Debug, Serialize)]
pub(super) struct PolicyError {
    kind: ErrorKind,
    pub(super) message: String,
}
impl From<String> for PolicyError {
    fn from(message: String) -> Self {
        Self {
            kind: ErrorKind::InvalidEvidence,
            message,
        }
    }
}
fn failure(kind: ErrorKind, message: &str) -> PolicyError {
    PolicyError {
        kind,
        message: message.to_owned(),
    }
}
fn hash(value: &impl Serialize) -> Result<String, PolicyError> {
    Ok(digest(&serde_json::to_vec(value).map_err(error)?))
}
fn validate_split(split: &Split, registry: &[CaseIdentity]) -> Result<(), PolicyError> {
    let ids = split
        .tuning
        .iter()
        .chain(&split.holdout)
        .collect::<BTreeSet<_>>();
    let registered = registry
        .iter()
        .map(|c| &c.workflow.case_id)
        .collect::<BTreeSet<_>>();
    if split.schema_version != 1
        || split.tuning.is_empty()
        || split.holdout.is_empty()
        || ids.len() != split.tuning.len() + split.holdout.len()
        || ids != registered
    {
        return Err(failure(
            ErrorKind::InvalidPolicy,
            "split must partition every registered case exactly once into nonempty tuning and holdout sets",
        ));
    }
    // A renamed case/input cannot cross the holdout boundary. Missing bindings stay
    // unsupported at execution rather than being silently removed from the registry.
    let datasets = |group: &[String]| {
        registry
            .iter()
            .filter(|c| group.contains(&c.workflow.case_id))
            .filter_map(|c| c.manifest.dataset_digest.as_ref())
            .collect::<BTreeSet<_>>()
    };
    if !datasets(&split.tuning).is_disjoint(&datasets(&split.holdout)) {
        return Err(failure(
            ErrorKind::InvalidPolicy,
            "dataset identity crosses split boundary",
        ));
    }
    Ok(())
}
fn campaign(repo: &Path, root: &Path) -> Result<Campaign, PolicyError> {
    let saved: Campaign = read(&root.join("campaign.json"))?;
    if saved.registry != config::registry(repo, saved.config.as_ref())? {
        return Err(failure(
            ErrorKind::IdentityMismatch,
            "campaign source/config/model/dataset/executable identity mismatch",
        ));
    }
    validate_split(&saved.split, &saved.registry)?;
    Ok(saved)
}
fn operations(root: &Path) -> Result<Vec<Operation>, PolicyError> {
    let mut indices = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(error)? {
        let entry = entry.map_err(error)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| failure(ErrorKind::InvalidEvidence, "non-UTF8 operation"))?;
        if let Some(index) = name
            .strip_prefix("operation-")
            .and_then(|n| n.strip_suffix(".json"))
        {
            let index = index.parse::<usize>().map_err(error)?;
            if name != format!("operation-{index}.json") || !indices.insert(index) {
                return Err(failure(
                    ErrorKind::InvalidEvidence,
                    "invalid operation filename",
                ));
            }
        }
    }
    if !indices.iter().copied().eq(0..indices.len()) {
        return Err(failure(
            ErrorKind::InvalidEvidence,
            "non-contiguous operation journal",
        ));
    }
    indices
        .into_iter()
        .map(|i| {
            let operation: Operation = read(&root.join(format!("operation-{i}.json")))?;
            if operation.identity.campaign != root || operation.identity.operation != i {
                return Err(failure(
                    ErrorKind::IdentityMismatch,
                    "operation belongs to another campaign or ordinal",
                ));
            }
            Ok(operation)
        })
        .collect()
}
fn run_path(identity: &RunIdentity) -> PathBuf {
    identity
        .campaign
        .join(format!("operation-{}", identity.operation))
}
fn measured(
    repo: &Path,
    baseline: &Operation,
    count: usize,
) -> Result<(Vec<String>, String), PolicyError> {
    if baseline.mode != SuiteMode::Regression {
        return Err(failure(
            ErrorKind::InvalidEvidence,
            "selection requires regression tuning receipts, never holdout or synthetic observations",
        ));
    }
    let cases = journal::completed(
        repo,
        &run_path(&baseline.identity),
        baseline.identity.clone(),
    )?;
    let receipt_digest = hash(&cases)?;
    let mut scores = Vec::new();
    for case in cases {
        if case.status != ScriptedStatus::Succeeded || case.elapsed_ns.is_none() {
            return Err(failure(
                ErrorKind::MissingMeasurement,
                "every tuning case requires a successful measured receipt",
            ));
        }
        scores.push((
            case.case_id,
            case.elapsed_ns
                .ok_or_else(|| failure(ErrorKind::MissingMeasurement, "elapsed_ns absent"))?,
        ));
    }
    scores.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok((
        scores.into_iter().take(count).map(|(id, _)| id).collect(),
        receipt_digest,
    ))
}

pub(super) fn selected(
    repo: &Path,
    output: &Path,
    identity: &RunIdentity,
) -> Result<Vec<CaseIdentity>, PolicyError> {
    let campaign = campaign(repo, &identity.campaign)?;
    let operations = operations(&identity.campaign)?;
    let op = operations
        .get(identity.operation)
        .ok_or_else(|| failure(ErrorKind::InvalidEvidence, "missing operation"))?;
    if op.identity != *identity
        || identity.campaign_digest != hash(&campaign)?
        || output != run_path(identity)
    {
        return Err(failure(
            ErrorKind::IdentityMismatch,
            "operation identity mismatch",
        ));
    }
    if comparison::admission(&identity.campaign, op.mode, identity.operation)?
        != op.comparison_digest
    {
        return Err(failure(
            ErrorKind::IdentityMismatch,
            "comparison admission changed",
        ));
    }
    let allowed = if op.mode == SuiteMode::SealedFinal {
        &campaign.split.holdout
    } else {
        &campaign.split.tuning
    };
    let unique = op.selected_case_ids.iter().collect::<BTreeSet<_>>();
    if op.selected_case_ids.is_empty()
        || unique.len() != op.selected_case_ids.len()
        || op.selected_case_ids.iter().any(|id| !allowed.contains(id))
        || !(1..=100).contains(&op.repeats)
        || (op.mode != SuiteMode::Soak && op.repeats != 1)
        || op.mode == SuiteMode::Scripted
    {
        return Err(failure(
            ErrorKind::InvalidPolicy,
            "operation violates frozen split or repetition budget",
        ));
    }
    if op.mode == SuiteMode::Adaptive {
        let index = op
            .baseline
            .filter(|i| *i < identity.operation)
            .ok_or_else(|| failure(ErrorKind::InvalidEvidence, "invalid baseline"))?;
        let baseline = operations
            .get(index)
            .ok_or_else(|| failure(ErrorKind::InvalidEvidence, "missing baseline"))?;
        let (ids, digest) = measured(repo, baseline, op.selected_case_ids.len())?;
        if ids != op.selected_case_ids || op.measurement_digest.as_ref() != Some(&digest) {
            return Err(failure(
                ErrorKind::InvalidEvidence,
                "adaptive selection evidence changed",
            ));
        }
    } else if &op.selected_case_ids != allowed
        || op.baseline.is_some()
        || op.measurement_digest.is_some()
    {
        return Err(failure(
            ErrorKind::InvalidPolicy,
            "non-adaptive mode must execute the entire frozen partition",
        ));
    }
    let mut selected = Vec::new();
    for repeat in 0..op.repeats {
        for id in &op.selected_case_ids {
            let mut case = campaign
                .registry
                .iter()
                .find(|c| &c.workflow.case_id == id)
                .cloned()
                .ok_or_else(|| failure(ErrorKind::InvalidPolicy, "unknown case"))?;
            if op.repeats > 1 {
                case.workflow.case_id = format!("{id}#{}", repeat + 1);
            }
            selected.push(case);
        }
    }
    Ok(selected)
}

pub(super) fn allow_execution(identity: &RunIdentity) -> Result<(), PolicyError> {
    let ops = operations(&identity.campaign)?;
    if let Some(final_index) = ops.iter().position(|o| o.mode == SuiteMode::SealedFinal)
        && identity.operation != final_index
    {
        return Err(failure(
            ErrorKind::Sealed,
            "final admission permanently seals campaign tuning",
        ));
    }
    Ok(())
}

fn initialize(
    repo: &Path,
    policy: &Path,
    root: &Path,
    config_path: Option<&Path>,
) -> Result<Value, PolicyError> {
    let config = config_path
        .map(|path| {
            if fs::metadata(path).map_err(error)?.len() > 64 * 1024 {
                return Err("comparison config exceeds 64 KiB".to_owned());
            }
            read::<config::Config>(path)
        })
        .transpose()
        .map_err(|e| failure(ErrorKind::InvalidPolicy, &e))?;
    let mut split: Split = read(policy).map_err(|e| failure(ErrorKind::InvalidPolicy, &e))?;
    split.tuning.sort();
    split.holdout.sort();
    let campaign = Campaign {
        split,
        registry: config::registry(repo, config.as_ref())
            .map_err(|e| failure(ErrorKind::InvalidPolicy, &e))?,
        config,
    };
    validate_split(&campaign.split, &campaign.registry)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(error)?;
    let canonical = fs::canonicalize(root).map_err(error)?;
    let root = canonical.as_path();
    let _lock = journal::lock(root)?;
    atomic(root, "campaign.json", &campaign)?;
    fs::File::open(
        root.parent()
            .ok_or_else(|| failure(ErrorKind::InvalidPolicy, "campaign parent missing"))?,
    )
    .and_then(|d| d.sync_all())
    .map_err(error)?;
    Ok(json!({"schema_version":1,"campaign_digest":hash(&campaign)?,"live_executed":false}))
}
fn execute(
    repo: &Path,
    root: &Path,
    mode: SuiteMode,
    metric: &str,
    count: usize,
) -> Result<Value, PolicyError> {
    let root = fs::canonicalize(root).map_err(error)?;
    let _lock = journal::lock(&root)?;
    let campaign = campaign(repo, &root)?;
    let ops = operations(&root)?;
    if ops.iter().any(|op| op.mode == SuiteMode::SealedFinal) {
        return Err(failure(
            ErrorKind::Sealed,
            "final admission permanently seals campaign; resume its existing suite only",
        ));
    }
    if count == 0
        || count > 100
        || (mode == SuiteMode::Adaptive && count > campaign.split.tuning.len())
    {
        return Err(failure(
            ErrorKind::InvalidPolicy,
            "count must be 1..100; adaptive count cannot exceed tuning size",
        ));
    }
    if mode == SuiteMode::Adaptive && metric != "elapsed_ns" {
        return Err(failure(
            ErrorKind::UnsupportedMetric,
            "only measured executor elapsed_ns is available; no quality, security, token or cost metric",
        ));
    }
    // No overlapping operations: an interrupted admission must be reconciled first.
    for op in &ops {
        journal::completed(repo, &run_path(&op.identity), op.identity.clone())?;
    }
    let mut op = Operation {
        identity: RunIdentity {
            campaign: root.clone(),
            operation: ops.len(),
            campaign_digest: hash(&campaign)?,
        },
        mode,
        selected_case_ids: if mode == SuiteMode::SealedFinal {
            campaign.split.holdout.clone()
        } else {
            campaign.split.tuning.clone()
        },
        repeats: if mode == SuiteMode::Soak { count } else { 1 },
        baseline: None,
        measurement_digest: None,
        comparison_digest: comparison::admission(&root, mode, ops.len())?,
    };
    if mode == SuiteMode::Adaptive {
        let baseline = ops
            .iter()
            .rev()
            .find(|o| o.mode == SuiteMode::Regression)
            .ok_or_else(|| {
                failure(
                    ErrorKind::MissingMeasurement,
                    "run regression to collect tuning receipts first",
                )
            })?;
        let (ids, digest) = measured(repo, baseline, count)?;
        op.selected_case_ids = ids;
        op.baseline = Some(baseline.identity.operation);
        op.measurement_digest = Some(digest);
    }
    // Fsync the irreversible final admission BEFORE exposing any holdout execution.
    atomic(&root, &format!("operation-{}.json", ops.len()), &op)?;
    let execution = journal::run_selected(
        repo,
        &run_path(&op.identity),
        false,
        Some(op.identity.clone()),
    )?;
    Ok(
        json!({"schema_version":1,"mode":op.mode,"selected_case_ids":op.selected_case_ids,"repeats":op.repeats,"baseline_operation":op.baseline,"measurement_digest":op.measurement_digest,"campaign_digest":op.identity.campaign_digest,"execution":execution}),
    )
}

/// Exact CLI shapes are matched by the caller; failures are structured and nonzero.
pub(crate) fn command(args: &[&str]) -> Result<(String, bool), String> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = match args {
        ["init", policy, root] => initialize(&repo, Path::new(policy), Path::new(root), None),
        ["init-config", policy, config, root] => initialize(
            &repo,
            Path::new(policy),
            Path::new(root),
            Some(Path::new(config)),
        ),
        [mode, root, rest @ ..] => {
            let (mode, metric, count) = match *mode {
                "regression" => (SuiteMode::Regression, "", Ok(1)),
                "sealed-final" => (SuiteMode::SealedFinal, "", Ok(1)),
                "soak" => (
                    SuiteMode::Soak,
                    "",
                    rest.first().and_then(|n| n.parse().ok()).ok_or_else(|| {
                        failure(ErrorKind::InvalidPolicy, "invalid repetition count")
                    }),
                ),
                "adaptive" => (
                    SuiteMode::Adaptive,
                    rest.first().copied().unwrap_or(""),
                    rest.get(1).and_then(|n| n.parse().ok()).ok_or_else(|| {
                        failure(ErrorKind::InvalidPolicy, "invalid selection count")
                    }),
                ),
                _ => return Err("unknown policy command".to_owned()),
            };
            count.and_then(|count| execute(&repo, Path::new(root), mode, metric, count))
        }
        _ => return Err("invalid policy command".to_owned()),
    };
    let (value, failed) = match result {
        Ok(value) => {
            let failed = value["execution"]["hard_invariant_failed"] == true;
            (value, failed)
        }
        Err(error) => (json!({"error":error}), true),
    };
    serde_json::to_string_pretty(&value)
        .map(|json| (json + "\n", failed))
        .map_err(error)
}
