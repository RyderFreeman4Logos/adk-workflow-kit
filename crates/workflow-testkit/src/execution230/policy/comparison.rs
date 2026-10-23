//! Single-pair tuning comparisons. No causal inference from scripted wall time.
use super::*;

#[cfg(test)]
mod tests;
use std::{collections::BTreeMap, io::Write, process::Stdio};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    baseline: PathBuf,
    candidate: PathBuf,
    baseline_campaign_digest: String,
    candidate_campaign_digest: String,
    baseline_cases_digest: String,
    max_regression_bps: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    config_only: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

fn saved(root: &Path) -> Result<Campaign, String> {
    let campaign: Campaign = read(&root.join("campaign.json"))?;
    validate_split(&campaign.split, &campaign.registry).map_err(|e| e.message)?;
    Ok(campaign)
}
fn cases(root: &Path, campaign: &Campaign) -> Result<(Operation, Vec<ExecutedCase>), String> {
    let mut ops = operations(root).map_err(|e| e.message)?;
    if ops.len() != 1 {
        return Err("comparison requires exactly one complete regression operation; no holdout, selection or repeated history".to_owned());
    }
    let op = ops.remove(0);
    if op.mode != SuiteMode::Regression
        || op.repeats != 1
        || op.selected_case_ids != campaign.split.tuning
        || op.identity.campaign_digest != hash(campaign).map_err(|e| e.message)?
        || op.baseline.is_some()
        || op.measurement_digest.is_some()
    {
        return Err("comparison requires the entire frozen tuning partition".to_owned());
    }
    let selected = campaign
        .registry
        .iter()
        .filter(|c| campaign.split.tuning.contains(&c.workflow.case_id))
        .cloned()
        .collect();
    let cases =
        journal::completed_snapshot(&run_path(&op.identity), selected, op.identity.clone())?;
    for case in &cases {
        if case.status != ScriptedStatus::Succeeded || case.elapsed_ns.is_none_or(|n| n == 0) {
            return Err("unsupported or missing elapsed_ns measurement".to_owned());
        }
        let receipt = case.receipt.as_ref().ok_or("missing runtime receipt")?;
        if digest(&fs::read(receipt.run_root().join("workflow.toml")).map_err(error)?)
            != case.manifest.workflow_digest
        {
            return Err("runtime workflow source mismatch".to_owned());
        }
    }
    Ok((op, cases))
}

fn compatible(baseline: &Campaign, candidate: &Campaign, config_only: bool) -> Result<(), String> {
    let first = baseline.registry.first().ok_or("empty registry")?;
    let next = candidate.registry.first().ok_or("empty registry")?;
    if config_only {
        // source() below proves every registry row shares this source and executable.
        // Config schema is fixed; distinct loop-policy values produce distinct profile bytes.
        if first.manifest.source_revision != next.manifest.source_revision
            || first.manifest.source_tree != next.manifest.source_tree
            || first.manifest.source_files_digest != next.manifest.source_files_digest
            || first.manifest.executable_digest != next.manifest.executable_digest
            || baseline.config.is_none()
            || candidate.config.is_none()
            || baseline.config == candidate.config
        {
            return Err("config-only requires identical source/executable and distinct explicit loop-budget configs".to_owned());
        }
    } else if first.manifest.source_revision == next.manifest.source_revision {
        return Err(
            "comparison requires distinct committed revisions, not same-revision runs".to_owned(),
        );
    }
    if baseline.split != candidate.split || baseline.registry.len() != candidate.registry.len() {
        return Err("comparison split or registry mismatch".to_owned());
    }
    for (a, b) in baseline.registry.iter().zip(&candidate.registry) {
        if a.workflow != b.workflow
            || a.manifest.workflow_digest != b.manifest.workflow_digest
            || (!config_only && a.manifest.config_digest != b.manifest.config_digest)
            || a.manifest.model_digest != b.manifest.model_digest
            || a.manifest.dataset_digest != b.manifest.dataset_digest
        {
            return Err("paired workflow/config/model/input identity mismatch".to_owned());
        }
    }
    Ok(())
}

// Read Git objects only: never check out, copy, or execute the historical source.
// ponytail: source blobs fit in memory here; stream the batch if repository size grows.
fn committed_files(repo: &Path, revision: &str) -> Result<BTreeMap<String, Vec<u8>>, String> {
    if ![40, 64].contains(&revision.len())
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid committed revision".to_owned());
    }
    if git(
        repo,
        &[
            "--no-replace-objects",
            "rev-parse",
            &format!("{revision}^{{commit}}"),
        ],
    )? != revision
    {
        return Err("revision is not a commit".to_owned());
    }
    let names = git(
        repo,
        &[
            "--no-replace-objects",
            "ls-tree",
            "-r",
            "--name-only",
            "-z",
            revision,
        ],
    )?;
    let names = names
        .split('\0')
        .filter(|n| !n.is_empty())
        .collect::<BTreeSet<_>>();
    if names.iter().any(|n| n.contains(['\n', '\r'])) {
        return Err("unsupported source filename".to_owned());
    }
    let requests = names
        .iter()
        .map(|n| format!("{revision}:{n}\n"))
        .collect::<String>();
    let mut child = Command::new("git")
        .current_dir(repo)
        .args(["--no-replace-objects", "cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(error)?;
    let mut stdin = child.stdin.take().ok_or("missing git stdin")?;
    // Drain stdout concurrently with writing requests; neither pipe may deadlock.
    let writer = std::thread::spawn(move || stdin.write_all(requests.as_bytes()));
    let result = child.wait_with_output().map_err(error)?;
    writer
        .join()
        .map_err(|_| "git request writer panicked")?
        .map_err(error)?;
    if !result.status.success() {
        return Err("source object read failed".to_owned());
    }
    let mut bytes = result.stdout.as_slice();
    let mut files = BTreeMap::new();
    for name in names {
        let end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("missing object header")?;
        let header = std::str::from_utf8(&bytes[..end])
            .map_err(error)?
            .split_whitespace()
            .collect::<Vec<_>>();
        if header.len() != 3 || header[1] != "blob" {
            return Err("source must contain only blobs".to_owned());
        }
        let size = header[2].parse::<usize>().map_err(error)?;
        bytes = bytes.get(end + 1..).ok_or("truncated object")?;
        let content = bytes.get(..size).ok_or("truncated blob")?.to_vec();
        if bytes.get(size) != Some(&b'\n') {
            return Err("invalid object separator".to_owned());
        }
        bytes = bytes.get(size + 1..).ok_or("truncated object")?;
        files.insert(name.to_owned(), content);
    }
    if !bytes.is_empty() {
        return Err("unexpected source object data".to_owned());
    }
    Ok(files)
}
fn source(repo: &Path, campaign: &Campaign) -> Result<(), String> {
    let first = &campaign.registry.first().ok_or("empty registry")?.manifest;
    if !first
        .executable_digest
        .strip_prefix("sha256:")
        .is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("invalid executable identity".to_owned());
    }
    let files = committed_files(repo, &first.source_revision)?;
    let tree = git(
        repo,
        &[
            "--no-replace-objects",
            "rev-parse",
            &format!("{}^{{tree}}", first.source_revision),
        ],
    )?;
    let mut hasher = Sha256::new();
    for (name, bytes) in &files {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let source_digest = format!("sha256:{:x}", hasher.finalize());
    let workflows = files
        .keys()
        .filter(|p| {
            let parts = p.split('/').collect::<Vec<_>>();
            parts.len() == 3
                && matches!(parts[0], "examples" | "templates")
                && parts[2] == "workflow.toml"
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let registered = campaign
        .registry
        .iter()
        .map(|c| c.workflow.source.clone())
        .collect::<BTreeSet<_>>();
    if workflows != registered || registered.len() != campaign.registry.len() {
        return Err("committed workflow registry mismatch".to_owned());
    }
    for case in &campaign.registry {
        let m = &case.manifest;
        if m.source_revision != first.source_revision
            || m.source_tree != tree
            || m.source_files_digest != source_digest
            || m.executable_digest != first.executable_digest
            || m.workflow_source != case.workflow.source
            || m.workflow_digest != digest(files.get(&m.workflow_source).ok_or("missing workflow")?)
        {
            return Err(
                "committed source identity mismatch (dirty or foreign snapshot)".to_owned(),
            );
        }
        let mut expected = m.clone();
        expected.config_digest = None;
        expected.model_digest = None;
        expected.dataset_digest = None;
        if let Some((mut profile, input)) = scripted_inputs_with(&m.workflow_source, |path| {
            serde_json::from_slice(files.get(path).ok_or("missing committed scripted input")?)
                .map_err(error)
        })? {
            if let Some(config) = &campaign.config {
                config.apply(&mut profile)?;
            }
            bind_inputs(&mut expected, &profile, &input)?;
        }
        if expected != *m {
            return Err("committed config/model/input identity mismatch".to_owned());
        }
    }
    Ok(())
}

pub(super) fn admission(
    root: &Path,
    mode: SuiteMode,
    ordinal: usize,
) -> Result<Option<String>, String> {
    let path = root.join("comparison.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(e)),
        Ok(_) => {
            if mode != SuiteMode::Regression || ordinal != 0 {
                return Err("comparison campaign admits one regression only".to_owned());
            }
            let plan: Plan = read(&path)?;
            if plan.schema_version != 1 || plan.candidate != root {
                return Err("comparison plan identity mismatch".to_owned());
            }
            Ok(Some(hash(&plan).map_err(|e| e.message)?))
        }
    }
}
fn declare(
    repo: &Path,
    baseline: &Path,
    candidate: &Path,
    threshold: &str,
    config_only: bool,
) -> Result<Value, String> {
    let max_regression_bps = threshold.parse::<u32>().map_err(error)?;
    let _baseline_lock = journal::lock(baseline)?;
    let _candidate_lock = journal::lock(candidate)?;
    let baseline = fs::canonicalize(baseline).map_err(error)?;
    let candidate = fs::canonicalize(candidate).map_err(error)?;
    if !operations(&candidate).map_err(|e| e.message)?.is_empty()
        || candidate.join("comparison.json").exists()
    {
        return Err("predeclare threshold before candidate execution; plan is one-shot".to_owned());
    }
    let a = saved(&baseline)?;
    let b = saved(&candidate)?;
    let (_, rows) = cases(&baseline, &a)?;
    compatible(&a, &b, config_only)?;
    source(repo, &a)?;
    source(repo, &b)?;
    let plan = Plan {
        schema_version: 1,
        baseline,
        candidate: candidate.clone(),
        baseline_campaign_digest: hash(&a).map_err(|e| e.message)?,
        candidate_campaign_digest: hash(&b).map_err(|e| e.message)?,
        baseline_cases_digest: hash(&rows).map_err(|e| e.message)?,
        max_regression_bps,
        config_only,
    };
    atomic(&candidate, "comparison.json", &plan)?;
    Ok(
        json!({"schema_version":1,"comparison_plan_digest":hash(&plan).map_err(|e| e.message)?,"max_regression_bps":max_regression_bps}),
    )
}
fn exceeds(baseline: u64, candidate: u64, bps: u32) -> bool {
    u128::from(candidate) * 10_000 > u128::from(baseline) * (10_000 + u128::from(bps))
}
fn report(repo: &Path, candidate: &Path) -> Result<Value, String> {
    let _candidate_lock = journal::lock(candidate)?;
    let candidate = fs::canonicalize(candidate).map_err(error)?;
    let plan: Plan = read(&candidate.join("comparison.json"))?;
    if plan.schema_version != 1 || plan.candidate != candidate {
        return Err("comparison plan identity mismatch".to_owned());
    }
    let _baseline_lock = journal::lock(&plan.baseline)?;
    let a = saved(&plan.baseline)?;
    let b = saved(&candidate)?;
    let (_, baseline) = cases(&plan.baseline, &a)?;
    let (op, current) = cases(&candidate, &b)?;
    compatible(&a, &b, plan.config_only)?;
    source(repo, &a)?;
    source(repo, &b)?;
    let plan_digest = hash(&plan).map_err(|e| e.message)?;
    if hash(&a).map_err(|e| e.message)? != plan.baseline_campaign_digest
        || hash(&b).map_err(|e| e.message)? != plan.candidate_campaign_digest
        || hash(&baseline).map_err(|e| e.message)? != plan.baseline_cases_digest
        || op.comparison_digest.as_ref() != Some(&plan_digest)
    {
        return Err("predeclared comparison identity/evidence mismatch".to_owned());
    }
    let mut rows = Vec::new();
    let mut failed = false;
    let mut run_ids = BTreeSet::new();
    for (a, b) in baseline.iter().zip(&current) {
        if a.case_id != b.case_id {
            return Err("paired case mismatch".to_owned());
        }
        for case in [a, b] {
            if !run_ids.insert(case.admitted_run_id.as_ref().ok_or("missing run id")?) {
                return Err("duplicate runtime observation".to_owned());
            }
        }
        let before = a.elapsed_ns.ok_or("missing elapsed_ns")?;
        let after = b.elapsed_ns.ok_or("missing elapsed_ns")?;
        let delta = i128::from(after) - i128::from(before);
        let delta_ns = i64::try_from(delta).map_err(error)?;
        let delta_bps = i64::try_from(delta * 10_000 / i128::from(before)).map_err(error)?;
        let regression = exceeds(before, after, plan.max_regression_bps);
        failed |= regression;
        rows.push(json!({"case_id":a.case_id,"baseline_elapsed_ns":before,"candidate_elapsed_ns":after,
            "delta_ns":delta_ns,"delta_bps":delta_bps,
            "performance_target_failed":regression,"baseline_run_id":a.admitted_run_id,"candidate_run_id":b.admitted_run_id,"baseline_manifest":a.manifest,"candidate_manifest":b.manifest}));
    }
    Ok(
        json!({"schema_version":1,"evidence_kind":"paired_scripted_execution","live_executed":false,
        "comparison_plan_digest":plan_digest,"config_only":plan.config_only,"baseline_campaign_digest":plan.baseline_campaign_digest,
        "candidate_campaign_digest":plan.candidate_campaign_digest,"baseline_cases_digest":plan.baseline_cases_digest,
        "candidate_cases_digest":hash(&current).map_err(|e| e.message)?,
        "baseline_source_revision":a.registry[0].manifest.source_revision,"candidate_source_revision":b.registry[0].manifest.source_revision,
        "max_regression_bps":plan.max_regression_bps,"cases":rows,"hard_invariant_failed":false,
        "performance_target_failed":failed,"uncertainty_interval":null,
        "uncertainty_unavailable_reason":"one observation per revision/case; independent repeated sampling not established"}),
    )
}

pub(crate) fn command(args: &[&str]) -> Result<(String, bool), String> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = match args {
        ["compare-plan", baseline, candidate, bps] => {
            declare(&repo, Path::new(baseline), Path::new(candidate), bps, false)
        }
        ["compare-plan", baseline, candidate, bps, "config-only"] => {
            declare(&repo, Path::new(baseline), Path::new(candidate), bps, true)
        }
        ["compare", candidate] => report(&repo, Path::new(candidate)),
        _ => Err("invalid comparison command".to_owned()),
    };
    let (value, failed) = match result {
        Ok(value) => {
            let failed = value["performance_target_failed"] == true;
            (value, failed)
        }
        Err(message) => (
            json!({"hard_invariant_failed":true,"error":{"kind":"invalid_comparison","message":message}}),
            true,
        ),
    };
    serde_json::to_string_pretty(&value)
        .map(|json| (json + "\n", failed))
        .map_err(error)
}
