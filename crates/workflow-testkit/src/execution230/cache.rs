//! Bounded, single-agent result-cache experiment. No provider KV measurements.
//! Each arm owns a fresh cache; only the declared order/capacity/input changes.
//! ponytail: single-agent sequential probe; generalize only with node-level controls.
use super::*;
use std::{
    collections::BTreeMap,
    os::unix::fs::{DirBuilderExt, MetadataExt},
};
use workflow_runtime::{NodeCacheRetention, NodeResultCache};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Step {
    arm: String,
    variant: String,
    invalidate_before: bool,
    retain_after: Option<usize>,
    expected_content_cache_class: Option<String>,
    identity: journal::CaseIdentity,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Experiment {
    schema_version: u32,
    output_directory: PathBuf,
    trust_domain: String,
    cache_protocol: String,
    pressure_policy: String,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheState {
    entries: usize,
    digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    experiment_digest: String,
    step: usize,
    run_id: String,
    cache_before: CacheState,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    step: usize,
    case: ExecutedCase,
    content_cache_class: String,
    removed_entries: usize,
    cache_entries_after: usize,
    cache_after: CacheState,
}

fn inputs(repo: &Path, variant: &str) -> Result<(Value, Value), String> {
    let (profile, mut input) = scripted_inputs(repo, "examples/00-runtime-smoke/workflow.toml")?
        .ok_or("missing runtime-smoke adapter")?;
    if variant == "B" {
        // A changed request is a negative cache-key control, not an equivalent case.
        input
            .as_object_mut()
            .ok_or("input must be an object")?
            .insert(
                "request".to_owned(),
                json!("content-cache key invalidation control B"),
            );
    }
    Ok((profile, input))
}

fn expected(repo: &Path, output: &Path) -> Result<Experiment, String> {
    let identity = journal::registry(repo)?
        .into_iter()
        .find(|c| c.workflow.case_id == "runtime-smoke")
        .ok_or("missing runtime-smoke")?;
    let mut steps = Vec::new();
    for (arm, variants, retain_after) in [
        ("unbounded-grouped", "AABBA", None),
        ("capacity-one-grouped", "AABBA", Some(1)),
        ("capacity-one-interleaved", "ABABA", Some(1)),
        ("explicit-invalidation", "AAA", None),
    ] {
        for (index, variant) in variants.chars().enumerate() {
            let variant = variant.to_string();
            let mut identity = identity.clone();
            let (profile, input) = inputs(repo, &variant)?;
            bind_inputs(&mut identity.manifest, &profile, &input)?;
            steps.push(Step {
                arm: arm.to_owned(),
                variant,
                invalidate_before: arm == "explicit-invalidation" && index == 2,
                retain_after,
                expected_content_cache_class: if retain_after.is_none() {
                    Some(
                        if index == 0 || index == 2 {
                            "cold"
                        } else {
                            "warm"
                        }
                        .to_owned(),
                    )
                } else {
                    None
                },
                identity,
            });
        }
    }
    Ok(Experiment {
        schema_version: 1,
        output_directory: output.to_owned(),
        trust_domain: workflow_runtime::TrustDomain::TrustedGoal
            .cache_salt()
            .to_owned(),
        cache_protocol: format!(
            "{}/node-result-schema-{}",
            workflow_adk::model_invocation::PROMPT_PROTOCOL_VERSION,
            workflow_runtime::NODE_CACHE_SCHEMA_VERSION
        ),
        pressure_policy: "NodeResultCache::gc/digest-order/post-run-capacity-not-LRU-v1".to_owned(),
        steps,
    })
}

fn runs(output: &Path, step: &Step) -> PathBuf {
    output.join(&step.arm)
}

// Before admission, open may leave any prefix of this empty scaffold. Under the
// private experiment's cooperative lock, validate every component before reuse;
// never follow links, delete contents, or accept entries/runtime runs. Like the
// journal, this is not a boundary against concurrent same-owner mutation.
fn empty_owned_arm(runs: &Path) -> Result<(), String> {
    let mut directory = runs.to_owned();
    for child in [Some(".node-result-cache"), Some("entries"), None] {
        let meta = fs::symlink_metadata(&directory).map_err(error)?;
        if !meta.is_dir() {
            return Err("unexpected cache arm".to_owned());
        }
        // SAFETY: geteuid has no preconditions or pointer arguments.
        if meta.uid() != unsafe { libc_geteuid() } || meta.mode() & 0o022 != 0 {
            return Err("unexpected cache arm owner or permissions".to_owned());
        }
        let mut entries = fs::read_dir(&directory).map_err(error)?;
        let Some(entry) = entries.next().transpose().map_err(error)? else {
            return Ok(());
        };
        if child.is_none_or(|name| entry.file_name() != name)
            || entries.next().transpose().map_err(error)?.is_some()
        {
            return Err("unexpected cache arm contents".to_owned());
        }
        directory = entry.path();
    }
    Err("unexpected cache arm contents".to_owned())
}

unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: Linux uid_t is u32; geteuid takes no arguments and accesses no Rust memory.
    unsafe { geteuid() }
}

fn crash_before_admission(barrier: &str) {
    let Ok(configured) = std::env::var("WORKFLOW_KIT_TEST_CRASH_BARRIER") else {
        return;
    };
    let (name, hit) = configured
        .rsplit_once('#')
        .and_then(|(name, hit)| hit.parse::<u64>().ok().map(|hit| (name, hit)))
        .unwrap_or((configured.as_str(), 1));
    if name != barrier {
        return;
    }
    static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1 == hit {
        // SAFETY: The existing Linux x86_64 wrapper signals only this process, without pointers.
        unsafe { libc_kill_self() };
    }
}

unsafe fn libc_kill_self() {
    unsafe extern "C" {
        fn syscall(number: i64, ...) -> i64;
    }
    const SYS_KILL: i64 = 62;
    const SIGKILL: i64 = 9;
    // SAFETY: Linux x86_64 syscall uses signed 64-bit long; syscall 62 is kill.
    // Its integer arguments are this process's positive PID and SIGKILL, with no pointers.
    unsafe {
        syscall(SYS_KILL, libc_getpid(), SIGKILL);
    }
}

unsafe fn libc_getpid() -> i32 {
    unsafe extern "C" {
        fn getpid() -> i32;
    }
    // SAFETY: Linux pid_t is i32; getpid takes no arguments and accesses no Rust memory.
    unsafe { getpid() }
}
fn cache(runs: &Path) -> Result<NodeResultCache, String> {
    NodeResultCache::open(runs.join(".node-result-cache")).map_err(error)
}
fn state(cache: &NodeResultCache) -> Result<CacheState, String> {
    Ok(CacheState {
        entries: cache.inspect().map_err(error)?.entry_count(),
        digest: digest(&cache.export().map_err(error)?),
    })
}

// This narrow experiment admits one cacheable agent. Never infer warmth from order,
// elapsed time, inventory size, or a model response. Read real node receipts/events.
fn classify(case: &ExecutedCase) -> Result<String, String> {
    let receipt = case
        .receipt
        .as_ref()
        .ok_or("missing cache execution receipt")?;
    if case.status != ScriptedStatus::Succeeded
        || receipt.status() != "succeeded"
        || !case.hard_invariant_failures.is_empty()
        || case.unsupported_reason.is_some()
        || case.elapsed_ns.is_none_or(|ns| ns == 0)
    {
        return Err("unsuccessful cache experiment execution".to_owned());
    }
    let raw = serde_json::to_value(receipt).map_err(error)?;
    let dispositions = raw["cache_dispositions"]
        .as_object()
        .ok_or("missing cache dispositions")?;
    if dispositions.len() != 1 {
        return Err("expected exactly one cacheable agent".to_owned());
    }
    let disposition = dispositions
        .get("agent")
        .and_then(Value::as_str)
        .ok_or("missing agent disposition")?;
    let bytes = fs::read(receipt.run_root().join("events.jsonl")).map_err(error)?;
    if case.events_digest != Some(digest(&bytes)) {
        return Err("cache event digest mismatch".to_owned());
    }
    let events: Vec<Value> = String::from_utf8(bytes)
        .map_err(error)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(error))
        .collect::<Result<_, _>>()?;
    let turns = events
        .iter()
        .filter(|e| e["kind"] == "model_request_completed")
        .count();
    let nodes: Vec<_> = events
        .iter()
        .filter(|e| e["kind"] == "node_completed" && e["node_id"] == "agent")
        .collect();
    if nodes.len() != 1
        || nodes[0]["payload"]["cache_disposition"] != disposition
        || raw["event_counts"]["model_turns"].as_u64() != Some(turns as u64)
    {
        return Err("cache event/receipt mismatch".to_owned());
    }
    let (class, hits, reexecuted) = match (disposition, turns) {
        ("reused", 0) => ("warm", 1, 0),
        ("recorded", 1..) => ("cold", 0, 0),
        ("reexecuted", 1..) => ("reexecuted", 0, 1),
        _ => return Err("unclassified cache disposition/model execution".to_owned()),
    };
    if raw["event_counts"]["cache_hits"] != hits || raw["event_counts"]["reexecuted"] != reexecuted
    {
        return Err("cache count mismatch".to_owned());
    }
    Ok(class.to_owned())
}

fn validate_observation(
    output: &Path,
    step: &Step,
    admission: &Admission,
    row: &Observation,
) -> Result<(), String> {
    let case = &row.case;
    let receipt = case.receipt.as_ref().ok_or("missing receipt")?;
    let raw = serde_json::to_value(receipt).map_err(error)?;
    let recorded_entries = usize::try_from(
        raw["node_cache"]["entry_count"]
            .as_u64()
            .ok_or("missing inventory")?,
    )
    .map_err(error)?;
    let purged = if step.invalidate_before {
        admission.cache_before.entries
    } else {
        0
    };
    let retained = step
        .retain_after
        .map_or(recorded_entries, |cap| recorded_entries.min(cap));
    let removed = purged
        .checked_add(recorded_entries - retained)
        .ok_or("cache removal count overflow")?;
    if case.case_id != step.identity.workflow.case_id
        || case.manifest != step.identity.manifest
        || case.admitted_run_id.as_deref() != Some(admission.run_id.as_str())
        || receipt.run_id() != admission.run_id
        || receipt.run_root().parent() != Some(runs(output, step).as_path())
        || !journal::durable_receipt_matches(&runs(output, step), receipt)?
        || row.content_cache_class != classify(case)?
        || step
            .expected_content_cache_class
            .as_ref()
            .is_some_and(|expected| expected != &row.content_cache_class)
        || row.step != admission.step
        || row.cache_entries_after != row.cache_after.entries
        || retained != row.cache_entries_after
        || row.removed_entries != removed
    {
        return Err("cache observation evidence mismatch".to_owned());
    }
    Ok(())
}

// Match input variant and its occurrence, not queue position or cached output.
fn paired_comparisons(experiment: &Experiment, rows: &[Observation]) -> Result<Vec<Value>, String> {
    let mut pairs = Vec::new();
    for (control_arm, treatment_arm) in [
        ("unbounded-grouped", "capacity-one-grouped"),
        ("capacity-one-grouped", "capacity-one-interleaved"),
    ] {
        let mut occurrences = BTreeMap::<&str, usize>::new();
        for (control, step) in experiment
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.arm == control_arm)
        {
            let occurrence = occurrences.entry(&step.variant).or_default();
            let (treatment, other) = experiment
                .steps
                .iter()
                .enumerate()
                .filter(|(_, s)| s.arm == treatment_arm && s.variant == step.variant)
                .nth(*occurrence)
                .ok_or("missing paired cache observation")?;
            if step.identity != other.identity {
                return Err("paired cache input mismatch".to_owned());
            }
            let left = rows.get(control).ok_or("missing control observation")?;
            let right = rows.get(treatment).ok_or("missing treatment observation")?;
            let delta = i128::from(right.case.elapsed_ns.ok_or("missing elapsed time")?)
                - i128::from(left.case.elapsed_ns.ok_or("missing elapsed time")?);
            pairs.push(json!({"control_step": control, "treatment_step": treatment,
                "variant": step.variant, "occurrence": *occurrence,
                "elapsed_delta_ns": i64::try_from(delta).map_err(error)?,
                "control_content_cache_class": left.content_cache_class,
                "treatment_content_cache_class": right.content_cache_class}));
            *occurrence += 1;
        }
    }
    Ok(pairs)
}

/// Execute a fixed offline experiment or validate/resume its unstarted units.
/// An in-flight unit fails closed, including interruption during GC. It is never
/// replayed, reconciled into a success, or treated as an observed warm run.
pub(crate) fn command(output: &Path, resume: bool) -> Result<(String, bool), String> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !resume {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output)
            .map_err(error)?;
    }
    let _lock = journal::lock(output)?;
    let output = fs::canonicalize(output).map_err(error)?;
    let experiment = expected(&repo, &output)?;
    if resume {
        if journal::read::<Experiment>(&output.join("experiment.json"))? != experiment {
            return Err("cache experiment identity mismatch".to_owned());
        }
    } else {
        journal::atomic(&output, "experiment.json", &experiment)?;
        fs::File::open(output.parent().ok_or("missing parent")?)
            .and_then(|f| f.sync_all())
            .map_err(error)?;
    }
    let experiment_digest = digest(&serde_json::to_vec(&experiment).map_err(error)?);
    for entry in fs::read_dir(&output).map_err(error)? {
        let name = entry.map_err(error)?.file_name();
        let name = name.to_str().ok_or("invalid filename")?;
        if (name.starts_with("admission-") || name.starts_with("observation-"))
            && !(0..experiment.steps.len()).any(|i| {
                name == format!("admission-{i}.json") || name == format!("observation-{i}.json")
            })
        {
            return Err("unexpected experiment record".to_owned());
        }
    }
    let mut observations = Vec::new();
    let mut latest = BTreeMap::<String, CacheState>::new();
    let mut ids = BTreeSet::new();
    let mut missing = false;
    // Validate the entire prefix and each arm's last cache snapshot before effects.
    for (index, step) in experiment.steps.iter().enumerate() {
        let admission_path = output.join(format!("admission-{index}.json"));
        let row_path = output.join(format!("observation-{index}.json"));
        if !admission_path.try_exists().map_err(error)? {
            if row_path.try_exists().map_err(error)? {
                return Err("completion without admission".to_owned());
            }
            missing = true;
            continue;
        }
        if !row_path.try_exists().map_err(error)? {
            return Err(format!(
                "in-flight cache step {index}; no replay; preserve experiment and start a fresh directory"
            ));
        }
        if missing {
            return Err("non-contiguous experiment journal".to_owned());
        }
        let admission: Admission = journal::read(&admission_path)?;
        if admission.step != index
            || admission.experiment_digest != experiment_digest
            || !ids.insert(admission.run_id.clone())
            || latest
                .get(&step.arm)
                .is_some_and(|s| s != &admission.cache_before)
            || (!latest.contains_key(&step.arm) && admission.cache_before.entries != 0)
        {
            return Err("cache admission identity mismatch".to_owned());
        }
        let row: Observation = journal::read(&row_path)?;
        validate_observation(&output, step, &admission, &row)?;
        latest.insert(
            step.arm.clone(),
            CacheState {
                entries: row.cache_after.entries,
                digest: row.cache_after.digest.clone(),
            },
        );
        observations.push(row);
    }
    for (arm, saved) in &latest {
        if state(&cache(&output.join(arm))?)? != *saved {
            return Err("cache state changed since completion".to_owned());
        }
    }
    let started = Instant::now();
    for (index, step) in experiment.steps.iter().enumerate().skip(observations.len()) {
        if expected(&repo, &output)? != experiment {
            return Err("cache experiment source changed".to_owned());
        }
        let runs = runs(&output, step);
        if !latest.contains_key(&step.arm) {
            match fs::create_dir(&runs) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    empty_owned_arm(&runs)?;
                }
                Err(e) => return Err(error(e)),
            }
            // Test-only: kill after this new arm directory exists and before admission.
            crash_before_admission("after-cache-arm-dir-before-admission");
        }
        let cache = cache(&runs)?;
        if !latest.contains_key(&step.arm) {
            crash_before_admission("after-cache-open-before-admission");
        }
        let before = state(&cache)?;
        let mut removed_entries = 0;
        let case = execute_case_with_inputs(
            &repo,
            &runs,
            &step.identity.workflow,
            step.identity.manifest.clone(),
            Some(inputs(&repo, &step.variant)?),
            |run_id| {
                journal::atomic(
                    &output,
                    &format!("admission-{index}.json"),
                    &Admission {
                        experiment_digest: experiment_digest.clone(),
                        step: index,
                        run_id: run_id.to_owned(),
                        cache_before: before,
                    },
                )
                .map_err(std::io::Error::other)?;
                if step.invalidate_before {
                    removed_entries = cache
                        .gc(NodeCacheRetention {
                            max_entries: Some(0),
                        })
                        .map_err(std::io::Error::other)?;
                }
                Ok(())
            },
        )?;
        let content_cache_class = classify(&case)?;
        removed_entries += cache
            .gc(NodeCacheRetention {
                max_entries: step.retain_after,
            })
            .map_err(error)?;
        let cache_after = state(&cache)?;
        latest.insert(
            step.arm.clone(),
            CacheState {
                entries: cache_after.entries,
                digest: cache_after.digest.clone(),
            },
        );
        let row = Observation {
            step: index,
            case,
            content_cache_class,
            removed_entries,
            cache_entries_after: cache_after.entries,
            cache_after,
        };
        let admission = journal::read(&output.join(format!("admission-{index}.json")))?;
        validate_observation(&output, step, &admission, &row)?;
        if expected(&repo, &output)? != experiment {
            return Err("cache experiment source changed".to_owned());
        }
        journal::atomic(&output, &format!("observation-{index}.json"), &row)?;
        observations.push(row);
        // Progress is a disposable projection; the admission/completion journal is authoritative.
        journal::atomic(
            &output,
            "progress.json",
            &json!({"completed": observations.len(), "total": experiment.steps.len(), "generation_elapsed_ns": started.elapsed().as_nanos().to_string(), "eta_s": null}),
        )?;
    }
    let pairs = paired_comparisons(&experiment, &observations)?;
    let report = json!({
        "schema_version": 1, "evidence_kind": "scripted_content_cache_execution", "live_executed": false,
        "experiment": experiment, "experiment_digest": experiment_digest, "observations": observations,
        "kv_cache_hit": null, "kv_unavailable_reason": "offline fake model has no provider KV/prefix telemetry",
        "paired_comparisons": pairs, "hard_invariant_failed": false,
        "uncertainty": null, "uncertainty_unavailable_reason": "bounded correlated scripted executions; no independent sampling or causal speedup claim",
    });
    Ok((
        serde_json::to_string_pretty(&report).map_err(error)? + "\n",
        false,
    ))
}
