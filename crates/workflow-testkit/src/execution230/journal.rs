//! Private-directory journal. Completion publication is atomic, execution is not exactly-once.
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseIdentity {
    pub(super) workflow: ScriptedWorkflow,
    pub(super) manifest: ExecutionManifest,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    schema_version: u32,
    output_directory: PathBuf,
    cases: Vec<CaseIdentity>,
    policy: Option<policy::RunIdentity>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    case_id: String,
    manifest: ExecutionManifest,
    run_id: String,
}

fn expected(
    repo: &Path,
    output: &Path,
    policy: Option<policy::RunIdentity>,
) -> Result<Suite, String> {
    let cases = if let Some(identity) = &policy {
        policy::selected(repo, output, identity).map_err(|e| e.message)?
    } else {
        registry(repo)?
    };
    Ok(Suite {
        schema_version: 2,
        output_directory: output.to_owned(),
        cases,
        policy,
    })
}

pub(super) fn registry(repo: &Path) -> Result<Vec<CaseIdentity>, String> {
    Ok(manifests(repo)?
        .into_iter()
        .map(|(workflow, manifest)| CaseIdentity { workflow, manifest })
        .collect())
}

// Resolve configured directory symlinks without changing their names or targets.
// The resolved directory remains private and caller-owned, with safe existing ancestry.
pub(super) fn lock(output: &Path) -> Result<fs::File, String> {
    let directory = fs::canonicalize(output).map_err(error)?;
    let owner = fs::metadata(&directory).map_err(error)?;
    // SAFETY: geteuid has no arguments and does not transfer ownership.
    let uid = unsafe { libc::geteuid() };
    if !owner.is_dir() || owner.uid() != uid || owner.mode() & 0o077 != 0 {
        return Err("suite directory must be private and caller-owned".to_owned());
    }
    for path in directory.ancestors() {
        let metadata = fs::metadata(path).map_err(error)?;
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            return Err("unsafe suite directory ancestry".to_owned());
        }
    }
    let path = directory.join("suite.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(error)?;
    let opened = file.metadata().map_err(error)?;
    let named = fs::symlink_metadata(&path).map_err(error)?;
    let current = fs::metadata(&directory).map_err(error)?;
    if !opened.is_file()
        || opened.uid() != uid
        || opened.mode() & 0o077 != 0
        || opened.nlink() != 1
        || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
        || !named.is_file()
        || (current.dev(), current.ino()) != (owner.dev(), owner.ino())
    {
        return Err("invalid suite lock identity".to_owned());
    }
    file.try_lock()
        .map_err(|_| "suite is already locked".to_owned())?;
    Ok(file)
}

pub(super) fn atomic(output: &Path, name: &str, value: &impl Serialize) -> Result<(), String> {
    let pending = output
        .join(output_path()?.file_name().ok_or("missing temporary name")?)
        .with_extension("pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)
        .map_err(error)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(error)?;
    file.sync_all().map_err(error)?;
    fs::rename(&pending, output.join(name)).map_err(error)?;
    fs::File::open(output)
        .and_then(|dir| dir.sync_all())
        .map_err(error)
}

pub(super) fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    if !fs::symlink_metadata(path).map_err(error)?.is_file() {
        return Err("journal entry is not a regular file".to_owned());
    }
    serde_json::from_slice(&fs::read(path).map_err(error)?).map_err(error)
}

fn optional<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => read(path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(e)),
    }
}

fn validate(
    suite: &Suite,
    abandon: Option<(&str, &str)>,
) -> Result<Vec<Option<ExecutedCase>>, String> {
    for entry in fs::read_dir(&suite.output_directory).map_err(error)? {
        let name = entry.map_err(error)?.file_name();
        let name = name.to_str().ok_or("non-UTF8 journal filename")?;
        if (name.starts_with("case-") || name.starts_with("admission-"))
            && !(0..suite.cases.len())
                .any(|i| name == format!("case-{i}.json") || name == format!("admission-{i}.json"))
        {
            return Err("unexpected journal record".to_owned());
        }
    }
    let mut completed = Vec::new();
    for (index, identity) in suite.cases.iter().enumerate() {
        let admission: Option<Admission> = optional(
            &suite
                .output_directory
                .join(format!("admission-{index}.json")),
        )?;
        let case: Option<ExecutedCase> =
            optional(&suite.output_directory.join(format!("case-{index}.json")))?;
        if let Some(admission) = &admission {
            if admission.case_id != identity.workflow.case_id
                || admission.manifest != identity.manifest
                || admission.run_id.is_empty()
            {
                return Err("admission identity mismatch".to_owned());
            }
            if case.is_none() && abandon != Some((&admission.case_id, &admission.run_id)) {
                return Err(format!(
                    "in-flight case {} run {}; explicit recovery required; no replay",
                    admission.case_id, admission.run_id
                ));
            }
        }
        if let Some(case) = &case {
            validate_evidence(case)?;
            if case.case_id != identity.workflow.case_id
                || case.manifest != identity.manifest
                || case.admitted_run_id.as_deref() != admission.as_ref().map(|a| a.run_id.as_str())
            {
                return Err("completed case identity mismatch".to_owned());
            }
            if let Some(receipt) = &case.receipt
                && (Some(receipt.run_id()) != case.admitted_run_id.as_deref()
                    || receipt.run_root().parent()
                        != Some(suite.output_directory.join("runs").as_path())
                    || !durable_receipt_matches(&suite.output_directory.join("runs"), receipt)?
                    || Some(digest(
                        &fs::read(receipt.run_root().join("events.jsonl")).map_err(error)?,
                    )) != case.events_digest)
            {
                return Err("completed execution evidence mismatch".to_owned());
            }
        }
        completed.push(case);
    }
    Ok(completed)
}

pub(super) fn durable_receipt_matches(
    runs: &Path,
    receipt: &ExecutionReceipt,
) -> Result<bool, String> {
    let current = ExecutionBackend::inspect(runs, receipt.run_id()).map_err(error)?;
    let mut current = serde_json::to_value(current).map_err(error)?;
    let mut original = serde_json::to_value(receipt).map_err(error)?;
    // `inspect` recomputes inventory of the shared cache, not the historical snapshot.
    // Retain that original observation unchanged; compare every durable receipt field.
    for projection in [&mut current, &mut original] {
        projection
            .as_object_mut()
            .ok_or("invalid receipt shape")?
            .remove("node_cache");
    }
    Ok(current == original)
}

pub(super) fn validate_evidence(case: &ExecutedCase) -> Result<(), String> {
    let valid = match case.status {
        ScriptedStatus::Succeeded => {
            case.hard_invariant_failures.is_empty()
                && case.unsupported_reason.is_none()
                && case
                    .receipt
                    .as_ref()
                    .is_some_and(|r| r.status() == "succeeded")
                && case.elapsed_ns.is_some()
        }
        ScriptedStatus::Failed => {
            !case.hard_invariant_failures.is_empty() && case.unsupported_reason.is_none()
        }
        ScriptedStatus::Unsupported => {
            case.unsupported_reason.is_some()
                && case.hard_invariant_failures.is_empty()
                && case.receipt.is_none()
                && case.elapsed_ns.is_none()
                && case.admitted_run_id.is_none()
        }
    };
    if !valid || case.receipt.is_some() != case.events_digest.is_some() {
        return Err("invalid completion evidence".to_owned());
    }
    Ok(())
}

/// Explicitly dispose of ambiguity, never infer that unknown effects did not occur.
pub(super) fn abandon(
    repo: &Path,
    output: &Path,
    case_id: &str,
    run_id: &str,
) -> Result<(), String> {
    let output = fs::canonicalize(output).map_err(error)?;
    let _lock = lock(&output)?;
    let saved: Suite = read(&output.join("suite.json"))?;
    let _campaign_lock = saved
        .policy
        .as_ref()
        .map(|i| lock(&i.campaign))
        .transpose()?;
    let suite = expected(repo, &output, saved.policy)?;
    if read::<Suite>(&output.join("suite.json"))? != suite {
        return Err("suite identity mismatch".to_owned());
    }
    let index = suite
        .cases
        .iter()
        .position(|c| c.workflow.case_id == case_id)
        .ok_or("unknown case")?;
    let admission: Admission = read(&output.join(format!("admission-{index}.json")))?;
    if admission.run_id != run_id {
        return Err("admission identity mismatch".to_owned());
    }
    let completed = validate(&suite, Some((case_id, run_id)))?;
    if completed.get(index).is_none_or(Option::is_some) {
        return Err("case is already completed".to_owned());
    }
    atomic(
        &output,
        &format!("case-{index}.json"),
        &ExecutedCase {
            case_id: case_id.to_owned(),
            manifest: admission.manifest,
            status: ScriptedStatus::Failed,
            receipt: None,
            admitted_run_id: Some(run_id.to_owned()),
            elapsed_ns: None,
            events_digest: None,
            hard_invariant_failures: vec![
                "explicitly abandoned in-flight run; effects unknown; not replayed".to_owned(),
            ],
            unsupported_reason: None,
        },
    )
}

pub(super) fn run(repo: &Path, output: &Path, resume: bool) -> Result<ExecutionReport, String> {
    let identity = if resume {
        read::<Suite>(&output.join("suite.json"))?.policy
    } else {
        None
    };
    let _campaign_lock = identity.as_ref().map(|i| lock(&i.campaign)).transpose()?;
    run_selected(repo, output, resume, identity)
}

pub(super) fn completed(
    repo: &Path,
    output: &Path,
    identity: policy::RunIdentity,
) -> Result<Vec<ExecutedCase>, String> {
    let _lock = lock(output)?;
    let suite = expected(repo, output, Some(identity))?;
    if read::<Suite>(&output.join("suite.json"))? != suite {
        return Err("suite identity mismatch".to_owned());
    }
    validate(&suite, None)?
        .into_iter()
        .map(|case| case.ok_or_else(|| "incomplete policy operation".to_owned()))
        .collect()
}

/// Validate archived evidence without comparing it to the current checkout.
/// The caller must independently authenticate the supplied historical identities.
pub(super) fn completed_snapshot(
    output: &Path,
    cases: Vec<CaseIdentity>,
    identity: policy::RunIdentity,
) -> Result<Vec<ExecutedCase>, String> {
    let _lock = lock(output)?;
    let expected = Suite {
        schema_version: 2,
        output_directory: output.to_owned(),
        cases,
        policy: Some(identity),
    };
    if read::<Suite>(&output.join("suite.json"))? != expected {
        return Err("suite identity mismatch".to_owned());
    }
    validate(&expected, None)?
        .into_iter()
        .map(|case| case.ok_or_else(|| "incomplete comparison operation".to_owned()))
        .collect()
}

pub(super) fn run_selected(
    repo: &Path,
    output: &Path,
    resume: bool,
    identity: Option<policy::RunIdentity>,
) -> Result<ExecutionReport, String> {
    if !resume {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output)
            .map_err(error)?;
    }
    let output = fs::canonicalize(output).map_err(error)?;
    let _lock = lock(&output)?;
    let suite = expected(repo, &output, identity)?;
    if resume {
        if read::<Suite>(&output.join("suite.json"))? != suite {
            return Err("suite identity mismatch".to_owned());
        }
    } else {
        fs::create_dir(output.join("runs")).map_err(error)?;
        atomic(&output, "suite.json", &suite)?;
        fs::File::open(output.parent().ok_or("suite parent missing")?)
            .and_then(|dir| dir.sync_all())
            .map_err(error)?;
    }
    // Validate every completion/admission before starting any further case.
    let completed = validate(&suite, None)?;
    let mut cases = Vec::new();
    for (index, (identity, previous)) in suite.cases.iter().zip(completed).enumerate() {
        if let Some(previous) = previous {
            cases.push(previous);
            continue;
        }
        if expected(repo, &output, suite.policy.clone())? != suite {
            return Err("source changed during smoke".to_owned());
        }
        if let Some(identity) = &suite.policy {
            policy::allow_execution(identity).map_err(|e| e.message)?;
        }
        let case = execute_case_with_inputs(
            repo,
            &output.join("runs"),
            &identity.workflow,
            identity.manifest.clone(),
            policy::inputs(repo, &identity.workflow.source, suite.policy.as_ref())?,
            |run_id| {
                atomic(
                    &output,
                    &format!("admission-{index}.json"),
                    &Admission {
                        case_id: identity.workflow.case_id.clone(),
                        manifest: identity.manifest.clone(),
                        run_id: run_id.to_owned(),
                    },
                )
                .map_err(std::io::Error::other)
            },
        )?;
        if expected(repo, &output, suite.policy.clone())? != suite {
            return Err("source changed during smoke".to_owned());
        }
        atomic(&output, &format!("case-{index}.json"), &case)?;
        cases.push(case);
    }
    Ok(ExecutionReport {
        schema_version: 2,
        evidence_kind: "scripted_execution",
        live_executed: false,
        output_directory: output,
        hard_invariant_failed: cases
            .iter()
            .any(|case| case.status != ScriptedStatus::Succeeded),
        cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn admission_owner_accepts_private_directory_symlink_without_changing_identity() {
        let root = output_path().unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.join("state");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.join("configured-state");
        symlink(&target, &alias).unwrap();
        let before = fs::symlink_metadata(&alias).unwrap();
        let guard = lock(&alias).expect("configured directory symlink is supported");
        let after = fs::symlink_metadata(&alias).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(after.file_type().is_symlink());
        assert!(
            lock(&target).is_err(),
            "both names must share one exclusive lock"
        );
        drop(guard);
        assert!(lock(&target).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn admission_owner_rejects_unsafe_lock_objects_without_modifying_them() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let root = output_path().unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = root.join("foreign");
        fs::write(&foreign, b"unchanged").unwrap();
        let path = root.join("suite.lock");
        symlink(&foreign, &path).unwrap();
        assert!(lock(&root).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"unchanged");
        fs::remove_file(&path).unwrap();
        fs::hard_link(&foreign, &path).unwrap();
        assert!(lock(&root).is_err());
        fs::remove_file(&path).unwrap();
        let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo is a valid NUL-terminated, owned fixture pathname.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(lock(&root).is_err());
        fs::remove_file(&path).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(lock(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
