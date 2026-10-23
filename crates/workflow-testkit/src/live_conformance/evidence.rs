//! Quality admission for the canonical retry question, independent of model verdicts.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_json::Value;
use workflow_runtime::{
    ArtifactId, ArtifactStore, CheckpointManifestV1, FilesystemArtifactStore, PageRequest,
    ProtectedArtifactReferenceV1, RunId, SqliteCheckpointStore, ToolEnvelope,
    WorkflowRuntimeEventKindV1, WorkflowRuntimeEventV1,
};
use workflow_spec::{SourcePath, read_bounded_regular_file};

use crate::code_investigation::{
    FixtureRepo, InvestigationAnswer, Snapshot, SourceRange, validate_answer,
};

const FILES: [&str; 3] = ["Cargo.toml", "src/lib.rs", "src/retry.rs"];
const MAX_BYTES: u64 = 1024 * 1024;
// The fixed expected-finding check below applies only to this canonical task.
const CANONICAL_QUESTION: &str = "Where is the default retry path?";
const CANONICAL_PATH: &str = "src";

fn read(path: &Path, limit: u64) -> Result<Vec<u8>, ()> {
    read_bounded_regular_file(
        &SourcePath::from(path),
        usize::try_from(limit).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn snapshot(root: &Path) -> Result<Snapshot, ()> {
    FILES
        .into_iter()
        .map(|path| {
            Ok((
                path.to_owned(),
                String::from_utf8(read(&root.join("repo").join(path), MAX_BYTES)?)
                    .map_err(|_| ())?,
            ))
        })
        .collect::<Result<Vec<_>, ()>>()
        .map(|files| FixtureRepo::from_files(files).snapshot())
}

pub(super) struct Admission {
    root: PathBuf,
    input: String,
    snapshot: Snapshot,
}

#[derive(Deserialize)]
struct HostInput {
    question: String,
    path: String,
    snapshot: HostFacts,
}

#[derive(Deserialize)]
struct HostFacts {
    id: String,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RetainedManifest {
    run_id: String,
    checkpoint_manifest: CheckpointManifestV1,
}

impl Admission {
    /// Host facts are checked before spawning the workflow; they are not an answer.
    pub(super) fn new(root: &Path) -> Result<Self, ()> {
        let snapshot = snapshot(root)?;
        let input = String::from_utf8(read(&root.join("input.example.json"), MAX_BYTES)?)
            .map_err(|_| ())?;
        let value: HostInput = serde_json::from_str(&input).map_err(|_| ())?;
        if value.question != CANONICAL_QUESTION
            || value.path != CANONICAL_PATH
            || value.snapshot.id != snapshot.id()
            || value.snapshot.files.len() != FILES.len()
            || FILES.iter().any(|path| {
                value.snapshot.files.get(*path).map(String::as_str) != snapshot.digest_for(path)
            })
        {
            return Err(());
        }
        Ok(Self {
            root: root.to_owned(),
            input,
            snapshot,
        })
    }

    pub(super) fn input(&self) -> &str {
        &self.input
    }

    /// Inspect the accepted checkpoint's executed branch, never a scripted answer.
    /// Event payloads are evidence of completed reads, not execution authority.
    pub(super) fn validate(&self, root: &Path) -> Result<(), ()> {
        if snapshot(&self.root)?.id() != self.snapshot.id() {
            return Err(());
        }
        let manifest: RetainedManifest =
            serde_json::from_slice(&read(&root.join("run-manifest.json"), MAX_BYTES)?)
                .map_err(|_| ())?;
        let run_id = RunId::new(manifest.run_id.clone()).map_err(|_| ())?;
        // Opening a missing database would initialize it. Require the retained store first.
        if !root.join("checkpoint.sqlite").is_file() {
            return Err(());
        }
        let checkpoint = SqliteCheckpointStore::open(
            root.join("checkpoint.sqlite"),
            manifest.checkpoint_manifest,
        )
        .map_err(|_| ())?
        .load_latest(&run_id)
        .map_err(|_| ())?
        .ok_or(())?;
        let state: Value = serde_json::from_slice(checkpoint.state()).map_err(|_| ())?;
        let events = events(root, &manifest.run_id)?;
        // The final producer saves the full event prefix and its last node. Binding
        // retries may follow graph Done, so Done need not be the last log record.
        if checkpoint.event_sequence() != events.last().ok_or(())?.sequence()
            || checkpoint.node_id()
                != events
                    .iter()
                    .rev()
                    .find_map(|event| event.node_id())
                    .unwrap_or("terminal")
            || state.get("terminal").and_then(Value::as_str) != Some("publish")
        {
            return Err(());
        }
        let terminal = events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.kind(),
                    WorkflowRuntimeEventKindV1::WorkflowCompleted
                        | WorkflowRuntimeEventKindV1::WorkflowFailed
                        | WorkflowRuntimeEventKindV1::WorkflowCancelled
                        | WorkflowRuntimeEventKindV1::WorkflowIncomplete
                        | WorkflowRuntimeEventKindV1::WorkflowAbstained
                )
            })
            .ok_or(())?;
        let publish = events
            .iter()
            .rev()
            .find(|event| {
                event.node_id() == Some("publish")
                    && matches!(
                        event.kind(),
                        WorkflowRuntimeEventKindV1::NodeStarted
                            | WorkflowRuntimeEventKindV1::NodeCompleted
                            | WorkflowRuntimeEventKindV1::NodeFailed
                    )
            })
            .ok_or(())?;
        let selected = events
            .iter()
            .rev()
            .find(|event| {
                matches!(event.node_id(), Some("draft" | "revise"))
                    && matches!(
                        event.kind(),
                        WorkflowRuntimeEventKindV1::NodeStarted
                            | WorkflowRuntimeEventKindV1::NodeCompleted
                            | WorkflowRuntimeEventKindV1::NodeFailed
                    )
            })
            .ok_or(())?;
        if terminal.kind() != WorkflowRuntimeEventKindV1::WorkflowCompleted
            || publish.kind() != WorkflowRuntimeEventKindV1::NodeCompleted
            || selected.kind() != WorkflowRuntimeEventKindV1::NodeCompleted
            || selected.sequence() >= publish.sequence()
            || publish.sequence() >= terminal.sequence()
            || (state.get("node:revise").is_some() && selected.node_id() != Some("revise"))
        {
            return Err(());
        }
        let key = match selected.node_id() {
            Some("revise") => "node:revise",
            Some("draft") => "node:draft",
            _ => return Err(()),
        };
        let answer: InvestigationAnswer =
            serde_json::from_value(state.get(key).ok_or(())?.clone()).map_err(|_| ())?;
        validate_answer(&answer, &self.snapshot).map_err(|_| ())?;
        // This canonical task asks where default_retry is defined. This is a finite
        // expected-finding check, not an entailment evaluator for arbitrary prose.
        if !answer.claims().iter().any(|claim| {
            claim.text().contains("default_retry")
                && claim.evidence().iter().any(|evidence| {
                    evidence.path() == "src/retry.rs"
                        && evidence.snippet().contains("pub fn default_retry()")
                        && evidence.snippet().contains("retry_with_limit(3)")
                })
        }) {
            return Err(());
        }
        let reads = completed_reads(root, &events, &self.snapshot)?;
        if answer
            .claims()
            .iter()
            .flat_map(|claim| claim.evidence())
            .any(|evidence| {
                !reads.iter().any(|range| {
                    range.path() == evidence.path()
                        && range.start_line() <= evidence.start_line()
                        && range.end_line() >= evidence.end_line()
                })
            })
        {
            return Err(());
        }
        Ok(())
    }
}

fn events(root: &Path, run_id: &str) -> Result<Vec<WorkflowRuntimeEventV1>, ()> {
    let bytes = read(&root.join("events.jsonl"), 16 * MAX_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let mut seen = BTreeSet::new();
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            let event: WorkflowRuntimeEventV1 = serde_json::from_str(line).map_err(|_| ())?;
            if event.run_id() != run_id
                || event.sequence() != index as u64 + 1
                || !seen.insert(event.event_id().to_owned())
            {
                return Err(());
            }
            Ok(event)
        })
        .collect()
}

fn output(root: &Path, event: &WorkflowRuntimeEventV1) -> Result<Value, ()> {
    let Some(reference) = event.payload().get("artifact_reference") else {
        return event.payload().get("structured_output").cloned().ok_or(());
    };
    let reference: ProtectedArtifactReferenceV1 =
        serde_json::from_value(reference.clone()).map_err(|_| ())?;
    let id = ArtifactId::parse(reference.artifact_id()).ok_or(())?;
    if reference.byte_len() > MAX_BYTES
        || reference.sha256() != format!("sha256:{}", id.as_str())
        || !root.join("artifacts").is_dir()
    {
        return Err(());
    }
    let limit = NonZeroU64::new(MAX_BYTES).ok_or(())?;
    let store =
        FilesystemArtifactStore::try_new(root.join("artifacts"), limit, limit).map_err(|_| ())?;
    // The existing store validates the complete content-addressed file on read.
    let page = store
        .read_page(&id, PageRequest::new(0, limit))
        .map_err(|_| ())?;
    if page.next_offset().is_some() || page.bytes().len() as u64 != reference.byte_len() {
        return Err(());
    }
    serde_json::from_slice(page.bytes()).map_err(|_| ())
}

#[derive(Deserialize)]
struct ReadRange {
    path: String,
    start_line: usize,
    end_line: usize,
    snippet: String,
}

fn completed_reads(
    root: &Path,
    events: &[WorkflowRuntimeEventV1],
    snapshot: &Snapshot,
) -> Result<Vec<SourceRange>, ()> {
    let mut reads = Vec::new();
    for event in events
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolCompleted)
    {
        let results = output(root, event)?;
        for result in results.as_array().ok_or(())? {
            if result.get("tool_name").and_then(Value::as_str) != Some("read_source_range") {
                continue;
            }
            let response: ToolEnvelope<ReadRange> =
                serde_json::from_value(result.get("response").ok_or(())?.clone())
                    .map_err(|_| ())?;
            let ToolEnvelope::Success {
                payload: read,
                provenance,
                next_offset: None,
                artifact_id: None,
            } = response
            else {
                return Err(());
            };
            if provenance.tool_id() != "read_source_range" || provenance.tool_version() != "1" {
                return Err(());
            }
            let range = snapshot
                .read_source_range(&read.path, read.start_line, read.end_line)
                .map_err(|_| ())?;
            if read.snippet != range.snippet() {
                return Err(());
            }
            reads.push(range);
        }
    }
    Ok(reads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{code_investigation::Evidence, live_conformance::ConformanceDisposition};
    use serde_json::json;
    use std::{
        fs,
        os::unix::process::ExitStatusExt,
        process::{ExitStatus, Output},
        sync::atomic::{AtomicU64, Ordering},
        time::Instant,
    };
    use workflow_runtime::{DurableCheckpointV1, ToolProvenance, WorkflowRuntimeEventLogV1};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Retained {
        root: PathBuf,
        admission: Admission,
        store: SqliteCheckpointStore,
        run: RunId,
        state: Value,
        events: Vec<WorkflowRuntimeEventV1>,
    }

    impl Drop for Retained {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Retained {
        fn new(revised: bool) -> Self {
            let root = std::env::temp_dir().join(format!(
                "m3-07-generation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("retained root");
            let admission = Admission::new(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation"),
            )
            .expect("canonical facts");
            let snapshot = &admission.snapshot;
            let range = snapshot
                .read_source_range(
                    "src/retry.rs",
                    1,
                    snapshot
                        .source("src/retry.rs")
                        .expect("source")
                        .lines()
                        .count(),
                )
                .expect("complete source range");
            let answer = json!({"schema_version":1,"snapshot_id":snapshot.id(),"claims":[{"id":"retry","text":"default_retry uses retry_with_limit(3)","evidence":[Evidence::from_range("retry", &range)]}]});
            let run = RunId::new("retained-generation".to_owned()).expect("run identity");
            let manifest = CheckpointManifestV1::new(&run, "investigation", "1");
            let store =
                SqliteCheckpointStore::open(root.join("checkpoint.sqlite"), manifest.clone())
                    .expect("real SQLite store");
            fs::write(root.join("run-manifest.json"), serde_json::to_vec(&json!({"run_id":run.as_str(),"status":"succeeded","checkpoint_manifest":manifest})).expect("manifest JSON")).expect("manifest");
            let mut log =
                WorkflowRuntimeEventLogV1::new(run.as_str(), "investigation").expect("event log");
            let response = ToolEnvelope::success(
                json!({"path":range.path(),"start_line":range.start_line(),"end_line":range.end_line(),"snippet":range.snippet()}),
                ToolProvenance::new("read_source_range", "1"),
            );
            log.append("read", Some("inspect_evidence".to_owned()), "fixture", WorkflowRuntimeEventKindV1::ToolCompleted, json!({"structured_output":[{"tool_name":"read_source_range","response":response}]})).expect("completed read");
            log.append(
                "draft",
                Some("draft".to_owned()),
                "fixture",
                WorkflowRuntimeEventKindV1::NodeCompleted,
                json!({}),
            )
            .expect("draft completion");
            if revised {
                log.append(
                    "revise",
                    Some("revise".to_owned()),
                    "fixture",
                    WorkflowRuntimeEventKindV1::NodeCompleted,
                    json!({}),
                )
                .expect("revision completion");
            }
            log.append(
                "publish",
                Some("publish".to_owned()),
                "fixture",
                WorkflowRuntimeEventKindV1::NodeCompleted,
                json!({}),
            )
            .expect("publish completion");
            log.append(
                "done",
                None,
                "fixture",
                WorkflowRuntimeEventKindV1::WorkflowCompleted,
                json!({}),
            )
            .expect("workflow completion");
            // The real producer can record binding retries after graph Done.
            log.append(
                "retry",
                Some("planner".to_owned()),
                "fixture",
                WorkflowRuntimeEventKindV1::RetryScheduled,
                json!({}),
            )
            .expect("late retry record");
            let mut state = json!({"node:draft":answer,"terminal":"publish"});
            if revised {
                state["node:revise"] = answer;
            }
            let mut retained = Self {
                root,
                admission,
                store,
                run,
                state,
                events: log.into_events(),
            };
            retained.save();
            retained
        }

        fn checkpoint(&self) -> DurableCheckpointV1 {
            DurableCheckpointV1::new(
                self.run.clone(),
                self.events
                    .iter()
                    .rev()
                    .find_map(|event| event.node_id())
                    .expect("last node"),
                self.events.last().expect("events").sequence(),
                serde_json::to_vec(&self.state).expect("state"),
                Vec::<String>::new(),
            )
            .expect("checkpoint")
        }

        fn save(&mut self) {
            let checkpoint = self.checkpoint();
            self.store
                .save_checkpoint(checkpoint)
                .expect("save real checkpoint");
            let bytes = self
                .events
                .iter()
                .map(|event| serde_json::to_string(event).expect("event JSON"))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(self.root.join("events.jsonl"), bytes).expect("events");
        }

        fn assert_disposition(&self, expected: ConformanceDisposition) {
            let report = super::super::classify(
                Ok(Output {
                    status: ExitStatus::from_raw(0),
                    stdout: serde_json::to_vec(&json!({"status":"succeeded","run_root":self.root}))
                        .expect("receipt"),
                    stderr: Vec::new(),
                }),
                &self.root,
                Instant::now(),
                &self.admission,
            );
            assert_eq!(report.disposition(), expected, "{report:?}");
            if expected == ConformanceDisposition::Fail {
                assert_eq!(
                    report.metrics().expect("failure metrics").error_category(),
                    Some("invalid_evidence")
                );
            }
        }
    }

    #[test]
    fn same_run_stale_checkpoint_cannot_qualify_later_events() {
        let mut retained = Retained::new(true);
        retained.assert_disposition(ConformanceDisposition::Pass);
        let older = DurableCheckpointV1::new(
            retained.run.clone(),
            "revise",
            3,
            serde_json::to_vec(&retained.state).expect("older state"),
            Vec::<String>::new(),
        )
        .expect("earlier generation");
        // A later accepted revision is invalid; an earlier valid answer must not mask it.
        retained.state["node:revise"]["claims"][0]["evidence"][0]["digest"] =
            json!("sha256:invalid");
        retained.save();
        retained.assert_disposition(ConformanceDisposition::Fail);
        retained
            .store
            .save_checkpoint(older)
            .expect("restore actual earlier same-run row");
        retained.assert_disposition(ConformanceDisposition::Fail);
    }

    #[test]
    fn selected_answer_requires_its_completed_event() {
        for revised in [false, true] {
            for missing in [false, true] {
                let mut retained = Retained::new(revised);
                let selected = if revised { "revise" } else { "draft" };
                let mut log =
                    WorkflowRuntimeEventLogV1::new(retained.run.as_str(), "investigation")
                        .expect("replacement log");
                for event in &retained.events {
                    let selected_event = event.node_id() == Some(selected);
                    if selected_event && missing {
                        continue;
                    }
                    log.append(
                        event.event_id(),
                        event.node_id().map(str::to_owned),
                        event.occurred_at(),
                        if selected_event {
                            WorkflowRuntimeEventKindV1::NodeStarted
                        } else {
                            event.kind()
                        },
                        event.payload().clone(),
                    )
                    .expect("valid public event");
                }
                retained.events = log.into_events();
                retained.save();
                retained.assert_disposition(ConformanceDisposition::Fail);
            }
        }
    }

    #[test]
    fn completed_generation_preserves_post_terminal_retry_records() {
        for revised in [false, true] {
            Retained::new(revised).assert_disposition(ConformanceDisposition::Pass);
        }
    }
}
