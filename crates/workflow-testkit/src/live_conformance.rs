//! Opt-in live OpenAI-compatible conformance dispositions.
//!
//! Ordinary callers stay on [`LiveConformance::default`], which reports `SKIP`
//! without touching a profile, network, or credential handle.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Live conformance outcome. `SKIP` is only valid when live was not requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDisposition {
    /// Live execution was not requested.
    Skip,
    /// Canonical workflow completed and published.
    Pass,
    /// Canonical workflow completed with a valid abstention.
    Abstain,
    /// Contract, profile, or provider failure.
    Fail,
}

/// Safe, credential-free metrics persisted after an opted-in attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafeMetrics {
    request_count: u64,
    tool_count: u64,
    retry_count: u64,
    elapsed_ms: u64,
    review_revisions: u64,
    terminal: String,
    artifact_hashes: Vec<String>,
    profile_identity: String,
    error_category: Option<String>,
}

impl SafeMetrics {
    /// Model request count from the sanitized event log.
    pub const fn request_count(&self) -> u64 {
        self.request_count
    }
    /// Tool request count from the sanitized event log.
    pub const fn tool_count(&self) -> u64 {
        self.tool_count
    }
    /// Retry count from the sanitized event log.
    pub const fn retry_count(&self) -> u64 {
        self.retry_count
    }
    /// Wall time of the opted-in attempt in milliseconds.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
    /// Review/revise round count.
    pub const fn review_revisions(&self) -> u64 {
        self.review_revisions
    }
    /// Terminal node or fail-closed status.
    pub fn terminal(&self) -> &str {
        &self.terminal
    }
    /// Artifact hashes only; never raw payloads.
    pub fn artifact_hashes(&self) -> &[String] {
        &self.artifact_hashes
    }
    /// Parsed model/profile identity, never a credential.
    pub fn profile_identity(&self) -> &str {
        &self.profile_identity
    }
    /// Redacted provider error category, if the attempt failed.
    pub fn error_category(&self) -> Option<&str> {
        self.error_category.as_deref()
    }
}

/// Result of a live conformance attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    disposition: ConformanceDisposition,
    metrics: Option<SafeMetrics>,
}

impl ConformanceReport {
    /// Returns the typed disposition.
    pub const fn disposition(&self) -> ConformanceDisposition {
        self.disposition
    }

    /// Safe metrics exist only after an opted-in attempt.
    pub const fn metrics(&self) -> Option<&SafeMetrics> {
        self.metrics.as_ref()
    }
}

fn report(disposition: ConformanceDisposition, metrics: Option<SafeMetrics>) -> ConformanceReport {
    ConformanceReport {
        disposition,
        metrics,
    }
}

/// Explicit opt-in switch. Default is skip; it never reads environment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LiveConformance {
    enabled: bool,
}

impl LiveConformance {
    /// Enables a live attempt without consulting environment or config.
    pub const fn opt_in() -> Self {
        Self { enabled: true }
    }

    /// Runs the opt-in gate. Default reports `SKIP` and performs no I/O.
    pub fn run(self) -> ConformanceReport {
        if self.enabled {
            report(ConformanceDisposition::Fail, None)
        } else {
            report(ConformanceDisposition::Skip, None)
        }
    }

    /// Runs the canonical example through `workflowctl`. Extra env is child-only.
    pub fn run_canonical(
        self,
        workflowctl: &Path,
        example_root: &Path,
        profile: &Path,
        workdir: &Path,
    ) -> ConformanceReport {
        self.run_canonical_with_env(workflowctl, example_root, profile, workdir, &[])
    }

    /// Runs the canonical example, setting only the supplied child env pairs.
    pub fn run_canonical_with_env(
        self,
        workflowctl: &Path,
        example_root: &Path,
        profile: &Path,
        workdir: &Path,
        env: &[(&str, &str)],
    ) -> ConformanceReport {
        if !self.enabled {
            return report(ConformanceDisposition::Skip, None);
        }
        let Some(workflow) = example_root
            .join("workflow.toml")
            .to_str()
            .map(str::to_owned)
        else {
            return fail_closed(workdir, Instant::now(), None, None);
        };
        let Some(profile) = profile.to_str().map(str::to_owned) else {
            return fail_closed(workdir, Instant::now(), None, None);
        };
        let Some(workdir_s) = workdir.to_str().map(str::to_owned) else {
            return fail_closed(workdir, Instant::now(), None, None);
        };
        let input = match fs::read_to_string(example_root.join("input.example.json")) {
            Ok(input) => input,
            Err(_) => return fail_closed(workdir, Instant::now(), None, None),
        };
        let mut command = Command::new(workflowctl);
        command.args([
            "--json",
            "run",
            &workflow,
            "--profile",
            &profile,
            "--input",
            input.trim(),
            "--workdir",
            &workdir_s,
        ]);
        for (key, value) in env {
            command.env(key, value);
        }
        let started = Instant::now();
        classify(command.output(), workdir, started)
    }
}

fn fail_closed(
    workdir: &Path,
    started: Instant,
    run_root: Option<&Path>,
    error_category: Option<&str>,
) -> ConformanceReport {
    let metrics = collect_metrics(
        ConformanceDisposition::Fail,
        workdir,
        run_root,
        started,
        Some(error_category.unwrap_or("fail_closed")),
    );
    persist_metrics(workdir, &metrics);
    report(ConformanceDisposition::Fail, Some(metrics))
}

fn classify(
    output: std::io::Result<std::process::Output>,
    workdir: &Path,
    started: Instant,
) -> ConformanceReport {
    let output = match output {
        Ok(output) => output,
        Err(_) => return fail_closed(workdir, started, None, None),
    };
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    let run_root = receipt
        .get("run_root")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    if !output.status.success() || receipt["status"] != "succeeded" {
        return fail_closed(
            workdir,
            started,
            run_root.as_deref(),
            category_from_stderr(&output.stderr).as_deref(),
        );
    }
    let Some(run_root) = run_root else {
        return fail_closed(workdir, started, None, None);
    };
    let nodes = event_node_ids(&run_root);
    let published = nodes.iter().any(|node| node == "publish");
    let abstained = nodes.iter().any(|node| node == "abstain");
    let disposition = if published && !abstained {
        ConformanceDisposition::Pass
    } else if abstained && !published {
        ConformanceDisposition::Abstain
    } else {
        ConformanceDisposition::Fail
    };
    if disposition == ConformanceDisposition::Fail {
        return fail_closed(
            workdir,
            started,
            Some(&run_root),
            category_from_stderr(&output.stderr).as_deref(),
        );
    }
    let metrics = collect_metrics(disposition, workdir, Some(&run_root), started, None);
    persist_metrics(workdir, &metrics);
    report(disposition, Some(metrics))
}

fn category_from_stderr(stderr: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(stderr)
        .ok()?
        .get("details")?
        .get("category")?
        .as_str()
        .map(str::to_owned)
}

fn collect_metrics(
    disposition: ConformanceDisposition,
    _workdir: &Path,
    run_root: Option<&Path>,
    started: Instant,
    error_category: Option<&str>,
) -> SafeMetrics {
    let events = run_root
        .and_then(|root| fs::read_to_string(root.join("events.jsonl")).ok())
        .unwrap_or_default();
    let parsed = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    let count = |kind: &str| {
        parsed
            .iter()
            .filter(|value| value.get("kind").and_then(Value::as_str) == Some(kind))
            .count() as u64
    };
    let review_revisions = parsed
        .iter()
        .filter(|value| {
            value.get("kind").and_then(Value::as_str) == Some("node_completed")
                && value.get("node_id").and_then(Value::as_str) == Some("revise")
        })
        .count() as u64;
    let terminal = parsed
        .iter()
        .rev()
        .find_map(|value| {
            value
                .get("node_id")
                .and_then(Value::as_str)
                .filter(|node| *node == "publish" || *node == "abstain")
                .map(str::to_owned)
        })
        .unwrap_or_else(|| match disposition {
            ConformanceDisposition::Fail => "fail".to_owned(),
            ConformanceDisposition::Skip => "skip".to_owned(),
            ConformanceDisposition::Pass => "publish".to_owned(),
            ConformanceDisposition::Abstain => "abstain".to_owned(),
        });
    let manifest = run_root
        .and_then(|root| fs::read(root.join("run-manifest.json")).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let profile_identity = manifest
        .as_ref()
        .and_then(|value| value.get("profile_identity")?.as_str())
        .unwrap_or("unavailable")
        .to_owned();
    let artifact_hashes = manifest
        .as_ref()
        .and_then(|value| value.get("artifact_id")?.as_str())
        .map(|value| vec![value.to_owned()])
        .unwrap_or_default();
    SafeMetrics {
        request_count: count("model_request_completed"),
        tool_count: count("tool_requested"),
        retry_count: count("retry_scheduled"),
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        review_revisions,
        terminal,
        artifact_hashes,
        profile_identity,
        error_category: error_category.map(str::to_owned),
    }
}

fn persist_metrics(workdir: &Path, metrics: &SafeMetrics) {
    if let Ok(bytes) = serde_json::to_vec(metrics) {
        let _ = fs::write(workdir.join("conformance.json"), bytes);
    }
}

fn event_node_ids(run_root: &Path) -> Vec<String> {
    fs::read_to_string(run_root.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line).ok()?;
            value.get("node_id")?.as_str().map(str::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn review_revisions_for(events: &str) -> u64 {
        let root = std::env::temp_dir().join(format!(
            "m3-07-rev-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("temp run root");
        fs::write(root.join("events.jsonl"), events).expect("events");
        let metrics = collect_metrics(
            ConformanceDisposition::Pass,
            &root,
            Some(&root),
            Instant::now(),
            None,
        );
        let _ = fs::remove_dir_all(&root);
        metrics.review_revisions()
    }

    #[test]
    fn review_revisions_counts_one_event_per_revise_visit() {
        let none = concat!(
            r#"{"kind":"node_started","node_id":"review"}"#,
            "\n",
            r#"{"kind":"node_completed","node_id":"review"}"#,
            "\n",
        );
        let one = concat!(
            r#"{"kind":"node_started","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"model_request_completed","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"node_completed","node_id":"revise"}"#,
            "\n",
        );
        let repeated = concat!(
            r#"{"kind":"node_started","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"node_completed","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"node_started","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"model_request_completed","node_id":"revise"}"#,
            "\n",
            r#"{"kind":"node_completed","node_id":"revise"}"#,
            "\n",
        );
        assert_eq!(review_revisions_for(none), 0);
        assert_eq!(review_revisions_for(one), 1);
        assert_eq!(review_revisions_for(repeated), 2);
    }
}
