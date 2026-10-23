//! #230 scripted quality, security, cost, token, and cache harness.
//!
//! Deterministic fixtures only. A live model is an explicit opt-in wire record,
//! never implied by this module.

use std::{
    collections::{BTreeMap, BTreeSet},
    process,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use workflow_adk::{EscalationPolicy, ReasoningEffort};
use workflow_runtime::CacheDisposition;

const SCHEMA_VERSION: u32 = 1;

/// Frozen synthetic fixture identity, not the production execution registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredWorkflow {
    id: &'static str,
    source: &'static str,
}

impl RegisteredWorkflow {
    pub const fn id(self) -> &'static str {
        self.id
    }
}

/// Frozen golden-report fixture cases. See `execution230::scripted_workflows` for packages.
pub fn registered_workflows() -> &'static [RegisteredWorkflow] {
    &[
        RegisteredWorkflow {
            id: "code-investigation",
            source: "examples/01-code-investigation/workflow.toml",
        },
        RegisteredWorkflow {
            id: "minimal-template",
            source: "templates/minimal/workflow.toml",
        },
        RegisteredWorkflow {
            id: "runtime-smoke",
            source: "examples/00-runtime-smoke/workflow.toml",
        },
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteMode {
    Scripted,
    Regression,
    Adaptive,
    Soak,
    SealedFinal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheClass {
    Cold,
    Warm,
    Pressure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenClasses {
    pub input: u32,
    pub cached_input: u32,
    pub reasoning: u32,
    pub visible_output: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub id: String,
    pub workflow_id: String,
    pub cache_class: CacheClass,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkSuite {
    mode: SuiteMode,
    cases: Vec<BenchmarkCase>,
}

impl BenchmarkSuite {
    pub fn scripted(cases: Vec<BenchmarkCase>) -> Self {
        Self {
            mode: SuiteMode::Scripted,
            cases,
        }
    }

    pub fn mode(&self) -> SuiteMode {
        self.mode
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunManifest {
    schema_version: u32,
    pub suite: SuiteMode,
    source_revision: String,
    model_revision: String,
    dataset_revision: String,
    config_digest: String,
    case_ids: Vec<String>,
    cases: Vec<BenchmarkCase>,
}

impl RunManifest {
    pub fn bind(
        suite: &BenchmarkSuite,
        source_revision: &str,
        model_revision: &str,
        dataset_revision: &str,
        config_digest: &str,
    ) -> Self {
        let mut cases = suite.cases.clone();
        cases.sort_by(|left, right| left.id.cmp(&right.id));
        let case_ids = cases.iter().map(|case| case.id.clone()).collect();
        Self {
            schema_version: SCHEMA_VERSION,
            suite: suite.mode,
            source_revision: source_revision.to_owned(),
            model_revision: model_revision.to_owned(),
            dataset_revision: dataset_revision.to_owned(),
            config_digest: config_digest.to_owned(),
            case_ids,
            cases,
        }
    }

    pub fn digest(&self) -> String {
        digest(
            serde_json::to_string(self)
                .expect("manifest json")
                .as_bytes(),
        )
    }

    pub fn case_ids(&self) -> &[String] {
        &self.case_ids
    }
}

/// Evidence origin is mandatory; a supplied observation is not verified execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SyntheticFixture,
    ProvidedObservation,
    WireFixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaseEnvelope {
    pub schema_version: u32,
    pub evidence_kind: EvidenceKind,
    pub case_id: String,
    pub workflow_id: String,
    pub source_revision: String,
    pub model_revision: String,
    pub dataset_revision: String,
    pub config_digest: String,
    pub route: String,
    pub reasoning: ReasoningEffort,
    pub tokens: TokenClasses,
    pub prefill_ns: u64,
    pub decode_ns: u64,
    pub provider_cost_micros: u64,
    pub result_cache: CacheDisposition,
    pub prefix_hash: String,
    pub prefix_hit: bool,
    pub retries: u32,
    pub escalation: EscalationPolicy,
    pub hitl: bool,
    pub cache_class: CacheClass,
    pub quality_millis: u32,
    pub security_failures: u32,
    pub live_opt_in: bool,
    pub live_executed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaseObservation {
    pub case_id: String,
    pub workflow_id: String,
    pub quality_millis: u32,
    pub security_failures: u32,
    pub tokens: TokenClasses,
    pub prefill_ns: u64,
    pub decode_ns: u64,
    pub provider_cost_micros: u64,
    pub result_cache: CacheDisposition,
    pub prefix_hash: String,
    pub prefix_hit: bool,
    pub retries: u32,
    pub escalation: EscalationPolicy,
    pub hitl: bool,
    pub cache_class: CacheClass,
    pub route: String,
    pub reasoning: ReasoningEffort,
    pub model_revision: String,
    pub source_revision: String,
    pub dataset_revision: String,
    pub config_digest: String,
}

impl From<CaseObservation> for CaseEnvelope {
    fn from(observation: CaseObservation) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            evidence_kind: EvidenceKind::ProvidedObservation,
            case_id: observation.case_id,
            workflow_id: observation.workflow_id,
            source_revision: observation.source_revision,
            model_revision: observation.model_revision,
            dataset_revision: observation.dataset_revision,
            config_digest: observation.config_digest,
            route: observation.route,
            reasoning: observation.reasoning,
            tokens: observation.tokens,
            prefill_ns: observation.prefill_ns,
            decode_ns: observation.decode_ns,
            provider_cost_micros: observation.provider_cost_micros,
            result_cache: observation.result_cache,
            prefix_hash: observation.prefix_hash,
            prefix_hit: observation.prefix_hit,
            retries: observation.retries,
            escalation: observation.escalation,
            hitl: observation.hitl,
            cache_class: observation.cache_class,
            quality_millis: observation.quality_millis,
            security_failures: observation.security_failures,
            live_opt_in: false,
            live_executed: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateReport {
    pub schema_version: u32,
    pub mode: SuiteMode,
    pub cases: Vec<CaseEnvelope>,
    pub hard_invariant_failed: bool,
    pub optional_target_failed: bool,
    pub catastrophic_security: u32,
    /// Upper confidence bound for an unobserved catastrophe. Never zero.
    pub catastrophe_bound: OrderedFloat,
}

impl AggregateReport {
    pub fn canonical_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report json") + "\n"
    }
}

/// Fixed-point fraction so reports stay deterministic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrderedFloat(u32);

impl PartialOrd for OrderedFloat {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedFloat {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq<f64> for OrderedFloat {
    fn eq(&self, other: &f64) -> bool {
        (self.as_f64() - other).abs() < 1e-9
    }
}

impl PartialOrd<f64> for OrderedFloat {
    fn partial_cmp(&self, other: &f64) -> Option<std::cmp::Ordering> {
        self.as_f64().partial_cmp(other)
    }
}

impl OrderedFloat {
    pub(crate) fn millionths(self) -> u32 {
        self.0
    }

    fn as_f64(self) -> f64 {
        f64::from(self.0) / 1_000_000.0
    }
}

pub fn scripted_fixture(id: &str, cache_class: CacheClass) -> BenchmarkCase {
    BenchmarkCase {
        id: id.to_owned(),
        workflow_id: "runtime-smoke".to_owned(),
        cache_class,
    }
}

pub fn case_envelope(case: &BenchmarkCase) -> CaseEnvelope {
    let warm = case.cache_class == CacheClass::Warm;
    CaseEnvelope {
        schema_version: SCHEMA_VERSION,
        evidence_kind: EvidenceKind::SyntheticFixture,
        case_id: case.id.clone(),
        workflow_id: case.workflow_id.clone(),
        source_revision: "scripted".to_owned(),
        model_revision: "scripted-model".to_owned(),
        dataset_revision: "scripted-dataset".to_owned(),
        config_digest: digest(case.id.as_bytes()),
        route: "scripted".to_owned(),
        reasoning: ReasoningEffort::Low,
        tokens: TokenClasses {
            input: 8,
            cached_input: u32::from(warm),
            reasoning: 1,
            visible_output: 4,
        },
        prefill_ns: 1,
        decode_ns: 1,
        provider_cost_micros: 0,
        result_cache: if warm {
            CacheDisposition::Reused
        } else {
            CacheDisposition::Recorded
        },
        prefix_hash: digest(case.workflow_id.as_bytes()),
        prefix_hit: warm,
        retries: 0,
        escalation: EscalationPolicy::None,
        hitl: false,
        cache_class: case.cache_class,
        quality_millis: 1000,
        security_failures: 0,
        live_opt_in: false,
        live_executed: false,
    }
}

/// Returns synthetic golden fixtures; the public `scripted` CLI executes real workflows.
pub fn run_scripted_smoke() -> Result<AggregateReport, String> {
    run_mode(SuiteMode::Scripted, 1)
}

pub fn run_mode(mode: SuiteMode, repeats: usize) -> Result<AggregateReport, String> {
    if repeats == 0 {
        return Err("repeat count must be positive".to_owned());
    }
    let mut cases = Vec::new();
    for repeat in 0..repeats {
        for workflow in registered_workflows() {
            let case_id = if repeats == 1 {
                workflow.id.to_owned()
            } else {
                format!("{}-{repeat}", workflow.id)
            };
            let case = BenchmarkCase {
                id: case_id,
                workflow_id: workflow.id.to_owned(),
                cache_class: if repeat == 0 {
                    CacheClass::Cold
                } else {
                    CacheClass::Warm
                },
            };
            let mut envelope = case_envelope(&case);
            envelope.source_revision = digest(workflow.source.as_bytes());
            cases.push(envelope);
        }
    }
    Ok(AggregateReport {
        schema_version: SCHEMA_VERSION,
        mode,
        hard_invariant_failed: false,
        optional_target_failed: false,
        catastrophic_security: 0,
        catastrophe_bound: confidence_bound(0, cases.len(), 95),
        cases,
    })
}

pub fn resume_suite(
    manifest: &RunManifest,
    completed: &[CaseEnvelope],
) -> Result<Vec<CaseEnvelope>, String> {
    let mut expected = BTreeMap::new();
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.case_ids
            != manifest
                .cases
                .iter()
                .map(|case| case.id.clone())
                .collect::<Vec<_>>()
    {
        return Err("invalid manifest case binding".to_owned());
    }
    for case in &manifest.cases {
        if case.id.is_empty() || expected.insert(case.id.as_str(), case).is_some() {
            return Err("empty or duplicate manifest case id".to_owned());
        }
    }
    let mut done = BTreeSet::new();
    for case in completed {
        let expected_case = expected
            .get(case.case_id.as_str())
            .ok_or_else(|| format!("unknown completed case {}", case.case_id))?;
        if !done.insert(case.case_id.as_str())
            || case.schema_version != SCHEMA_VERSION
            || case.workflow_id != expected_case.workflow_id
            || case.cache_class != expected_case.cache_class
            || case.source_revision != manifest.source_revision
            || case.model_revision != manifest.model_revision
            || case.dataset_revision != manifest.dataset_revision
            || case.config_digest != manifest.config_digest
        {
            return Err(format!("conflicting completed case {}", case.case_id));
        }
    }
    Ok(manifest
        .cases
        .iter()
        .filter(|case| !done.contains(case.id.as_str()))
        .map(|case| {
            let mut envelope = case_envelope(case);
            envelope
                .source_revision
                .clone_from(&manifest.source_revision);
            envelope.model_revision.clone_from(&manifest.model_revision);
            envelope
                .dataset_revision
                .clone_from(&manifest.dataset_revision);
            envelope.config_digest.clone_from(&manifest.config_digest);
            envelope
        })
        .collect())
}

/// One-sided Hoeffding bound for independent Bernoulli trials, rounded upward
/// to millionths. `events` counts affected trials, not individual violations.
/// Empty samples, invalid confidence percentages, and all-failure samples yield 1.
pub fn confidence_bound(events: u32, trials: usize, confidence: u32) -> OrderedFloat {
    if trials == 0 || !(1..100).contains(&confidence) || u64::from(events) >= trials as u64 {
        return OrderedFloat(1_000_000);
    }
    let trials = trials as f64;
    let alpha = 1.0 - f64::from(confidence) / 100.0;
    let upper = (f64::from(events) / trials + (-alpha.ln() / (2.0 * trials)).sqrt()).min(1.0);
    OrderedFloat((upper * 1_000_000.0).ceil() as u32)
}

pub fn aggregate_report(
    observations: &[CaseObservation],
    quality_floor: u32,
    token_ceiling: u32,
) -> Result<AggregateReport, String> {
    let observations = observation_index(observations)?;
    if quality_floor > 1000 {
        return Err("quality floor exceeds 1000".to_owned());
    }
    let catastrophic_security = observations.values().try_fold(0_u32, |total, item| {
        total
            .checked_add(item.security_failures)
            .ok_or_else(|| "security failure count overflow".to_owned())
    })?;
    let affected_cases = observations
        .values()
        .filter(|item| item.security_failures > 0)
        .count();
    let hard_invariant_failed = catastrophic_security > 0;
    let optional_target_failed = observations.values().any(|item| {
        item.quality_millis < quality_floor || item.tokens.visible_output > token_ceiling
    });
    let cases = observations
        .into_values()
        .cloned()
        .map(CaseEnvelope::from)
        .collect::<Vec<_>>();
    Ok(AggregateReport {
        schema_version: SCHEMA_VERSION,
        mode: SuiteMode::Regression,
        hard_invariant_failed,
        optional_target_failed,
        catastrophic_security,
        catastrophe_bound: confidence_bound(affected_cases as u32, cases.len(), 95),
        cases,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedRow {
    pub case_id: String,
    pub quality_delta_millis: i64,
    pub security_delta: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedReport {
    pub rows: Vec<PairedRow>,
}

pub fn compare_revisions(
    left: &[CaseObservation],
    right: &[CaseObservation],
) -> Result<PairedReport, String> {
    let left_by_id = observation_index(left)?;
    let right_by_id = observation_index(right)?;
    if !left_by_id.keys().eq(right_by_id.keys()) {
        return Err("paired case sets differ".to_owned());
    }
    let mut rows = Vec::new();
    for item in left_by_id.into_values() {
        let other = right_by_id
            .get(item.case_id.as_str())
            .copied()
            .ok_or_else(|| format!("missing paired case {}", item.case_id))?;
        if item.workflow_id != other.workflow_id
            || item.dataset_revision != other.dataset_revision
            || item.cache_class != other.cache_class
        {
            return Err(format!("incompatible paired case {}", item.case_id));
        }
        rows.push(PairedRow {
            case_id: item.case_id.clone(),
            quality_delta_millis: i64::from(other.quality_millis) - i64::from(item.quality_millis),
            security_delta: i64::from(other.security_failures) - i64::from(item.security_failures),
        });
    }
    rows.sort_by(|left_row, right_row| left_row.case_id.cmp(&right_row.case_id));
    Ok(PairedReport { rows })
}

fn observation_index(
    observations: &[CaseObservation],
) -> Result<BTreeMap<&str, &CaseObservation>, String> {
    if observations.is_empty() {
        return Err("no observations".to_owned());
    }
    let mut by_id = BTreeMap::new();
    for item in observations {
        if item.quality_millis > 1000 || item.tokens.cached_input > item.tokens.input {
            return Err(format!("invalid observation range {}", item.case_id));
        }
        if [
            &item.case_id,
            &item.workflow_id,
            &item.source_revision,
            &item.model_revision,
            &item.dataset_revision,
            &item.config_digest,
        ]
        .iter()
        .any(|value| value.is_empty())
            || by_id.insert(item.case_id.as_str(), item).is_some()
        {
            return Err(format!("empty binding or duplicate case {}", item.case_id));
        }
    }
    Ok(by_id)
}

pub fn split_manifests(
    suite: &BenchmarkSuite,
    threshold_ids: &[&str],
) -> (RunManifest, RunManifest) {
    let threshold_cases: Vec<BenchmarkCase> = suite
        .cases
        .iter()
        .filter(|case| threshold_ids.contains(&case.id.as_str()))
        .cloned()
        .collect();
    let holdout_cases: Vec<BenchmarkCase> = suite
        .cases
        .iter()
        .filter(|case| !threshold_ids.contains(&case.id.as_str()))
        .cloned()
        .collect();
    let mut threshold = BenchmarkSuite::scripted(threshold_cases);
    threshold.mode = SuiteMode::Regression;
    let mut holdout = BenchmarkSuite::scripted(holdout_cases);
    holdout.mode = SuiteMode::SealedFinal;
    (
        RunManifest::bind(&threshold, "src", "model", "ds", "threshold"),
        RunManifest::bind(&holdout, "src", "model", "ds", "holdout"),
    )
}

pub fn pareto_frontier(points: &[CaseObservation]) -> Vec<CaseObservation> {
    let mut kept = Vec::new();
    for point in points {
        let dominated = points.iter().any(|other| {
            other.case_id != point.case_id
                && dominates(
                    (other.quality_millis, u64::from(other.tokens.visible_output)),
                    (point.quality_millis, u64::from(point.tokens.visible_output)),
                )
        });
        if !dominated {
            kept.push(point.clone());
        }
    }
    kept.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    kept
}

// Metric owners choose and name the token dimension; dominance arithmetic is shared.
pub(crate) fn dominates(other: (u32, u64), point: (u32, u64)) -> bool {
    other.0 >= point.0 && other.1 <= point.1 && (other.0 > point.0 || other.1 < point.1)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn execution_command(output: &std::path::Path, resume: bool) -> Result<(String, bool), String> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let report = if resume {
        crate::execution230::resume_registered_smoke(&repo, output)
    } else {
        crate::execution230::run_registered_smoke(&repo, output)
    }?;
    serde_json::to_string_pretty(&report)
        .map(|json| (json + "\n", report.hard_invariant_failed))
        .map_err(|error| error.to_string())
}

pub fn bench230_main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        args @ (["init", _, _]
        | ["init-config", _, _, _]
        | ["regression" | "sealed-final", _]
        | ["soak", _, _]
        | ["adaptive", _, _, _]) => crate::execution230::policy::command(args),
        args @ (["compare-plan", _, _, _]
        | ["compare-plan", _, _, _, "config-only"]
        | ["compare", _]) => crate::execution230::policy::comparison_command(args),
        [mode @ ("cache-experiment" | "cache-resume"), output] => {
            crate::execution230::cache::command(
                std::path::Path::new(output),
                *mode == "cache-resume",
            )
        }
        args @ (["measure", _, _]
        | ["measure-live", _, _]
        | ["measure-report", _]
        | ["measure-compare", _, _]
        | ["measure-aggregate", _, _, ..]) => crate::execution230::measurement::command(args),
        ["fixture"] => run_scripted_smoke().map(|report| (report.canonical_json(), false)),
        ["scripted"] => {
            crate::execution230::output_path().and_then(|output| execution_command(&output, false))
        }
        ["scripted", "--output", output] => execution_command(std::path::Path::new(output), false),
        ["resume", output] => execution_command(std::path::Path::new(output), true),
        ["abandon", output, case_id, run_id] => {
            let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            crate::execution230::abandon_registered_case(
                &repo,
                std::path::Path::new(output),
                case_id,
                run_id,
            )
            .map(|()| {
                (
                    "{\"recovery\":\"abandoned_without_replay\"}\n".to_owned(),
                    false,
                )
            })
        }
        _ => {
            eprintln!(
                "usage: bench-230 scripted [--output DIR]|resume DIR|abandon DIR CASE_ID RUN_ID|fixture|init SPLIT.json CAMPAIGN|init-config SPLIT.json CONFIG.json CAMPAIGN|regression CAMPAIGN|adaptive CAMPAIGN elapsed_ns COUNT|soak CAMPAIGN REPEATS|sealed-final CAMPAIGN|compare-plan BASELINE CANDIDATE MAX_REGRESSION_BPS [config-only]|compare CANDIDATE|cache-experiment DIR|cache-resume DIR|measure BINDING.json DIR|measure-live BINDING.json DIR|measure-report DIR|measure-compare LEFT_DIR RIGHT_DIR|measure-aggregate SAMPLING.json DIR..."
            );
            process::exit(2);
        }
    };
    match result {
        Ok((json, failed)) => {
            print!("{json}");
            if failed {
                process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
