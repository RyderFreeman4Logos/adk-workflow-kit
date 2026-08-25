use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use workflow_compiler::{compile_str, CompileError};
use workflow_runtime::{
    decode_structured_tool_output, BackendCapabilities, RequestedCapabilities, SandboxCapability,
    StructuredOutputError, UnsatisfiedCapabilities,
};

use crate::{FakeSandboxBackend, FakeSandboxRequest};

const WORKFLOW: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "bench"
version = "1"
entry = "done"
[[nodes]]
id = "done"
kind = "terminal"
"#;

/// One deterministic benchmark timing sample.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkSample {
    /// Stable benchmark category.
    pub name: String,
    /// Number of nanoseconds measured by the local monotonic clock.
    pub elapsed_ns: u128,
}

/// Typed failure diagnostics captured without fixture payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkDiagnostics {
    /// Compiler parser diagnostic code.
    pub compiler_code: String,
    /// Runtime output diagnostic code.
    pub runtime_code: String,
    /// Sandbox capability diagnostic code.
    pub sandbox_code: String,
    /// Privacy-safe rendered diagnostic summary.
    pub rendered: String,
}

/// Baseline output for BENCH-001.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkReport {
    /// Stable report schema version.
    pub schema_version: u32,
    /// Benchmark samples in compiler, runtime, sandbox order.
    pub samples: Vec<BenchmarkSample>,
    /// Typed failure evidence from each boundary.
    pub diagnostics: BenchmarkDiagnostics,
}

fn compiler_diagnostic_code(error: &CompileError) -> &'static str {
    match error {
        CompileError::Parse(_) => "workflow.parse.invalid",
        CompileError::Graph(_) => "workflow.graph.invalid",
        CompileError::State(_) => "workflow.state.invalid",
        CompileError::PredicateRegistryRequired => "workflow.predicate.registry_required",
        CompileError::Registry(_) => "workflow.predicate.registry_missing",
    }
}

fn runtime_diagnostic_code(error: &StructuredOutputError) -> &'static str {
    match error {
        StructuredOutputError::OutputTooLarge => "runtime.output.too_large",
        StructuredOutputError::InvalidUtf8 => "runtime.output.invalid_utf8",
        StructuredOutputError::InvalidJson => "runtime.output.invalid",
        StructuredOutputError::TrailingBytes => "runtime.output.trailing_bytes",
    }
}

fn sandbox_diagnostic_code(_: &UnsatisfiedCapabilities) -> &'static str {
    "sandbox.capability.unsatisfied"
}

impl BenchmarkReport {
    /// Writes the report as one deterministic pretty JSON artifact.
    pub fn write_json(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let encoded = serde_json::to_string_pretty(self).map_err(|error| error.to_string())?;
        fs::write(path, format!("{encoded}\n")).map_err(|error| error.to_string())
    }
}

/// Runs synthetic compiler, runtime, and sandbox measurements.
pub fn run_suite() -> Result<BenchmarkReport, String> {
    let compiler_start = Instant::now();
    compile_str("bench-001.workflow.toml", WORKFLOW).map_err(|error| error.to_string())?;
    let compiler_elapsed = compiler_start.elapsed().as_nanos().max(1);
    let compiler_error = compile_str("bench-001-invalid.workflow.toml", "[invalid")
        .expect_err("synthetic invalid workflow must fail");

    let runtime_start = Instant::now();
    let runtime_error = decode_structured_tool_output::<String>(b"{", 1024)
        .expect_err("synthetic invalid output must fail");
    let runtime_elapsed = runtime_start.elapsed().as_nanos().max(1);

    let sandbox_start = Instant::now();
    let request = FakeSandboxRequest::new(
        String::from("synthetic-command"),
        PathBuf::from("/tmp/bench-001"),
        BTreeMap::new(),
        RequestedCapabilities::new([]),
    )
    .map_err(|error| error.to_string())?;
    let mut backend = FakeSandboxBackend::new(BackendCapabilities::new([]));
    backend
        .execute(&request)
        .map_err(|error| error.to_string())?;
    let sandbox_elapsed = sandbox_start.elapsed().as_nanos().max(1);

    let denied_request = RequestedCapabilities::new([SandboxCapability::Network]);
    let sandbox_error = workflow_runtime::verify_sandbox_capabilities(
        &denied_request,
        &BackendCapabilities::new([]),
    )
    .expect_err("network capability must cross the fake backend boundary");

    Ok(BenchmarkReport {
        schema_version: 1,
        samples: vec![
            BenchmarkSample {
                name: String::from("compiler"),
                elapsed_ns: compiler_elapsed,
            },
            BenchmarkSample {
                name: String::from("runtime"),
                elapsed_ns: runtime_elapsed,
            },
            BenchmarkSample {
                name: String::from("sandbox"),
                elapsed_ns: sandbox_elapsed,
            },
        ],
        diagnostics: BenchmarkDiagnostics {
            compiler_code: String::from(compiler_diagnostic_code(&compiler_error)),
            runtime_code: String::from(runtime_diagnostic_code(&runtime_error)),
            sandbox_code: String::from(sandbox_diagnostic_code(&sandbox_error)),
            rendered: format!("{}; {}; {}", compiler_error, runtime_error, sandbox_error),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{
        compiler_diagnostic_code, run_suite, runtime_diagnostic_code, sandbox_diagnostic_code,
        BenchmarkReport,
    };
    use workflow_compiler::compile_str;
    use workflow_runtime::{decode_structured_tool_output, verify_sandbox_capabilities};

    #[test]
    fn suite_reports_compiler_runtime_and_sandbox_samples() {
        let report = run_suite().expect("synthetic benchmark suite should run");

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.samples.len(), 3);
        assert!(report.samples.iter().all(|sample| sample.elapsed_ns > 0));
        assert!(report
            .samples
            .iter()
            .any(|sample| sample.name == "compiler"));
        assert!(report.samples.iter().any(|sample| sample.name == "runtime"));
        assert!(report.samples.iter().any(|sample| sample.name == "sandbox"));
    }

    #[test]
    fn suite_keeps_typed_failure_diagnostics_and_boundary_checks() {
        let report = run_suite().expect("synthetic benchmark suite should run");
        let compiler_error = compile_str("bench-001-invalid.workflow.toml", "[invalid")
            .expect_err("synthetic invalid workflow must fail");
        let runtime_error = decode_structured_tool_output::<String>(b"{", 1024)
            .expect_err("synthetic invalid output must fail");
        let sandbox_error = verify_sandbox_capabilities(
            &workflow_runtime::RequestedCapabilities::new([
                workflow_runtime::SandboxCapability::Network,
            ]),
            &workflow_runtime::BackendCapabilities::new([]),
        )
        .expect_err("network capability must cross the fake backend boundary");

        assert_eq!(
            report.diagnostics.compiler_code,
            compiler_diagnostic_code(&compiler_error)
        );
        assert_eq!(
            report.diagnostics.runtime_code,
            runtime_diagnostic_code(&runtime_error)
        );
        assert_eq!(
            report.diagnostics.sandbox_code,
            sandbox_diagnostic_code(&sandbox_error)
        );
        assert!(!report.diagnostics.rendered.contains("BENCH_SECRET"));
    }

    #[test]
    fn baseline_report_writes_a_single_json_artifact() {
        let report = run_suite().expect("synthetic benchmark suite should run");
        let path = std::env::temp_dir().join("adk-workflow-kit-bench-001-test-report.json");

        report.write_json(&path).expect("report should be written");
        let encoded = std::fs::read_to_string(&path).expect("report should be readable");
        let decoded: BenchmarkReport =
            serde_json::from_str(&encoded).expect("report JSON is valid");
        assert_eq!(decoded, report);
        std::fs::remove_file(path).expect("test report should be removed");
    }
}
