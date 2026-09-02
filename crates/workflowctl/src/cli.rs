use std::{
    ffi::OsString,
    fmt,
    io::Write,
    num::NonZeroU64,
    path::Path,
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
    time::Instant,
};

use clap::{Arg, ArgAction, Command};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_adk::execution::{
    ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1, ExecutionReceipt,
};
use workflow_compiler::{
    AuditDisposition, Diagnostic, SkillManifest, SkillResourceId, SkillRuntimeLock,
    SkillRuntimeManifest, WorkflowLock, audit_dependencies, compile_file, render_mermaid,
};
use workflow_review::{SecretFixtureSurface, validate_secret_free_fixture};
use workflow_runtime::{
    DevelopmentHotReload, FilesystemArtifactStore, HotReloadError, PureTransformBinding,
    PureTransformPlanV1, PureTransformRequest, RequestedCapabilities, RunContext, RunController,
    RunId, RunLimits, RunOutcome, SandboxCapability, WorkdirManager,
};
use workflow_spec::{SourcePath, read_bounded_regular_file};
use workflow_testkit::{EvalEnvelope, EvalFixture, EvalInput, ReplayBundle, compile_eval};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS] <COMMAND>\n\nCommands:\n  validate <PATH>\n  graph <PATH> --format mermaid\n  lock <PATH>\n  skill lint <PATH>\n  skill test <PATH>\n  test <PATH>\n  eval <PATH>\n  replay <PATH>\n  audit\n  run <PATH> [--profile <PATH> | --module <PATH>] --input <JSON> --workdir <DIR>\n  resume --run-id <ID> --workdir <DIR>\n  inspect --run-id <ID> --workdir <DIR>\n  explain-run <PATH> --module <PATH> --input <JSON>\n  reload <PATH> --current-workflow <PATH> --current-module <PATH> --module <PATH> --input <JSON>\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n";
const JSON_ERROR: &str = "{\"diagnostic_version\":1,\"code\":\"workflow.cli.invalid_arguments\",\"message\":\"invalid command-line arguments\",\"location\":null,\"details\":{}}";

static INTERRUPT_CANCELLATION: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());
static INTERRUPT_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn signal(signal: i32, handler: extern "C" fn(i32)) -> usize;
}

extern "C" fn cancel_on_sigint(_: i32) {
    let cancellation = INTERRUPT_CANCELLATION.load(Ordering::Relaxed);
    if !cancellation.is_null() {
        // SAFETY: `interrupt_cancellation` retains one Arc until process exit.
        unsafe { (*cancellation).store(true, Ordering::Release) };
    }
}

fn interrupt_cancellation() -> Arc<AtomicBool> {
    let cancellation = Arc::new(AtomicBool::new(false));
    // The CLI executes one command per process; keep the signal target alive.
    let retained = Arc::into_raw(Arc::clone(&cancellation)).cast_mut();
    INTERRUPT_CANCELLATION.store(retained, Ordering::Release);
    if !INTERRUPT_HANDLER_INSTALLED.swap(true, Ordering::AcqRel) {
        // SAFETY: installs a C-ABI SIGINT handler that only performs atomic operations.
        unsafe { signal(2, cancel_on_sigint) };
    }
    cancellation
}

fn command() -> Command {
    Command::new("workflowctl")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit diagnostics as JSON"),
        )
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::SetTrue)
                .help("Print help"),
        )
        .subcommand(
            Command::new("validate").arg(
                Arg::new("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Workflow source file"),
            ),
        )
        .subcommand(
            Command::new("graph")
                .arg(
                    Arg::new("path")
                        .value_name("PATH")
                        .required(true)
                        .help("Workflow source file"),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .required(true)
                        .value_name("FORMAT")
                        .value_parser(["mermaid"])
                        .help("Graph output format"),
                ),
        )
        .subcommand(
            Command::new("lock").arg(
                Arg::new("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Workflow source file"),
            ),
        )
        .subcommand(
            Command::new("skill")
                .subcommand(
                    Command::new("lint").arg(
                        Arg::new("path")
                            .value_name("PATH")
                            .required(true)
                            .help("Skill directory"),
                    ),
                )
                .subcommand(
                    Command::new("test").arg(
                        Arg::new("path")
                            .value_name("PATH")
                            .required(true)
                            .help("Skill directory"),
                    ),
                ),
        )
        .subcommand(
            Command::new("run")
                .arg(
                    Arg::new("path")
                        .value_name("PATH")
                        .required(true)
                        .help("Workflow source file"),
                )
                .arg(
                    Arg::new("module")
                        .long("module")
                        .value_name("PATH")
                        .help("Transform module file"),
                )
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_name("PATH")
                        .conflicts_with("module")
                        .help("ADK execution profile file"),
                )
                .arg(
                    Arg::new("input")
                        .long("input")
                        .required(true)
                        .value_name("JSON")
                        .help("Transform input JSON"),
                )
                .arg(
                    Arg::new("workdir")
                        .long("workdir")
                        .required(true)
                        .value_name("DIR")
                        .help("Run workdir base directory"),
                )
                .arg(
                    Arg::new("fail-checkpoint-saves")
                        .long("fail-checkpoint-saves")
                        .hide(true)
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(run_state_command("resume"))
        .subcommand(run_state_command("inspect"))
        .subcommand(
            Command::new("explain-run")
                .arg(
                    Arg::new("path")
                        .value_name("PATH")
                        .required(true)
                        .help("Workflow source file"),
                )
                .arg(
                    Arg::new("module")
                        .long("module")
                        .required(true)
                        .value_name("PATH")
                        .help("Transform module file"),
                )
                .arg(
                    Arg::new("input")
                        .long("input")
                        .required(true)
                        .value_name("JSON")
                        .help("Transform input JSON"),
                ),
        )
        .subcommand(
            Command::new("reload")
                .arg(Arg::new("path").value_name("PATH").required(true))
                .arg(
                    Arg::new("current-workflow")
                        .long("current-workflow")
                        .required(true),
                )
                .arg(
                    Arg::new("current-module")
                        .long("current-module")
                        .required(true),
                )
                .arg(Arg::new("module").long("module").required(true))
                .arg(Arg::new("input").long("input").required(true)),
        )
        .subcommand(
            Command::new("test").arg(
                Arg::new("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Test fixture file"),
            ),
        )
        .subcommand(
            Command::new("eval").arg(
                Arg::new("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Eval fixture file"),
            ),
        )
        .subcommand(
            Command::new("replay").arg(
                Arg::new("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Replay bundle file"),
            ),
        )
        .subcommand(Command::new("audit"))
}

fn run_state_command(name: &'static str) -> Command {
    Command::new(name)
        .arg(
            Arg::new("run-id")
                .long("run-id")
                .required(true)
                .value_name("ID"),
        )
        .arg(
            Arg::new("workdir")
                .long("workdir")
                .required(true)
                .value_name("DIR"),
        )
}

fn exit_diagnostic(diagnostic: Diagnostic, json: bool) -> ! {
    if json {
        let rendered = match serde_json::to_string(&diagnostic) {
            Ok(rendered) => rendered,
            Err(_) => JSON_ERROR.to_owned(),
        };
        eprintln!("{rendered}");
    } else {
        eprintln!("{diagnostic}");
    }
    exit(2)
}

fn exit_invalid_arguments(json: bool) -> ! {
    exit_diagnostic(Diagnostic::invalid_cli_arguments(), json)
}

fn write_stdout(output: &str, json: bool) {
    if std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .is_err()
    {
        exit_diagnostic(Diagnostic::stdout_write_failed(), json);
    }
}

use crate::secure_open::{SkillValidationFailure, read_skill_file};

fn validate_skill_manifest(
    root: &Path,
) -> Result<(Vec<u8>, SkillManifest), SkillValidationFailure> {
    let markdown = read_skill_file(root, "SKILL.md", SkillValidationFailure::Manifest)?;
    let manifest =
        SkillManifest::parse(root, &markdown).map_err(|_| SkillValidationFailure::Manifest)?;
    Ok((markdown, manifest))
}

fn lint_skill(root: &Path) -> Result<(), SkillValidationFailure> {
    let _ = validate_skill_manifest(root)?;
    Ok(())
}

fn test_skill(root: &Path) -> Result<(), SkillValidationFailure> {
    let (markdown, manifest) = validate_skill_manifest(root)?;
    let runtime_bytes =
        read_skill_file(root, "skill.runtime.toml", SkillValidationFailure::Manifest)?;
    let runtime = SkillRuntimeManifest::parse(&runtime_bytes)
        .map_err(|_| SkillValidationFailure::Manifest)?;
    let skill_metadata = manifest.discovery_metadata();
    if runtime.skill_id() != skill_metadata.id() {
        return Err(SkillValidationFailure::Manifest);
    }

    let mut scripts = Vec::with_capacity(runtime.scripts().len());
    for script in runtime.scripts() {
        if script.runtime() != "python3" {
            return Err(SkillValidationFailure::Script);
        }
        let bytes = read_skill_file(root, script.path(), SkillValidationFailure::Script)?;
        scripts.push((script.id().as_str().to_owned(), bytes));
    }

    let mut resources = Vec::<(SkillResourceId, Vec<u8>)>::with_capacity(runtime.resources().len());
    for resource in runtime.resources() {
        let bytes = read_skill_file(root, resource.id().as_str(), SkillValidationFailure::Script)?;
        resources.push((resource.id().clone(), bytes));
    }

    let script_bytes = scripts
        .iter()
        .map(|(id, bytes)| (id.as_str(), bytes.as_slice()));
    let resource_bytes = resources.iter().map(|(id, bytes)| (id, bytes.as_slice()));
    SkillRuntimeLock::try_from_declared_bytes(&runtime, &markdown, script_bytes, resource_bytes)
        .map_err(|_| SkillValidationFailure::Script)?;
    Ok(())
}

fn skill_diagnostic(failure: SkillValidationFailure) -> Diagnostic {
    match failure {
        SkillValidationFailure::Manifest => Diagnostic::skill_manifest_invalid(),
        SkillValidationFailure::Script => Diagnostic::skill_script_invalid(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn build_binding(workflow: &str, module: &str) -> Result<PureTransformBinding, Box<Diagnostic>> {
    let plan = match compile_file(workflow) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(Box::new(match Diagnostic::try_from(&error) {
                Ok(diagnostic) => diagnostic,
                Err(_) => Diagnostic::invalid_cli_arguments(),
            }));
        }
    };
    let ir = plan.ir();
    let module_bytes = match read_bounded_regular_file(
        &SourcePath::from(module),
        PureTransformRequest::MAX_MODULE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return Err(Box::new(Diagnostic::run_unsupported_input())),
    };
    let digest = format!("sha256:{}", hex_encode(&Sha256::digest(&module_bytes)));
    PureTransformBinding::new(
        ir.workflow_id().as_str(),
        ir.workflow_version(),
        digest,
        &module_bytes,
    )
    .map_err(|_| Box::new(Diagnostic::run_unsupported_input()))
}

/// Compiles the workflow and builds the bounded pure-transform execution plan.
///
/// Any unsupported input fails closed with a typed `workflow.run` diagnostic
/// without executing nodes or touching artifact state.
fn build_run_plan(
    workflow: &str,
    module: &str,
    input: &str,
) -> Result<PureTransformPlanV1, Box<Diagnostic>> {
    let binding = build_binding(workflow, module)?;
    let input: Value = match serde_json::from_str(input) {
        Ok(input) => input,
        Err(_) => return Err(Box::new(Diagnostic::run_unsupported_input())),
    };
    PureTransformPlanV1::new(
        binding,
        input,
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .map_err(|_| Box::new(Diagnostic::run_unsupported_input()))
}

fn reload_bindings(
    current: PureTransformBinding,
    replacement: &PureTransformBinding,
) -> Result<(PureTransformBinding, PureTransformBinding), HotReloadError> {
    let mut publisher = DevelopmentHotReload::new(current);
    let old_run = publisher.start_run();
    let published = publisher.reload(
        old_run.module_digest(),
        replacement.workflow_id(),
        replacement.workflow_version(),
        replacement.module_digest(),
        Some(replacement.module_bytes()),
    )?;
    Ok((old_run, published))
}

fn run_limits() -> RunLimits {
    RunLimits::new(
        NonZeroU64::new(10_000).expect("positive limit"),
        NonZeroU64::new(10_000).expect("positive limit"),
        NonZeroU64::new(10_000).expect("positive limit"),
        NonZeroU64::new(60_000).expect("positive limit"),
        NonZeroU64::new(60_000).expect("positive limit"),
        NonZeroU64::new(60_000).expect("positive limit"),
        NonZeroU64::new(64 * 1024).expect("positive limit"),
    )
}

/// Distinct typed CLI dispositions for test, eval, replay, and boundary miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CliDisposition {
    TestRun,
    EvalRun,
    ReplayRun,
    BoundaryMiss,
}

/// Redacted acknowledgement that one CLI command ran.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CliEnvelope {
    disposition: CliDisposition,
    fixture_name: String,
    fixture_count: usize,
    payload_len: usize,
}

impl CliEnvelope {
    #[cfg(test)]
    fn disposition(&self) -> CliDisposition {
        self.disposition
    }
}

impl fmt::Display for CliEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.disposition {
            CliDisposition::TestRun => "test ran",
            CliDisposition::EvalRun => "eval ran",
            CliDisposition::ReplayRun => "replay ran",
            CliDisposition::BoundaryMiss => "command fixture missed a typed boundary",
        })
    }
}

/// Typed, payload-free CLI bind failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct CliError {
    disposition: CliDisposition,
    code: &'static str,
}

impl CliError {
    const TEST_BOUNDARY: Self = Self {
        disposition: CliDisposition::BoundaryMiss,
        code: "workflow.cli.boundary_miss",
    };
    const EVAL_BOUNDARY: Self = Self {
        disposition: CliDisposition::BoundaryMiss,
        code: "eval.boundary_miss",
    };
    const REPLAY_INVALID: Self = Self {
        disposition: CliDisposition::BoundaryMiss,
        code: "workflow.cli.replay_invalid",
    };

    #[cfg(test)]
    fn disposition(self) -> CliDisposition {
        self.disposition
    }

    fn diagnostic(self) -> Diagnostic {
        match self.code {
            "eval.boundary_miss" => Diagnostic::eval_boundary_miss(),
            "workflow.cli.replay_invalid" => Diagnostic::replay_invalid(),
            "workflow.audit.critical" => Diagnostic::audit_critical(),
            "workflow.audit.boundary_miss" => Diagnostic::audit_boundary_miss(),
            _ => Diagnostic::cli_boundary_miss(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            "eval.boundary_miss" => "eval boundary miss",
            "workflow.cli.replay_invalid" => "replay bundle is invalid",
            _ => "command fixture missed a typed boundary",
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedFixtureWire {
    name: String,
    payload: String,
}

fn invalid_token(value: &str) -> bool {
    value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control())
}

fn bind_test(name: &str, payload: &str) -> Result<CliEnvelope, CliError> {
    if invalid_token(name) || invalid_token(payload) {
        return Err(CliError::TEST_BOUNDARY);
    }
    validate_secret_free_fixture(
        SecretFixtureSurface::State,
        "state.json",
        payload.as_bytes(),
    )
    .map_err(|_| CliError::TEST_BOUNDARY)?;
    Ok(CliEnvelope {
        disposition: CliDisposition::TestRun,
        fixture_name: name.to_owned(),
        fixture_count: 1,
        payload_len: payload.len(),
    })
}

fn bind_eval(name: &str, payload: &str) -> Result<CliEnvelope, CliError> {
    validate_secret_free_fixture(
        SecretFixtureSurface::Workdir,
        "workdir/output.txt",
        payload.as_bytes(),
    )
    .map_err(|_| CliError::EVAL_BOUNDARY)?;
    let envelope = compile_eval(EvalInput::trajectory(EvalFixture::new(
        name.to_owned(),
        payload.to_owned(),
    )))
    .map_err(|_| CliError::EVAL_BOUNDARY)?;
    match envelope {
        EvalEnvelope::Trajectory { acknowledgement } => Ok(CliEnvelope {
            disposition: CliDisposition::EvalRun,
            fixture_name: acknowledgement.fixture_name().to_owned(),
            fixture_count: acknowledgement.fixture_count(),
            payload_len: payload.len(),
        }),
        EvalEnvelope::Rubric { .. } | EvalEnvelope::TrajectoryAndRubric { .. } => {
            Err(CliError::EVAL_BOUNDARY)
        }
    }
}

fn bind_replay(bytes: &[u8]) -> Result<CliEnvelope, CliError> {
    validate_secret_free_fixture(SecretFixtureSurface::Trace, "trace.jsonl", bytes)
        .map_err(|_| CliError::REPLAY_INVALID)?;
    let bundle = ReplayBundle::from_json(bytes).map_err(|_| CliError::REPLAY_INVALID)?;
    let trace = bundle.replay();
    Ok(CliEnvelope {
        disposition: CliDisposition::ReplayRun,
        fixture_name: String::from("replay"),
        fixture_count: trace.events().len(),
        payload_len: bytes.len(),
    })
}

const AUDIT_POLICY_PATH: &str = "deny.toml";
const AUDIT_LOCK_PATH: &str = "Cargo.lock";
const MAX_AUDIT_FILE_BYTES: usize = 1_048_576;

fn bind_audit() -> Result<String, Box<Diagnostic>> {
    let policy = read_audit_text(AUDIT_POLICY_PATH)?;
    let lock = read_audit_text(AUDIT_LOCK_PATH)?;
    match audit_dependencies(&policy, &lock) {
        Ok(report) => match report.disposition() {
            AuditDisposition::Clean => Ok(report.to_string()),
            AuditDisposition::Critical => Err(Box::new(Diagnostic::audit_critical())),
            AuditDisposition::BoundaryMiss => Err(Box::new(Diagnostic::audit_boundary_miss())),
        },
        Err(_) => Err(Box::new(Diagnostic::audit_boundary_miss())),
    }
}

fn read_audit_text(path: &str) -> Result<String, Box<Diagnostic>> {
    let bytes = read_bounded_regular_file(&SourcePath::from(path), MAX_AUDIT_FILE_BYTES)
        .map_err(|_| Box::new(Diagnostic::audit_boundary_miss()))?;
    String::from_utf8(bytes).map_err(|_| Box::new(Diagnostic::audit_boundary_miss()))
}

fn parse_named_fixture(bytes: &[u8], miss: CliError) -> Result<(String, String), CliError> {
    let wire: NamedFixtureWire = serde_json::from_slice(bytes).map_err(|_| miss)?;
    Ok((wire.name, wire.payload))
}

fn read_fixture_bytes(path: &str) -> Option<Vec<u8>> {
    read_bounded_regular_file(&SourcePath::from(path), ReplayBundle::MAX_BUNDLE_BYTES).ok()
}

fn write_command_result(envelope: &CliEnvelope, json: bool) {
    if json {
        match serde_json::to_string(envelope) {
            Ok(rendered) => write_stdout(&format!("{rendered}\n"), json),
            Err(_) => exit_diagnostic(Diagnostic::stdout_write_failed(), json),
        }
    } else {
        write_stdout(&format!("{envelope}\n"), json);
    }
}

fn write_execution_receipt(receipt: &ExecutionReceipt, json: bool) {
    if json {
        match serde_json::to_string(receipt) {
            Ok(rendered) => write_stdout(&format!("{rendered}\n"), json),
            Err(_) => exit_diagnostic(Diagnostic::stdout_write_failed(), json),
        }
    } else {
        write_stdout(
            &format!(
                "run_id={} status={} root={}\n",
                receipt.run_id(),
                receipt.status(),
                receipt.run_root().display()
            ),
            json,
        );
    }
}

fn exit_execution_error(kind: ExecutionErrorKind, json: bool) -> ! {
    let diagnostic = if kind == ExecutionErrorKind::InvalidProfile {
        Diagnostic::run_unsupported_input()
    } else {
        Diagnostic::run_failed_with_category(kind.conformance_category())
    };
    exit_diagnostic(diagnostic, json)
}

pub(crate) fn run() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    let json = arguments
        .iter()
        .take_while(|argument| argument.as_encoded_bytes() != b"--")
        .any(|argument| argument == "--json");
    let valid = arguments.iter().enumerate().all(|(index, argument)| {
        (index > 0 && arguments[index - 1] == "--input"
            || argument.as_encoded_bytes().len() <= 4096)
            && argument.to_str().is_some_and(|value| {
                !value.is_empty()
                    && !value.chars().any(|character| {
                        character <= '\u{001f}'
                            || character == '\u{007f}'
                            || ('\u{0080}'..='\u{009f}').contains(&character)
                            || matches!(
                                character,
                                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}'
                            )
                            || ('\u{202a}'..='\u{202e}').contains(&character)
                            || ('\u{2066}'..='\u{2069}').contains(&character)
                    })
            })
    });
    if !valid {
        exit_invalid_arguments(json);
    }

    let mut clap_arguments = Vec::with_capacity(arguments.len() + 1);
    clap_arguments.push(OsString::from("workflowctl"));
    clap_arguments.extend(arguments);
    let matches = match command().try_get_matches_from(clap_arguments) {
        Ok(matches) => matches,
        Err(_) => exit_invalid_arguments(json),
    };

    if matches.get_flag("help") {
        write_stdout(HELP, json);
        return;
    }

    match matches.subcommand() {
        Some(("validate", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            match compile_file(path.as_str()) {
                Ok(_) => write_stdout("valid\n", json),
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            }
        }
        Some(("graph", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            match compile_file(path.as_str()) {
                Ok(plan) => write_stdout(&render_mermaid(&plan), json),
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            }
        }
        Some(("lock", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let plan = match compile_file(path.as_str()) {
                Ok(plan) => plan,
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            };
            let workflow_lock = match WorkflowLock::try_from_plan(&plan) {
                Ok(workflow_lock) => workflow_lock,
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            };
            match workflow_lock.to_toml() {
                Ok(toml) => write_stdout(&toml, json),
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            }
        }
        Some(("skill", skill)) => match skill.subcommand() {
            Some(("lint", subcommand)) => {
                let Some(path) = subcommand.get_one::<String>("path") else {
                    exit_invalid_arguments(json);
                };
                match lint_skill(Path::new(path)) {
                    Ok(()) => write_stdout("valid\n", json),
                    Err(failure) => exit_diagnostic(skill_diagnostic(failure), json),
                }
            }
            Some(("test", subcommand)) => {
                let Some(path) = subcommand.get_one::<String>("path") else {
                    exit_invalid_arguments(json);
                };
                match test_skill(Path::new(path)) {
                    Ok(()) => write_stdout("passed\n", json),
                    Err(failure) => exit_diagnostic(skill_diagnostic(failure), json),
                }
            }
            _ => exit_invalid_arguments(json),
        },
        Some(("explain-run", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(module) = subcommand.get_one::<String>("module") else {
                exit_invalid_arguments(json);
            };
            let Some(input) = subcommand.get_one::<String>("input") else {
                exit_invalid_arguments(json);
            };
            match build_run_plan(path.as_str(), module.as_str(), input.as_str()) {
                Ok(plan) => write_stdout(&plan.render(), json),
                Err(diagnostic) => exit_diagnostic(*diagnostic, json),
            }
        }
        Some(("reload", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(module) = subcommand.get_one::<String>("module") else {
                exit_invalid_arguments(json);
            };
            let Some(current_workflow) = subcommand.get_one::<String>("current-workflow") else {
                exit_invalid_arguments(json);
            };
            let Some(current_module) = subcommand.get_one::<String>("current-module") else {
                exit_invalid_arguments(json);
            };
            let Some(input) = subcommand.get_one::<String>("input") else {
                exit_invalid_arguments(json);
            };
            let plan = match build_run_plan(path.as_str(), module.as_str(), input.as_str()) {
                Ok(plan) => plan,
                Err(diagnostic) => exit_diagnostic(*diagnostic, json),
            };
            let current = match build_binding(current_workflow.as_str(), current_module.as_str()) {
                Ok(binding) => binding,
                Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
            };
            match reload_bindings(current, plan.binding()) {
                Ok((old_run, published)) => {
                    let old_input: Value = match serde_json::from_str(input.as_str()) {
                        Ok(input) => input,
                        Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
                    };
                    let old_plan = match PureTransformPlanV1::new(
                        old_run.clone(),
                        old_input,
                        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
                    ) {
                        Ok(plan) => plan,
                        Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
                    };
                    write_stdout(
                        &format!(
                            "reloaded old={} new={}\n{}",
                            old_run.module_digest(),
                            published.module_digest(),
                            old_plan.render()
                        ),
                        json,
                    );
                }
                Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
            }
        }
        Some(("run", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(input) = subcommand.get_one::<String>("input") else {
                exit_invalid_arguments(json);
            };
            let Some(workdir) = subcommand.get_one::<String>("workdir") else {
                exit_invalid_arguments(json);
            };
            if let Some(profile_path) = subcommand.get_one::<String>("profile") {
                let profile_bytes = match read_bounded_regular_file(
                    &SourcePath::from(profile_path.as_str()),
                    64 * 1024,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
                };
                let profile = match ExecutionProfileV1::parse(&profile_bytes) {
                    Ok(profile) => profile,
                    Err(error) => exit_execution_error(error.kind(), json),
                };
                let input = match serde_json::from_str(input) {
                    Ok(input) => input,
                    Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
                };
                let cancellation = interrupt_cancellation();
                if subcommand.get_flag("fail-checkpoint-saves") {
                    ExecutionBackend::fail_checkpoint_saves_for_tests();
                }
                match ExecutionBackend::run_cancellable(path, profile, input, workdir, cancellation)
                {
                    Ok(receipt) => write_execution_receipt(&receipt, json),
                    Err(error) => {
                        if let Some(receipt) = error.receipt() {
                            write_execution_receipt(receipt, json);
                        }
                        exit_execution_error(error.kind(), json)
                    }
                }
                return;
            }
            let Some(module) = subcommand.get_one::<String>("module") else {
                exit_invalid_arguments(json);
            };
            let plan = match build_run_plan(path.as_str(), module.as_str(), input.as_str()) {
                Ok(plan) => plan,
                Err(diagnostic) => exit_diagnostic(*diagnostic, json),
            };
            let run_id = match RunId::new(format!(
                "workflowctl:{}:{}",
                plan.binding().workflow_id(),
                plan.binding().workflow_version()
            )) {
                Ok(run_id) => run_id,
                Err(_) => exit_diagnostic(Diagnostic::run_unsupported_input(), json),
            };
            let context = RunContext::new(run_id, run_limits());
            let manager = match WorkdirManager::new(workdir.as_str()) {
                Ok(manager) => manager,
                Err(_) => exit_diagnostic(Diagnostic::run_failed(), json),
            };
            let run_workdir = match manager.allocate(context.run_id()) {
                Ok(run_workdir) => run_workdir,
                Err(_) => exit_diagnostic(Diagnostic::run_failed(), json),
            };
            let mut artifacts = match FilesystemArtifactStore::try_new(
                std::path::Path::new(workdir.as_str()).join("artifacts"),
                NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
                NonZeroU64::new(64 * 1024).expect("positive page limit"),
            ) {
                Ok(store) => store,
                Err(_) => exit_diagnostic(Diagnostic::run_failed(), json),
            };
            let controller = RunController::new(&context);
            let started = Instant::now();
            let result = plan.execute(
                &context,
                controller,
                || started.elapsed(),
                &run_workdir,
                &mut artifacts,
            );
            let outcome = result.outcome();
            match outcome {
                RunOutcome::Completed { output } => {
                    write_stdout(&format!("artifact={}\n", output.as_str()), json);
                }
                RunOutcome::Abstained { .. }
                | RunOutcome::Incomplete { .. }
                | RunOutcome::Failed { .. }
                | RunOutcome::Cancelled { .. }
                | RunOutcome::TimedOut { .. }
                | RunOutcome::LimitExceeded { .. }
                | RunOutcome::PolicyDenied { .. } => {
                    exit_diagnostic(Diagnostic::run_failed(), json);
                }
            }
        }
        Some(("inspect", subcommand)) | Some(("resume", subcommand)) => {
            let Some(run_id) = subcommand.get_one::<String>("run-id") else {
                exit_invalid_arguments(json);
            };
            let Some(workdir) = subcommand.get_one::<String>("workdir") else {
                exit_invalid_arguments(json);
            };
            let result = if matches.subcommand_name() == Some("resume") {
                let cancellation = interrupt_cancellation();
                ExecutionBackend::resume_cancellable(workdir, run_id, cancellation)
            } else {
                ExecutionBackend::inspect(workdir, run_id)
            };
            match result {
                Ok(receipt) => write_execution_receipt(&receipt, json),
                Err(error) => exit_execution_error(error.kind(), json),
            }
        }
        Some(("test", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(bytes) = read_fixture_bytes(path) else {
                exit_invalid_arguments(json);
            };
            let (name, payload) = match parse_named_fixture(&bytes, CliError::TEST_BOUNDARY) {
                Ok(fixture) => fixture,
                Err(error) => exit_diagnostic(error.diagnostic(), json),
            };
            match bind_test(&name, &payload) {
                Ok(envelope) => write_command_result(&envelope, json),
                Err(error) => exit_diagnostic(error.diagnostic(), json),
            }
        }
        Some(("eval", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(bytes) = read_fixture_bytes(path) else {
                exit_invalid_arguments(json);
            };
            let (name, payload) = match parse_named_fixture(&bytes, CliError::EVAL_BOUNDARY) {
                Ok(fixture) => fixture,
                Err(error) => exit_diagnostic(error.diagnostic(), json),
            };
            match bind_eval(&name, &payload) {
                Ok(envelope) => write_command_result(&envelope, json),
                Err(error) => exit_diagnostic(error.diagnostic(), json),
            }
        }
        Some(("replay", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(bytes) = read_fixture_bytes(path) else {
                exit_invalid_arguments(json);
            };
            match bind_replay(&bytes) {
                Ok(envelope) => write_command_result(&envelope, json),
                Err(error) => exit_diagnostic(error.diagnostic(), json),
            }
        }
        Some(("audit", _)) => match bind_audit() {
            Ok(output) => write_stdout(&format!("{output}\n"), json),
            Err(diagnostic) => exit_diagnostic(*diagnostic, json),
        },
        _ => exit_invalid_arguments(json),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use sha2::{Digest, Sha256};
    use workflow_runtime::{DevelopmentHotReload, HotReloadErrorKind, ProductionProfile, RunId};

    use super::{
        CliDisposition, SkillValidationFailure, bind_eval, bind_replay, bind_test, command,
        test_skill, validate_skill_manifest,
    };

    const SCHEMA: &str =
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#;

    fn unit_skill_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "workflowctl-cli-005-unit-{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create unit skill directory");
        path
    }

    fn script_digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn invalid_manifest_fixture_maps_to_typed_diagnostic() {
        let path = unit_skill_path("manifest");
        let marker = "UNIT_INVALID_MANIFEST_55";
        fs::write(path.join("SKILL.md"), marker).expect("write invalid manifest fixture");

        let failure = match validate_skill_manifest(&path) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid manifest fixture must fail"),
        };
        let diagnostic = super::skill_diagnostic(failure);
        assert_eq!(diagnostic.code(), "skill.cli.invalid_manifest");
        assert!(
            !serde_json::to_string(&diagnostic)
                .expect("serialize diagnostic")
                .contains(marker)
        );
        fs::remove_dir_all(path).expect("remove unit skill directory");
    }

    #[test]
    fn invalid_script_fixture_maps_to_distinct_typed_diagnostic() {
        let path = unit_skill_path("script");
        let skill_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("unit skill directory name");
        let script = b"UNIT_INVALID_SCRIPT_55";
        fs::create_dir_all(path.join("scripts")).expect("create script directory");
        fs::create_dir_all(path.join("references")).expect("create references directory");
        fs::write(
            path.join("SKILL.md"),
            format!("---\nname: {skill_id}\ndescription: A unit fixture.\n---\n# Instructions\n"),
        )
        .expect("write valid manifest fixture");
        fs::write(path.join("scripts/check.py"), script).expect("write invalid script fixture");
        fs::write(path.join("references/schema.json"), SCHEMA).expect("write schema fixture");
        fs::write(
            path.join("skill.runtime.toml"),
            format!(
                "schema_version = 1\n\n[skill]\nid = \"{skill_id}\"\nversion = \"1.0.0\"\n\n[[scripts]]\nid = \"check\"\npath = \"scripts/check.py\"\nruntime = \"python3\"\nsha256 = \"sha256:{}\"\ninput_schema = \"references/schema.json\"\noutput_schema = \"references/schema.json\"\n\n[[resources]]\nid = \"references/schema.json\"\nsha256 = \"{}\"\n",
                "0".repeat(64),
                script_digest(SCHEMA.as_bytes()),
            ),
        )
        .expect("write runtime manifest fixture");

        let failure = match test_skill(&path) {
            Err(failure @ SkillValidationFailure::Script) => failure,
            Err(SkillValidationFailure::Manifest) => {
                panic!("legal manifest fixture must reach script validation")
            }
            Ok(()) => panic!("invalid script fixture must fail"),
        };
        let diagnostic = super::skill_diagnostic(failure);
        assert_eq!(diagnostic.code(), "skill.cli.invalid_script");
        assert_ne!(diagnostic.code(), "skill.cli.invalid_manifest");
        assert!(
            !serde_json::to_string(&diagnostic)
                .expect("serialize diagnostic")
                .contains("UNIT_INVALID_SCRIPT_55")
        );
        fs::remove_dir_all(path).expect("remove unit skill directory");
    }

    #[test]
    fn skill_lint_and_test_commands_are_declared() {
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "skill", "lint", "skill-dir"])
                .is_ok()
        );
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "skill", "test", "skill-dir"])
                .is_ok()
        );
    }

    #[test]
    fn test_eval_replay_commands_are_declared() {
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "test", "fixture.json"])
                .is_ok()
        );
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "eval", "fixture.json"])
                .is_ok()
        );
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "replay", "fixture.json"])
                .is_ok()
        );
    }

    #[test]
    fn local_ci_invokes_test_eval_replay_commands() {
        let justfile = include_str!("../../../justfile");
        assert!(
            justfile.contains("workflowctl test "),
            "local CI must invoke test"
        );
        assert!(
            justfile.contains("workflowctl eval "),
            "local CI must invoke eval"
        );
        assert!(
            justfile.contains("workflowctl replay "),
            "local CI must invoke replay"
        );
    }

    #[test]
    fn audit_command_is_declared() {
        assert!(
            command()
                .try_get_matches_from(["workflowctl", "audit"])
                .is_ok()
        );
    }

    #[test]
    fn local_ci_invokes_dependency_security_audit() {
        let justfile = include_str!("../../../justfile");
        assert!(
            justfile.contains("workflowctl audit"),
            "local CI must invoke the dependency security audit"
        );
    }

    const CANARY_HOTRELOAD_80: &str = "CANARY_HOTRELOAD_80";
    const CANARY_INFLIGHT_OLD_PKG_80: &str = "CANARY_INFLIGHT_OLD_PKG_80";
    const CANARY_PROD_NO_RELOAD_80: &str = "CANARY_PROD_NO_RELOAD_80";

    fn canary_binding(marker: &str) -> workflow_runtime::PureTransformBinding {
        let module = marker.as_bytes();
        workflow_runtime::PureTransformBinding::new(
            "workflow",
            marker,
            format!("sha256:{:x}", Sha256::digest(module)),
            module,
        )
        .expect("canary binding must be valid")
    }

    #[test]
    fn hot_reload_canary_declares_development_bind() {
        let old = canary_binding(&format!("{CANARY_HOTRELOAD_80}_OLD"));
        let new = canary_binding(&format!("{CANARY_HOTRELOAD_80}_NEW"));
        let mut publisher = DevelopmentHotReload::new(old.clone());
        let published = publisher
            .reload(
                old.module_digest(),
                new.workflow_id(),
                new.workflow_version(),
                new.module_digest(),
                Some(new.module_bytes()),
            )
            .expect("development reload must publish a new bind");
        assert_eq!(published.module_digest(), new.module_digest());
    }

    #[test]
    fn hot_reload_canary_keeps_inflight_old_package() {
        let old = canary_binding(&format!("{CANARY_INFLIGHT_OLD_PKG_80}_OLD"));
        let new = canary_binding(&format!("{CANARY_INFLIGHT_OLD_PKG_80}_NEW"));
        let mut publisher = DevelopmentHotReload::new(old.clone());
        let in_flight = publisher.start_run();
        publisher
            .reload(
                old.module_digest(),
                new.workflow_id(),
                new.workflow_version(),
                new.module_digest(),
                Some(new.module_bytes()),
            )
            .expect("reload must publish a new bind");
        assert_eq!(in_flight.module_digest(), old.module_digest());
        assert_eq!(in_flight.workflow_version(), old.workflow_version());
    }

    #[test]
    fn hot_reload_canary_rejects_production_bind() {
        let base =
            std::env::temp_dir().join(format!("workflowctl-prod-reload-{}", std::process::id()));
        fs::create_dir_all(&base).expect("production test base must be created");
        let profile = ProductionProfile::new(&base).expect("production profile must bind");
        let run_id = RunId::new(CANARY_PROD_NO_RELOAD_80.to_owned()).expect("run ID must be valid");
        let binding = profile.bind(&run_id).expect("production bind must succeed");
        let error = binding
            .reload("current", "workflow", "2", "sha256:invalid", Some(b"new"))
            .expect_err("production reload must fail closed");
        assert_eq!(error.kind(), HotReloadErrorKind::ProductionReloadForbidden);
        let _ = std::fs::remove_dir_all(base);
    }

    const CANARY_CLI_TEST_54: &str = "CANARY_CLI_TEST_54";
    const CANARY_CLI_EVAL_54: &str = "CANARY_CLI_EVAL_54";
    const CANARY_CLI_REPLAY_54: &str = "CANARY_CLI_REPLAY_54";
    const CANARY_CLI_BOUNDARY_54: &str = "CANARY_CLI_BOUNDARY_54";

    fn canary_replay_bytes(canary: &str) -> Vec<u8> {
        let digest = format!("sha256:{:x}", Sha256::digest(canary.as_bytes()));
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "workflow_lock": {
                "toml": "test",
                "sha256": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            },
            "input_sha256": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "events": [
                { "type": "node_started", "node_id": "node-a" },
                {
                    "type": "terminal",
                    "status": "completed",
                    "outcome_sha256": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                }
            ],
            "fixtures": [
                { "sha256": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
                { "sha256": digest, "bytes": canary.as_bytes() }
            ],
            "artifacts": []
        }))
        .expect("serialize replay canary")
    }

    #[test]
    fn production_state_persistence_rejects_secret_canary() {
        let error = bind_test("state-78", "CANARY_SECRET_PROD_STATE_78")
            .expect_err("state persistence must reject secret canary");
        assert_eq!(error.disposition(), CliDisposition::BoundaryMiss);
    }

    #[test]
    fn production_workdir_persistence_rejects_secret_canary() {
        let error = bind_eval("workdir-78", "CANARY_SECRET_PROD_WORKDIR_78")
            .expect_err("workdir persistence must reject secret canary");
        assert_eq!(error.disposition(), CliDisposition::BoundaryMiss);
    }

    #[test]
    fn production_trace_persistence_rejects_secret_canary() {
        let bytes = canary_replay_bytes("CANARY_SECRET_PROD_TRACE_78");
        let bytes = String::from_utf8(bytes)
            .expect("replay fixture must be JSON")
            .replace(
                "\"toml\":\"test\"",
                "\"toml\":\"CANARY_SECRET_PROD_TRACE_78\"",
            );
        let error =
            bind_replay(bytes.as_bytes()).expect_err("trace persistence must reject secret canary");
        assert_eq!(error.disposition(), CliDisposition::BoundaryMiss);
    }

    #[test]
    fn canary_cli_test_54_is_typed_test_run_not_eval_or_replay() {
        let result = bind_test("canary-cli-test-54", CANARY_CLI_TEST_54)
            .expect("test canary must run through the platform test API");
        assert_eq!(result.disposition(), CliDisposition::TestRun);
        assert_ne!(result.disposition(), CliDisposition::EvalRun);
        assert_ne!(result.disposition(), CliDisposition::ReplayRun);
        assert!(!format!("{result:?}").contains(CANARY_CLI_TEST_54));
        assert!(!result.to_string().contains(CANARY_CLI_TEST_54));
        assert!(
            !serde_json::to_string(&result)
                .expect("serialize test envelope")
                .contains(CANARY_CLI_TEST_54)
        );
    }

    #[test]
    fn canary_cli_eval_54_is_typed_eval_run_not_test_or_replay() {
        let result = bind_eval("canary-cli-eval-54", CANARY_CLI_EVAL_54)
            .expect("eval canary must run through the eval bind");
        assert_eq!(result.disposition(), CliDisposition::EvalRun);
        assert_ne!(result.disposition(), CliDisposition::TestRun);
        assert_ne!(result.disposition(), CliDisposition::ReplayRun);
        assert!(!format!("{result:?}").contains(CANARY_CLI_EVAL_54));
        assert!(!result.to_string().contains(CANARY_CLI_EVAL_54));
        assert!(
            !serde_json::to_string(&result)
                .expect("serialize eval envelope")
                .contains(CANARY_CLI_EVAL_54)
        );
    }

    #[test]
    fn canary_cli_replay_54_is_typed_replay_run_not_test_or_eval() {
        let result = bind_replay(&canary_replay_bytes(CANARY_CLI_REPLAY_54))
            .expect("replay canary must run through the replay bind");
        assert_eq!(result.disposition(), CliDisposition::ReplayRun);
        assert_ne!(result.disposition(), CliDisposition::TestRun);
        assert_ne!(result.disposition(), CliDisposition::EvalRun);
        assert!(!format!("{result:?}").contains(CANARY_CLI_REPLAY_54));
        assert!(!result.to_string().contains(CANARY_CLI_REPLAY_54));
        assert!(
            !serde_json::to_string(&result)
                .expect("serialize replay envelope")
                .contains(CANARY_CLI_REPLAY_54)
        );
    }

    #[test]
    fn canary_cli_boundary_54_is_typed_miss_and_cannot_report_all_three_ran() {
        let error = bind_test("", CANARY_CLI_BOUNDARY_54)
            .expect_err("empty fixture name must miss the boundary");
        assert_eq!(error.disposition(), CliDisposition::BoundaryMiss);
        assert_ne!(error.disposition(), CliDisposition::TestRun);
        assert_ne!(error.disposition(), CliDisposition::EvalRun);
        assert_ne!(error.disposition(), CliDisposition::ReplayRun);
        assert!(!format!("{error:?}").contains(CANARY_CLI_BOUNDARY_54));
        assert!(!error.to_string().contains(CANARY_CLI_BOUNDARY_54));
        let serialized = serde_json::to_string(&error).expect("serialize boundary error");
        assert!(!serialized.contains(CANARY_CLI_BOUNDARY_54));
        assert!(
            !(serialized.contains("test_run")
                && serialized.contains("eval_run")
                && serialized.contains("replay_run"))
        );
    }
}
