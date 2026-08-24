use std::{ffi::OsString, io::Write, num::NonZeroU64, process::exit, time::Instant};

use clap::{Arg, ArgAction, Command};
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_compiler::{compile_file, render_mermaid, Diagnostic, WorkflowLock};
use workflow_runtime::{
    FilesystemArtifactStore, PureTransformBinding, PureTransformPlanV1, RequestedCapabilities,
    RunContext, RunController, RunId, RunLimits, RunOutcome, SandboxCapability, WorkdirManager,
};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS] <COMMAND>\n\nCommands:\n  validate <PATH>\n  graph <PATH> --format mermaid\n  lock <PATH>\n  run <PATH> --module <PATH> --input <JSON> --workdir <DIR>\n  explain-run <PATH> --module <PATH> --input <JSON>\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n";
const JSON_ERROR: &str = "{\"diagnostic_version\":1,\"code\":\"workflow.cli.invalid_arguments\",\"message\":\"invalid command-line arguments\",\"location\":null,\"details\":{}}";

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
                )
                .arg(
                    Arg::new("workdir")
                        .long("workdir")
                        .required(true)
                        .value_name("DIR")
                        .help("Run workdir base directory"),
                ),
        )
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

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
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
    let plan = match compile_file(workflow) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(Box::new(match Diagnostic::try_from(&error) {
                Ok(diagnostic) => diagnostic,
                Err(_) => Diagnostic::invalid_cli_arguments(),
            }))
        }
    };
    let ir = plan.ir();
    let module_bytes = match std::fs::read(module) {
        Ok(bytes) => bytes,
        Err(_) => return Err(Box::new(Diagnostic::run_unsupported_input())),
    };
    let input: Value = match serde_json::from_str(input) {
        Ok(input) => input,
        Err(_) => return Err(Box::new(Diagnostic::run_unsupported_input())),
    };
    let digest = format!("sha256:{}", hex_encode(&Sha256::digest(&module_bytes)));
    let binding = match PureTransformBinding::new(
        ir.workflow_id().as_str(),
        ir.workflow_version(),
        digest,
        &module_bytes,
    ) {
        Ok(binding) => binding,
        Err(_) => return Err(Box::new(Diagnostic::run_unsupported_input())),
    };
    PureTransformPlanV1::new(
        binding,
        input,
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .map_err(|_| Box::new(Diagnostic::run_unsupported_input()))
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

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    let json = arguments
        .iter()
        .take_while(|argument| argument.as_encoded_bytes() != b"--")
        .any(|argument| argument == "--json");
    let valid = arguments.iter().all(|argument| {
        argument.as_encoded_bytes().len() <= 4096
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
        Some(("run", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            let Some(module) = subcommand.get_one::<String>("module") else {
                exit_invalid_arguments(json);
            };
            let Some(input) = subcommand.get_one::<String>("input") else {
                exit_invalid_arguments(json);
            };
            let Some(workdir) = subcommand.get_one::<String>("workdir") else {
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
            let mut artifacts = FilesystemArtifactStore::new(
                std::path::Path::new(workdir.as_str()).join("artifacts"),
                NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
                NonZeroU64::new(64 * 1024).expect("positive page limit"),
            );
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
        _ => exit_invalid_arguments(json),
    }
}
