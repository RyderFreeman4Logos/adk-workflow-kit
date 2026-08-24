use std::{ffi::OsString, io::Write, num::NonZeroU64, path::Path, process::exit, time::Instant};

use clap::{Arg, ArgAction, Command};
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_compiler::{
    compile_file, render_mermaid, Diagnostic, SkillManifest, SkillResourceId, SkillRuntimeLock,
    SkillRuntimeManifest, WorkflowLock,
};
use workflow_runtime::{
    FilesystemArtifactStore, PureTransformBinding, PureTransformPlanV1, PureTransformRequest,
    RequestedCapabilities, RunContext, RunController, RunId, RunLimits, RunOutcome,
    SandboxCapability, WorkdirManager,
};
use workflow_spec::{read_bounded_regular_file, SourcePath};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS] <COMMAND>\n\nCommands:\n  validate <PATH>\n  graph <PATH> --format mermaid\n  lock <PATH>\n  skill lint <PATH>\n  skill test <PATH>\n  run <PATH> --module <PATH> --input <JSON> --workdir <DIR>\n  explain-run <PATH> --module <PATH> --input <JSON>\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n";
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

const MAX_SKILL_FILE_BYTES: usize = 65_536;

#[derive(Clone, Copy)]
enum SkillValidationFailure {
    Manifest,
    Script,
}

fn read_skill_file(
    root: &Path,
    relative_path: &str,
    failure: SkillValidationFailure,
) -> Result<Vec<u8>, SkillValidationFailure> {
    let path = root.join(relative_path);
    read_bounded_regular_file(&SourcePath::from(path.as_path()), MAX_SKILL_FILE_BYTES)
        .map_err(|_| failure)
}

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
    let module_bytes = match read_bounded_regular_file(
        &SourcePath::from(module),
        PureTransformRequest::MAX_MODULE_BYTES,
    ) {
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
        _ => exit_invalid_arguments(json),
    }
}

#[cfg(test)]
mod tests {
    use super::command;

    #[test]
    fn skill_lint_and_test_commands_are_declared() {
        assert!(command()
            .try_get_matches_from(["workflowctl", "skill", "lint", "skill-dir"])
            .is_ok());
        assert!(command()
            .try_get_matches_from(["workflowctl", "skill", "test", "skill-dir"])
            .is_ok());
    }
}
