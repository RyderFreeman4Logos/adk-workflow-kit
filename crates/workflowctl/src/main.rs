use std::{ffi::OsString, process::exit};

use clap::{Arg, ArgAction, Command};
use workflow_compiler::{compile_file, render_mermaid, Diagnostic, WorkflowLock};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS] <COMMAND>\n\nCommands:\n  validate <PATH>\n  graph <PATH> --format mermaid\n  lock <PATH>\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n";
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

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    let json = arguments.iter().any(|argument| argument == "--json");
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
        print!("{HELP}");
        return;
    }

    match matches.subcommand() {
        Some(("validate", subcommand)) => {
            let Some(path) = subcommand.get_one::<String>("path") else {
                exit_invalid_arguments(json);
            };
            match compile_file(path.as_str()) {
                Ok(_) => println!("valid"),
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
                Ok(plan) => print!("{}", render_mermaid(&plan)),
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
                Ok(toml) => print!("{toml}"),
                Err(error) => {
                    let diagnostic = match Diagnostic::try_from(&error) {
                        Ok(diagnostic) => diagnostic,
                        Err(_) => Diagnostic::invalid_cli_arguments(),
                    };
                    exit_diagnostic(diagnostic, json);
                }
            }
        }
        _ => exit_invalid_arguments(json),
    }
}
