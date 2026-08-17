use std::{ffi::OsString, process::exit};

use clap::{Arg, ArgAction, Command};
use workflow_compiler::Diagnostic;

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS]\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n\nPlanned commands (not available in v0.1): validate, graph, lock\n";
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
}

fn exit_invalid_arguments(json: bool) -> ! {
    let diagnostic = Diagnostic::invalid_cli_arguments();
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
    } else {
        exit_invalid_arguments(json);
    }
}
