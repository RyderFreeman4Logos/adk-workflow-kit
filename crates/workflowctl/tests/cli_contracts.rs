use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    process::{Command, Output},
};

const HELP: &str = "Thin workflow CLI over reusable libraries\n\nUsage: workflowctl [OPTIONS]\n\nOptions:\n      --json  Emit diagnostics as JSON\n  -h, --help  Print help\n\nPlanned commands (not available in v0.1): validate, graph, lock\n";
const HUMAN_ERROR: &str =
    "[workflow.cli.invalid_arguments] invalid command-line arguments location=null details={}\n";
const JSON_ERROR: &str = "{\"diagnostic_version\":1,\"code\":\"workflow.cli.invalid_arguments\",\"message\":\"invalid command-line arguments\",\"location\":null,\"details\":{}}\n";

fn output(command: &mut Command) -> Output {
    match command.output() {
        Ok(output) => output,
        Err(error) => panic!("workflowctl should start: {error}"),
    }
}

fn assert_error(output: Output, expected_stderr: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, expected_stderr.as_bytes());
}

#[test]
fn help_is_deterministic_success_with_empty_stderr_and_no_dispatch() {
    for arguments in [
        ["-h"].as_slice(),
        ["--help"].as_slice(),
        ["--json", "--help"].as_slice(),
        ["--help", "--json"].as_slice(),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.args(arguments);
        let output = output(&mut command);

        assert!(output.status.success());
        assert_eq!(output.stdout, HELP.as_bytes());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn json_error_is_stable_and_redacts_untrusted_arguments() {
    let secret = "secret-token-should-not-appear";
    let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    command.args(["--json", secret]);
    let output = output(&mut command);

    assert_error(output, JSON_ERROR);
}

#[test]
fn empty_and_hostile_arguments_fail_closed_without_panic_or_echo() {
    let hostile = [
        OsString::new(),
        OsString::from("\u{001f}"),
        OsString::from("\u{007f}"),
        OsString::from("\u{0080}"),
        OsString::from("\u{061c}"),
        OsString::from("\u{200e}"),
        OsString::from("\u{200f}"),
        OsString::from("\u{2028}"),
        OsString::from("\u{2029}"),
        OsString::from("\u{202a}"),
        OsString::from("\u{202e}"),
        OsString::from("\u{2066}"),
        OsString::from("\u{2069}"),
        OsString::from_vec(vec![0xff]),
    ];

    for argument in hostile {
        let mut command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
        command.arg(argument);
        assert_error(output(&mut command), HUMAN_ERROR);
    }
}

#[test]
fn oversized_argument_is_rejected_before_dispatch() {
    let accepted = "a".repeat(4096);
    let rejected = "a".repeat(4097);

    let mut accepted_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    accepted_command.arg(accepted);
    assert_error(output(&mut accepted_command), HUMAN_ERROR);

    let mut rejected_command = Command::new(env!("CARGO_BIN_EXE_workflowctl"));
    rejected_command.args(["--json", rejected.as_str()]);
    assert_error(output(&mut rejected_command), JSON_ERROR);
}
