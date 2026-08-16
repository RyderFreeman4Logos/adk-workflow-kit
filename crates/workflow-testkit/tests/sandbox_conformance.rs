use std::{collections::BTreeMap, path::PathBuf};

use workflow_runtime::{
    BackendCapabilities, RequestedCapabilities, SandboxCapability, UnsatisfiedCapabilities,
};
use workflow_testkit::{
    FakeSandboxBackend, FakeSandboxRequest, FakeSandboxRequestError, FakeSandboxRequestErrorKind,
};

fn assert_request_error(
    result: Result<FakeSandboxRequest, FakeSandboxRequestError>,
    expected_kind: FakeSandboxRequestErrorKind,
    hostile_input: &str,
) {
    let error = match result {
        Ok(_) => panic!("request should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), expected_kind);
    if !hostile_input.is_empty() {
        assert!(!error.to_string().contains(hostile_input));
    }
}

#[test]
fn empty_commands_are_rejected_without_recording_calls() {
    let backend = FakeSandboxBackend::new(BackendCapabilities::new([]));

    for command in ["", " \t\n"] {
        assert_request_error(
            FakeSandboxRequest::new(
                command.to_owned(),
                PathBuf::from("/work"),
                BTreeMap::new(),
                RequestedCapabilities::new([]),
            ),
            FakeSandboxRequestErrorKind::EmptyCommand,
            command,
        );
    }

    assert_eq!(backend.call_count(), 0);
}

#[test]
fn hostile_requests_are_rejected_without_exposing_input() {
    let backend = FakeSandboxBackend::new(BackendCapabilities::new([]));
    let hostile_command = "echo\u{7}command-secret";
    let hostile_workdir = "/tmp/../workdir-secret";
    let hostile_name = "BAD-NAME-SECRET";
    let hostile_value = "value\u{7}secret";

    assert_request_error(
        FakeSandboxRequest::new(
            hostile_command.to_owned(),
            PathBuf::from("/work"),
            BTreeMap::new(),
            RequestedCapabilities::new([]),
        ),
        FakeSandboxRequestErrorKind::HostileCommand,
        hostile_command,
    );
    assert_request_error(
        FakeSandboxRequest::new(
            "true".to_owned(),
            PathBuf::from(hostile_workdir),
            BTreeMap::new(),
            RequestedCapabilities::new([]),
        ),
        FakeSandboxRequestErrorKind::HostileWorkdir,
        hostile_workdir,
    );
    assert_request_error(
        FakeSandboxRequest::new(
            "true".to_owned(),
            PathBuf::from("/work"),
            BTreeMap::from([(hostile_name.to_owned(), "safe".to_owned())]),
            RequestedCapabilities::new([]),
        ),
        FakeSandboxRequestErrorKind::HostileEnvironment,
        hostile_name,
    );
    assert_request_error(
        FakeSandboxRequest::new(
            "true".to_owned(),
            PathBuf::from("/work"),
            BTreeMap::from([("SAFE".to_owned(), hostile_value.to_owned())]),
            RequestedCapabilities::new([]),
        ),
        FakeSandboxRequestErrorKind::HostileEnvironment,
        hostile_value,
    );

    assert_eq!(backend.call_count(), 0);
}

#[test]
fn requests_over_public_limits_are_rejected_without_recording_calls() {
    let backend = FakeSandboxBackend::new(BackendCapabilities::new([]));
    let too_many_environment_variables = (0..=FakeSandboxRequest::MAX_ENVIRONMENT_ENTRIES)
        .map(|index| (format!("VAR_{index}"), "x".to_owned()))
        .collect();
    let too_large_environment = BTreeMap::from([(
        "A".to_owned(),
        "x".repeat(FakeSandboxRequest::MAX_ENVIRONMENT_BYTES),
    )]);

    for (result, expected_kind) in [
        (
            FakeSandboxRequest::new(
                "x".repeat(FakeSandboxRequest::MAX_COMMAND_BYTES + 1),
                PathBuf::from("/work"),
                BTreeMap::new(),
                RequestedCapabilities::new([]),
            ),
            FakeSandboxRequestErrorKind::CommandTooLong,
        ),
        (
            FakeSandboxRequest::new(
                "true".to_owned(),
                PathBuf::from(format!(
                    "/{}",
                    "x".repeat(FakeSandboxRequest::MAX_WORKDIR_PATH_BYTES)
                )),
                BTreeMap::new(),
                RequestedCapabilities::new([]),
            ),
            FakeSandboxRequestErrorKind::WorkdirPathTooLong,
        ),
        (
            FakeSandboxRequest::new(
                "true".to_owned(),
                PathBuf::from("/work"),
                too_many_environment_variables,
                RequestedCapabilities::new([]),
            ),
            FakeSandboxRequestErrorKind::TooManyEnvironmentVariables,
        ),
        (
            FakeSandboxRequest::new(
                "true".to_owned(),
                PathBuf::from("/work"),
                too_large_environment,
                RequestedCapabilities::new([]),
            ),
            FakeSandboxRequestErrorKind::EnvironmentTooLarge,
        ),
    ] {
        assert_request_error(result, expected_kind, "not-present");
    }

    assert_eq!(backend.call_count(), 0);
}

#[test]
fn missing_capabilities_do_not_record_a_call() {
    let request = FakeSandboxRequest::new(
        "true".to_owned(),
        PathBuf::from("/work"),
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::Network]),
    )
    .expect("request should be valid");
    let mut backend = FakeSandboxBackend::new(BackendCapabilities::new([]));

    let error: UnsatisfiedCapabilities = backend
        .execute(&request)
        .expect_err("missing network capability should reject execution");

    assert_eq!(error.missing(), &[SandboxCapability::Network]);
    assert_eq!(backend.call_count(), 0);
}

#[test]
fn matching_capabilities_return_deterministic_receipts_without_creating_workdirs() {
    let workdir = std::env::temp_dir().join(format!(
        "workflow-testkit-fake-sandbox-{}",
        std::process::id()
    ));
    assert!(!workdir.exists(), "test workdir must start absent");
    let requested = || RequestedCapabilities::new([SandboxCapability::Network]);
    let request = || {
        FakeSandboxRequest::new(
            "true".to_owned(),
            workdir.clone(),
            BTreeMap::new(),
            requested(),
        )
        .expect("request should be valid")
    };
    let mut first = FakeSandboxBackend::new(BackendCapabilities::new([SandboxCapability::Network]));
    let mut second =
        FakeSandboxBackend::new(BackendCapabilities::new([SandboxCapability::Network]));

    let first_receipt = first.execute(&request()).expect("capabilities match");
    let second_receipt = second.execute(&request()).expect("capabilities match");

    assert_eq!(first_receipt, second_receipt);
    assert_eq!(first_receipt.call_index(), 1);
    assert_eq!(first.call_count(), 1);
    assert_eq!(second.call_count(), 1);
    assert!(!workdir.exists(), "fake execution must not create workdirs");
}
