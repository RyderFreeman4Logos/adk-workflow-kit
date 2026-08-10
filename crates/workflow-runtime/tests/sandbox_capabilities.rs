use std::error::Error;

use workflow_runtime::{
    verify_sandbox_capabilities, BackendCapabilities, RequestedCapabilities, SandboxCapability,
    UnsatisfiedCapabilities,
};

#[test]
fn exact_capability_sets_succeed() {
    let requested = RequestedCapabilities::new([SandboxCapability::Network]);
    let backend = BackendCapabilities::new([SandboxCapability::Network]);

    assert!(verify_sandbox_capabilities(&requested, &backend).is_ok());
}

#[test]
fn backend_supersets_succeed() {
    let requested = RequestedCapabilities::new([SandboxCapability::Network]);
    let backend = BackendCapabilities::new([
        SandboxCapability::FilesystemRead,
        SandboxCapability::Network,
    ]);

    assert!(verify_sandbox_capabilities(&requested, &backend).is_ok());
}

#[test]
fn empty_requests_succeed_against_any_backend() {
    let requested = RequestedCapabilities::new([]);

    assert!(verify_sandbox_capabilities(&requested, &BackendCapabilities::new([])).is_ok());
    assert!(verify_sandbox_capabilities(
        &requested,
        &BackendCapabilities::new([SandboxCapability::Network]),
    )
    .is_ok());
}

#[test]
fn one_missing_class_returns_the_typed_error() {
    let error: UnsatisfiedCapabilities = verify_sandbox_capabilities(
        &RequestedCapabilities::new([SandboxCapability::FilesystemWrite]),
        &BackendCapabilities::new([]),
    )
    .expect_err("an empty backend must not satisfy filesystem.write");

    assert_eq!(error.missing(), &[SandboxCapability::FilesystemWrite]);
}

#[test]
fn several_missing_classes_are_reported_once_in_stable_name_order() {
    let error = verify_sandbox_capabilities(
        &RequestedCapabilities::new([
            SandboxCapability::ProcessSpawn,
            SandboxCapability::Network,
            SandboxCapability::DeviceAccess,
        ]),
        &BackendCapabilities::new([]),
    )
    .expect_err("an empty backend must not satisfy non-empty requirements");

    assert_eq!(
        error.missing(),
        &[
            SandboxCapability::DeviceAccess,
            SandboxCapability::Network,
            SandboxCapability::ProcessSpawn,
        ]
    );
}

#[test]
fn duplicate_inputs_are_deduplicated() {
    let error = verify_sandbox_capabilities(
        &RequestedCapabilities::new([
            SandboxCapability::Network,
            SandboxCapability::FilesystemRead,
            SandboxCapability::Network,
            SandboxCapability::FilesystemRead,
        ]),
        &BackendCapabilities::new([SandboxCapability::Network, SandboxCapability::Network]),
    )
    .expect_err("filesystem.read remains missing");

    assert_eq!(error.missing(), &[SandboxCapability::FilesystemRead]);
}

#[test]
fn a_different_class_never_satisfies_the_request() {
    let error = verify_sandbox_capabilities(
        &RequestedCapabilities::new([SandboxCapability::FilesystemRead]),
        &BackendCapabilities::new([SandboxCapability::FilesystemWrite]),
    )
    .expect_err("filesystem.write must not satisfy filesystem.read");

    assert_eq!(error.missing(), &[SandboxCapability::FilesystemRead]);
}

#[test]
fn every_v1_capability_has_its_stable_name() {
    let cases = [
        (SandboxCapability::FilesystemRead, "filesystem.read"),
        (SandboxCapability::FilesystemWrite, "filesystem.write"),
        (SandboxCapability::Network, "network"),
        (SandboxCapability::ProcessSpawn, "process.spawn"),
        (SandboxCapability::MaximumPids, "limit.pids"),
        (SandboxCapability::CpuTime, "limit.cpu_time"),
        (SandboxCapability::WallTime, "limit.wall_time"),
        (SandboxCapability::IdleTime, "limit.idle_time"),
        (SandboxCapability::Memory, "limit.memory"),
        (SandboxCapability::OutputBytes, "limit.output_bytes"),
        (SandboxCapability::OpenFiles, "limit.open_files"),
        (
            SandboxCapability::EnvironmentVariables,
            "environment.variables",
        ),
        (SandboxCapability::SyscallProfile, "syscall.profile"),
        (SandboxCapability::UserGroupIdentity, "identity.user_group"),
        (SandboxCapability::DeviceAccess, "device.access"),
    ];

    for (capability, expected) in cases {
        assert_eq!(capability.as_str(), expected);
    }
}

#[test]
fn error_diagnostics_are_read_only_safe_and_deterministic() {
    let error = verify_sandbox_capabilities(
        &RequestedCapabilities::new([
            SandboxCapability::ProcessSpawn,
            SandboxCapability::DeviceAccess,
            SandboxCapability::Network,
        ]),
        &BackendCapabilities::new([]),
    )
    .expect_err("all requested capabilities are missing");
    let as_error: &dyn Error = &error;

    assert_eq!(
        error.missing(),
        &[
            SandboxCapability::DeviceAccess,
            SandboxCapability::Network,
            SandboxCapability::ProcessSpawn,
        ]
    );
    assert_eq!(
        as_error.to_string(),
        "unsatisfied sandbox capabilities: device.access, network, process.spawn"
    );
    assert!(as_error.source().is_none());
}

#[test]
fn preflight_exposes_only_success_or_typed_failure() {
    let preflight: fn(
        &RequestedCapabilities,
        &BackendCapabilities,
    ) -> Result<(), UnsatisfiedCapabilities> = verify_sandbox_capabilities;

    assert!(preflight(
        &RequestedCapabilities::new([SandboxCapability::Network]),
        &BackendCapabilities::new([]),
    )
    .is_err());
}
