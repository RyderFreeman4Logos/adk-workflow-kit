use super::*;

#[test]
fn failed_real_fixture_retains_exact_capture_after_owned_cleanup() {
    let retained = temp_root("phase-custody-retained");
    for kind in ["normal-control", "forced-control"] {
        let sink = retained.join(kind);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "oracle_phase_tests::custody_tests::capture_assertion_fixture",
                "--nocapture",
            ])
            .env(PHASE_TEST, kind)
            .env(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV, "no-auth-run")
            .env(ORACLE_FAILURE_BOUNDARY_SINK_ENV, &sink);
        // One exclusive group contains both owned fixture levels and the CLI.
        // Cover their original wait, D-state cleanup and receiver-drain bounds,
        // with one original wait budget per level for startup and verification.
        let budget = 2 * (2 * ORACLE_TIMEOUT + ORACLE_D_STATE_TIMEOUT + ORACLE_CLEANUP_TIMEOUT);
        let output = abort_fixture_output(&mut command, &retained, budget).unwrap();
        let missing_outcome = [&output.stdout, &output.stderr].iter().any(|bytes| {
            bytes
                .windows(b"closed inner outcome missing after cleanup".len())
                .any(|part| part == b"closed inner outcome missing after cleanup")
        });
        let verified = [&output.stdout, &output.stderr].iter().any(|bytes| {
            bytes
                .windows(b"diagnostic_custody_verified=true".len())
                .any(|part| part == b"diagnostic_custody_verified=true")
        });
        let lost_bytes = [&output.stdout, &output.stderr].iter().any(|bytes| {
            bytes
                .windows(b"retained capture must preserve exact bytes".len())
                .any(|part| part == b"retained capture must preserve exact bytes")
        });
        assert_eq!(output.status.code(), Some(101));
        assert!(
            verified,
            "diagnostic custody control failed; missing_inner_outcome={missing_outcome}; lost_exact_bytes={lost_bytes}"
        );
        let sidecar = sink.with_extension(kind);
        let value: Value = serde_json::from_slice(&fs::read(sidecar).unwrap()).unwrap();
        assert_eq!(value["inner_outcome"], "child-supervision-completed");
        assert_eq!(value["capture_qualified"], false);
        assert_eq!(value["server_joined"], false);
        assert_eq!(value["child_tail"], "complete");
    }
}

#[test]
fn rejected_custody_preserves_failure_and_existing_destinations() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root("phase-custody-refusals");
    for mode in [
        "opt-out",
        "wrong-operation",
        "symlink",
        "nonprivate-existing",
    ] {
        let sink = root.join(mode);
        let sidecar = sink.with_extension("normal-control");
        let sentinel = root.join(format!("{mode}-sentinel"));
        fs::write(&sentinel, b"owned-sentinel").unwrap();
        if mode == "symlink" {
            std::os::unix::fs::symlink(&sentinel, &sidecar).unwrap();
        } else if mode == "nonprivate-existing" {
            fs::write(&sidecar, b"owned-sentinel").unwrap();
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "oracle_phase_tests::custody_tests::capture_assertion_fixture",
                "--nocapture",
            ])
            .env(PHASE_TEST, "reject-normal-control")
            .env(
                ORACLE_FAILURE_BOUNDARY_OPERATION_ENV,
                if mode == "wrong-operation" {
                    "wrong-operation"
                } else {
                    "no-auth-run"
                },
            );
        if mode == "opt-out" {
            command.env_remove(ORACLE_FAILURE_BOUNDARY_SINK_ENV);
        } else {
            command.env(ORACLE_FAILURE_BOUNDARY_SINK_ENV, &sink);
        }
        let budget = 2 * (2 * ORACLE_TIMEOUT + ORACLE_D_STATE_TIMEOUT + ORACLE_CLEANUP_TIMEOUT);
        let output = abort_fixture_output(&mut command, &root, budget).unwrap();
        assert_eq!(output.status.code(), Some(101));
        assert!(
            output
                .stdout
                .windows(b"diagnostic_custody_rejection_verified=true".len())
                .any(|part| part == b"diagnostic_custody_rejection_verified=true")
        );
        match mode {
            "symlink" => {
                assert!(sidecar.is_symlink());
                assert_eq!(fs::read(&sentinel).unwrap(), b"owned-sentinel");
            }
            "nonprivate-existing" => {
                assert_eq!(fs::read(&sidecar).unwrap(), b"owned-sentinel");
                assert_eq!(
                    fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
                    0o644
                );
            }
            _ => assert!(!sidecar.exists()),
        }
    }
}

#[test]
fn capture_assertion_fixture() {
    let kind = match std::env::var_os(PHASE_TEST).as_deref() {
        Some(value) if value == std::ffi::OsStr::new("normal-control") => "normal-control",
        Some(value) if value == std::ffi::OsStr::new("forced-control") => "forced-control",
        Some(value) if value == std::ffi::OsStr::new("reject-normal-control") => "normal-control",
        _ => return,
    };
    let root = temp_root("phase-custody-original");
    let root_path = root.to_path_buf();
    let sink = root.join("capture");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "oracle_phase_tests::custody_tests::failed_real_cli_fixture",
            "--nocapture",
        ])
        .env(PHASE_TEST, "fail-after-capture")
        .env(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV, "no-auth-run")
        .env(ORACLE_FAILURE_BOUNDARY_SINK_ENV, &sink)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(101));
    // Valid JSON whitespace is part of the producer bytes, not a new record.
    fs::OpenOptions::new()
        .append(true)
        .open(&sink)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let expected = fs::read(&sink).unwrap();
    let failed_assertion = std::panic::catch_unwind(|| read_fixture_capture(&output, &sink, kind));
    let failed_assertion = failed_assertion.expect_err("fixture failure must remain a failure");
    root.cleanup().unwrap();
    drop(root);
    assert!(!root_path.exists(), "original capture must be cleaned up");
    if std::env::var_os(PHASE_TEST).as_deref()
        == Some(std::ffi::OsStr::new("reject-normal-control"))
    {
        println!("diagnostic_custody_rejection_verified=true");
        std::panic::resume_unwind(failed_assertion);
    }
    let mut retained = std::env::var_os(ORACLE_FAILURE_BOUNDARY_SINK_ENV).unwrap();
    retained.push(format!(".{kind}"));
    let actual = fs::read(retained).unwrap();
    assert_eq!(
        actual, expected,
        "retained capture must preserve exact bytes"
    );
    let value: Value = serde_json::from_slice(&actual).unwrap();
    let rows = value["rows"].as_array().unwrap();
    assert!(rows.len() > 2, "interior records must survive cleanup");
    assert!(
        rows.iter().any(|row| row[0] == 2 && row[1] == 52),
        "real CLI child entry missing"
    );
    assert_eq!(
        value["inner_outcome"], "child-supervision-completed",
        "closed inner outcome missing after cleanup"
    );
    assert_eq!(value["invalid"], 0);
    assert_eq!(value["duplicate"], 0);
    assert_eq!(value["overflow"], 0);
    // This control has no HTTP server. Its diagnostic custody can pass while
    // the unchanged capture qualification and actual fixture failure stay false.
    assert_eq!(value["capture_qualified"], false);
    assert_eq!(value["server_joined"], false);
    println!("diagnostic_custody_verified=true");
    std::panic::resume_unwind(failed_assertion);
}

#[test]
fn failed_real_cli_fixture() {
    if std::env::var_os(PHASE_TEST).as_deref() != Some(std::ffi::OsStr::new("fail-after-capture")) {
        return;
    }
    let capture = oracle_phase::Capture::configured(true).unwrap();
    let root = temp_root("phase-custody-cli");
    let (spawned_tx, _spawned_rx) = mpsc::sync_channel(1);
    let child = run_oracle_operation(
        &root,
        "phase-custody-invalid-cli",
        &["--json", "--definitely-invalid"],
        ("WORKFLOWCTL_UNUSED_PHASE_CREDENTIAL", None),
        Some(&spawned_tx),
        "no-auth-run",
    );
    oracle_phase::mark(75, u32::from(child.is_err()));
    capture.finish(false);
    root.cleanup().unwrap();
    let child = child.expect("real CLI must finish supervision");
    assert_eq!(child.status.code(), Some(2));
    // Exercise the existing real-output assertion after Capture publication.
    // The integration fixture must still exit101; custody never changes it.
    assert_child_success(&child, "deliberate real CLI failure after phase capture");
}
