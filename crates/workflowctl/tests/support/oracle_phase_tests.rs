use super::*;

const PHASE_TEST: &str = "WORKFLOWCTL_NO_AUTH_PHASE_TEST";

#[test]
fn timeout_retains_child_phases_after_containment_and_fixture_cleanup() {
    let retained = temp_root("phase-retained");
    let sink = retained.join("worker-phases");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "oracle_phase_tests::held_real_cli_fixture",
            "--nocapture",
        ])
        .env(PHASE_TEST, "1")
        .env(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV, "no-auth-run")
        .env(ORACLE_FAILURE_BOUNDARY_SINK_ENV, &sink)
        .output()
        .unwrap();
    let capture = read_fixture_capture(&output, &sink, "forced-control");
    assert_eq!(capture["child_tail"], "UNKNOWN");
    assert_eq!(capture["child_reaped"], true);
    assert_eq!(capture["server_joined"], true);
    assert_eq!(capture["rows_qualified"], true);
    assert_eq!(capture["capture_qualified"], false);
    assert!(
        capture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == 2 && row[1] == 52)
    );
    assert!(
        capture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == 2 && row[1] == 68)
    );
}

#[test]
fn held_real_cli_fixture() {
    if std::env::var_os(PHASE_TEST).is_none() {
        return;
    }
    let capture = oracle_phase::Capture::configured(true);
    let root = temp_root("phase-held-cli");
    let root_path = root.to_path_buf();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (workflow, profile, runs) = write_fixture(
        &root,
        json!({
            "schema_version":1,
            "model":{"provider":"openai-compatible", "name":"phase-worker", "version":"1",
                "model":"synthetic", "base_url":format!("http://{address}/v1"), "auth":"none"},
            "sandbox":{"capabilities":[]}
        }),
    );
    let (spawned_tx, spawned_rx) = mpsc::sync_channel::<OracleChildIdentity>(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let server_phase = capture.as_ref().map(oracle_phase::Capture::server);
    let server = thread::spawn(move || {
        let _scope = oracle_phase::activate(server_phase);
        oracle_phase::mark(62, 0);
        let identity = spawned_rx.recv_timeout(ORACLE_TIMEOUT).unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + ORACLE_TIMEOUT;
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::yield_now()
                }
                result => panic!("owned listener failed: {}", result.is_err()),
            }
        };
        let request = read_model_request(&mut socket, deadline, "synthetic-phase-canary").unwrap();
        assert_eq!(request.authorization_headers, 0);
        assert!(
            matches!(owned_child_stat(identity.pid), OwnedChildStat::Ready { starttime, .. } if starttime == identity.starttime)
        );
        // SAFETY: this is the exact live child identity delivered by our spawn;
        // SIGSTOP holds its real provider await until the original supervisor kills/reaps it.
        assert_eq!(
            unsafe { libc::kill(identity.pid as libc::pid_t, libc::SIGSTOP) },
            0
        );
        let _ = done_rx.recv_timeout(ORACLE_TIMEOUT + ORACLE_CLEANUP_TIMEOUT);
        oracle_phase::mark(63, 0);
    });
    let child = run_oracle_operation(
        &root,
        "phase-held",
        &[
            "--json",
            "run",
            workflow.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--input",
            r#"{"request":"public"}"#,
            "--workdir",
            runs.to_str().unwrap(),
        ],
        ("WORKFLOWCTL_UNUSED_PHASE_CREDENTIAL", None),
        Some(&spawned_tx),
        "no-auth-run",
    );
    signal_oracle_child_done(&done_tx);
    let joined = server.join();
    if let Some(capture) = capture {
        capture.finish(true);
    }
    assert!(joined.is_ok(), "owned server failed after containment");
    assert!(
        child
            .unwrap_err()
            .starts_with("oracle child timed out; oracle child reaped after kill")
    );
    drop(root);
    assert!(
        !root_path.exists(),
        "owned fixture cleanup must run before evidence readback"
    );
}

#[test]
fn enabled_success_retains_worker_only_normal_end() {
    let root = temp_root("phase-success");
    let sink = root.join("sink");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "oracle_phase_tests::normal_real_cli_fixture",
            "--nocapture",
        ])
        .env(PHASE_TEST, "normal")
        .env(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV, "no-auth-run")
        .env(ORACLE_FAILURE_BOUNDARY_SINK_ENV, &sink)
        .output()
        .unwrap();
    let value = read_fixture_capture(&output, &sink, "normal-control");
    assert_eq!(value["child_tail"], "complete");
    assert_eq!(value["capture_qualified"], true);
    assert!(
        value["parent_start"]
            .as_u64()
            .is_some_and(|start| start > 0)
    );
    assert!(value["child_start"].as_u64().is_some_and(|start| start > 0));
    assert_eq!(value["child_reaped"], true);
    assert_eq!(value["server_joined"], true);
    assert_eq!(value["invalid"], 0);
    assert_eq!(value["duplicate"], 0);
    assert_eq!(value["overflow"], 0);
    let rows = value["rows"].as_array().unwrap();
    for stage in [12, 16, 20, 21, 36, 37, 50, 51, 52, 53, 54, 68, 69] {
        assert!(
            rows.iter().any(|r| r[0] == 2 && r[1] == stage),
            "missing numeric stage {stage}"
        );
    }
    let child = value["child_pid"].as_u64().unwrap();
    assert!(rows.iter().filter(|r| r[0] == 2).all(|r| r[2] == child));
}

#[test]
fn dormant_and_rejected_capabilities_preserve_structured_error_bytes() {
    let root = temp_root("phase-error-bytes");
    let run = |label: &str, bad_fd: Option<i32>| {
        let out = root.join(format!("{label}.stdout"));
        let err = root.join(format!("{label}.stderr"));
        let mut command = binary();
        command
            .args(["--json", "--definitely-invalid"])
            .env_remove("WORKFLOWCTL_ORACLE_PHASE_FD")
            .env_remove("WORKFLOWCTL_ORACLE_PHASE_COOKIE");
        if let Some(fd) = bad_fd {
            command
                .env("WORKFLOWCTL_ORACLE_PHASE_FD", fd.to_string())
                .env("WORKFLOWCTL_ORACLE_PHASE_COOKIE", "0");
        }
        let child = command
            .stdout(Stdio::from(fs::File::create(&out).unwrap()))
            .stderr(Stdio::from(fs::File::create(&err).unwrap()))
            .spawn()
            .unwrap();
        wait_bounded_child(
            child,
            &out,
            &err,
            Instant::now() + ORACLE_TIMEOUT,
            "phase-error-control",
        )
        .unwrap()
    };
    let baseline = run("off", None);
    assert_eq!(baseline.status.code(), Some(2));
    let error: Value =
        serde_json::from_slice(&baseline.stderr).expect("one unpolluted structured error");
    assert!(error.is_object());
    for fd in [1, 2] {
        let other = run(&format!("reject-{fd}"), Some(fd));
        assert_eq!(other.status.code(), baseline.status.code());
        assert_eq!(other.stdout, baseline.stdout);
        assert_eq!(other.stderr, baseline.stderr);
    }
    assert!(oracle_phase::Capture::configured(false).is_none());
}

#[test]
fn normal_real_cli_fixture() {
    if std::env::var_os(PHASE_TEST).as_deref() == Some(std::ffi::OsStr::new("normal")) {
        m1_10_auth::assert_no_auth_role("worker");
    }
}

fn read_fixture_capture(output: &Output, sink: &Path, kind: &'static str) -> Value {
    let value: Value = fs::read(sink)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| json!({"capture_unavailable":true}));
    // Explicit opt-in evidence, never a fallback for a refused publication.
    // These two predeclared sidecars cannot claim the real worker sink.
    if std::env::var_os(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV).as_deref()
        == Some(std::ffi::OsStr::new("no-auth-run"))
        && let Some(mut path) = std::env::var_os(ORACLE_FAILURE_BOUNDARY_SINK_ENV)
    {
        path.push(format!(".{kind}"));
        if let Some(file) = oracle_failure_file(&path) {
            let _ = serde_json::to_writer(file, &value);
        }
    }
    let rows = value["rows"].as_array();
    assert!(
        output.status.success(),
        "owned {kind} fixture failed; exit={:?} rows={} invalid={} duplicate={} tail={} first={:?} last={:?}",
        output.status.code(),
        rows.map_or(0, Vec::len),
        value["invalid"],
        value["duplicate"],
        value["child_tail"],
        rows.and_then(|r| r.first()),
        rows.and_then(|r| r.last())
    );
    value
}
