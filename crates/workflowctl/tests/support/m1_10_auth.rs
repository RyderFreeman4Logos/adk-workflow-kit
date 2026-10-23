use super::*;

fn supervised_no_auth_child(
    role: &str,
    child: Result<Output, String>,
    server: &thread::Result<Result<RequestObservation, &'static str>>,
) -> Output {
    match child {
        Ok(child) => child,
        Err(error) => {
            let role = match role {
                "worker" => "worker",
                "reviewer" => "reviewer",
                _ => "unknown",
            };
            // Keep only finite outcomes from the already joined server. Never
            // format a child error, request observation, or thread panic payload.
            let outcome = match server {
                Ok(Ok(_)) => "completed",
                Ok(Err("oracle listener accept timed out")) => "accept-timeout",
                Ok(Err(_)) => "request-failed",
                Err(_) => "thread-panicked",
            };
            let (stage, outcomes) = match error.as_str() {
                "oracle child stdout create failed" => ("stdout-setup", "not-started".to_owned()),
                "oracle child stderr create failed" => ("stderr-setup", "not-started".to_owned()),
                "oracle child spawn failed" => ("spawn", "not-started".to_owned()),
                "oracle child output open failed" => {
                    ("output-open", "reaped-before-readback".to_owned())
                }
                "oracle child output read failed" => {
                    ("output-read", "reaped-before-readback".to_owned())
                }
                "oracle child output exceeded size limit" => {
                    ("output-size-limit", "reaped-before-readback".to_owned())
                }
                _ => error
                    .split_once("; ")
                    .and_then(|(stage, details)| {
                        let stage = match stage {
                            "oracle child timed out" => "timeout",
                            "oracle child wait failed" => "wait",
                            _ => return None,
                        };
                        // The unchanged producer emits at most three cleanup labels
                        // and one readback error per output. Reject other text in full.
                        let outcomes = details
                            .split("; ")
                            .take(6)
                            .map(|detail| match detail {
                                "oracle child kill failed" => Some("kill-failed"),
                                "oracle child reap check failed" => Some("reap-check-failed"),
                                "oracle child reaped after kill" => Some("reaped-after-kill"),
                                "oracle child output open failed" => Some("output-open-failed"),
                                "oracle child output read failed" => Some("output-read-failed"),
                                "oracle child output exceeded size limit" => {
                                    Some("output-size-limit")
                                }
                                _ => None,
                            })
                            .collect::<Option<Vec<_>>>()?;
                        (outcomes.len() <= 5 && outcomes.contains(&"reaped-after-kill"))
                            .then(|| (stage, outcomes.join(",")))
                    })
                    .unwrap_or_else(|| ("unknown", "unknown".to_owned())),
            };
            panic!(
                "bounded production child supervision failed; role={role}; server={outcome}; child_stage={stage}; child_outcomes={outcomes}"
            );
        }
    }
}

#[test]
fn no_auth_supervision_failure_preserves_finite_context_without_payloads() {
    const MARKER: &str = "synthetic-private-failure-payload";
    let child_errors = [
        (
            "oracle child timed out; oracle child reaped after kill".to_owned(),
            "timeout",
            "reaped-after-kill",
        ),
        (
            "oracle child stdout create failed".to_owned(),
            "stdout-setup",
            "not-started",
        ),
        (
            "oracle child output read failed".to_owned(),
            "output-read",
            "reaped-before-readback",
        ),
        (
            "oracle child wait failed; oracle child kill failed; oracle child reap check failed; oracle child reaped after kill; oracle child output open failed; oracle child output exceeded size limit".to_owned(),
            "wait",
            "kill-failed,reap-check-failed,reaped-after-kill,output-open-failed,output-size-limit",
        ),
        (MARKER.to_owned(), "unknown", "unknown"),
        (
            format!("oracle child timed out; oracle child reaped after kill; {MARKER}"),
            "unknown",
            "unknown",
        ),
    ];
    for role in ["worker", "reviewer"] {
        let observations = [
            (
                Ok(Ok(RequestObservation {
                    method: MARKER.to_owned(),
                    path: MARKER.to_owned(),
                    authorization_headers: 0,
                    authorization_canary_occurrences: 0,
                    request_canary_occurrences: 0,
                })),
                "completed",
            ),
            (
                Ok(Err("oracle listener accept timed out")),
                "accept-timeout",
            ),
            (Ok(Err(MARKER)), "request-failed"),
            (
                Err(Box::new(MARKER.to_owned()) as Box<dyn std::any::Any + Send>),
                "thread-panicked",
            ),
        ];
        for (observation, expected) in observations {
            for (error, stage, outcomes) in &child_errors {
                let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    supervised_no_auth_child(role, Err(error.clone()), &observation)
                }))
                .expect_err("child supervision failure must remain a failure");
                let message = failure
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| failure.downcast_ref::<&str>().copied())
                    .expect("finite child supervision diagnostic");
                assert!(message.contains(&format!("role={role}")));
                assert!(message.contains(&format!("server={expected}")));
                assert!(message.contains(&format!("child_stage={stage}")));
                assert!(message.contains(&format!("child_outcomes={outcomes}")));
                assert!(!message.contains(MARKER));
            }
        }
    }
}

#[test]
fn production_no_auth_worker_and_reviewer_omit_authorization() {
    for role in ["worker", "reviewer"] {
        assert_no_auth_role(role);
    }
}

pub(super) fn assert_no_auth_role(role: &str) {
    const ABSENT_HANDLE: &str = "WORKFLOWCTL_NO_AUTH_UNUSED_HANDLE";
    const CANARY: &str = "synthetic-unused-no-auth-token";
    let capture = oracle_phase::Capture::configured(role == "worker");
    let root = temp_root(&format!("no-auth-{role}"));
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let model = json!({
        "provider":"openai-compatible", "name":"no-auth-model", "version":"1",
        "model":"synthetic", "base_url":format!("http://{address}/v1"), "auth":"none"
    });
    let mut profile_value = json!({
        "schema_version":1, "model":model, "sandbox":{"capabilities":[]}
    });
    if role == "reviewer" {
        profile_value["reviewer_model"] = profile_value["model"].clone();
        profile_value["model"] = json!({"provider":"fake", "name":"unused-worker", "version":"1", "model":"fake", "responses":["unused"]});
    }
    let (workflow, profile, runs) = write_fixture(&root, profile_value);
    if role == "reviewer" {
        let source = fs::read_to_string(&workflow).unwrap().replace(
            "model = { role = \"worker\", id = \"unused-worker\", version = \"1\" }",
            "model = { role = \"reviewer\", id = \"no-auth-model\", version = \"1\" }",
        );
        fs::write(&workflow, source).unwrap();
    }
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (spawned_tx, spawned_rx) = mpsc::sync_channel(1);
    let server_phase = capture.as_ref().map(oracle_phase::Capture::server);
    let server = thread::spawn(move || {
        let _scope = oracle_phase::activate(server_phase);
        oracle_phase::mark(62, 0);
        oracle_phase::mark(66, 5000);
        let result = serve_oracle_request_until_child_done(
            listener,
            CANARY,
            done_rx,
            None,
            Instant::now() + ORACLE_TIMEOUT,
            Some(spawned_rx),
        );
        oracle_phase::mark(63, u32::from(result.is_err()));
        result
    });
    let child = run_oracle_operation(
        &root,
        "no-auth",
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
        (ABSENT_HANDLE, None),
        Some(&spawned_tx),
        "no-auth-run",
    );
    signal_oracle_child_done(&done_tx);
    let observation = server.join();
    oracle_phase::mark(
        74,
        match &observation {
            Ok(Ok(_)) => 0,
            Ok(Err(_)) => 1,
            Err(_) => 2,
        },
    );
    oracle_phase::mark(75, u32::from(child.is_err()));
    if let Some(capture) = capture {
        capture.finish(true);
    }
    let child = supervised_no_auth_child(role, child, &observation);
    assert_child_success(&child, "production NoAuth invocation");
    assert_eq!(json_stdout(&child)["status"], "succeeded");
    let observation = observation
        .expect("owned server thread")
        .expect("production request");
    assert_eq!(observation.method, "POST");
    assert_eq!(observation.path, "/v1/chat/completions");
    assert_eq!(observation.authorization_headers, 0);
    assert_eq!(observation.request_canary_occurrences, 0);
    let run_root = sole_run_root(&runs).unwrap();
    let persisted: Value =
        serde_json::from_slice(&fs::read(run_root.join("execution-profile.json")).unwrap())
            .unwrap();
    let field = if role == "worker" {
        "model"
    } else {
        "reviewer_model"
    };
    assert_eq!(persisted[field]["auth"], "none");
    assert!(persisted[field].get("credential_env").is_none());
}
