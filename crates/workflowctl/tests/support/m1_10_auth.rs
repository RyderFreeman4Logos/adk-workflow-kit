use super::*;

#[test]
fn production_no_auth_worker_and_reviewer_omit_authorization() {
    const ABSENT_HANDLE: &str = "WORKFLOWCTL_NO_AUTH_UNUSED_HANDLE";
    const CANARY: &str = "synthetic-unused-no-auth-token";
    for role in ["worker", "reviewer"] {
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
        let server = thread::spawn(move || {
            serve_oracle_request_until_child_done(
                listener,
                CANARY,
                done_rx,
                None,
                Instant::now() + ORACLE_TIMEOUT,
                Some(spawned_rx),
            )
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
        let child = child.expect("bounded production child");
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
}
