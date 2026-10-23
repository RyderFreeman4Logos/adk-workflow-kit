use super::*;

fn copy_example(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("copied example directory");
    for entry in fs::read_dir(source).expect("example entries") {
        let entry = entry.expect("example entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_example(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy example file");
        }
    }
}

fn run_at(
    example: &Path,
    profile: &Path,
    workdir: &Path,
) -> workflow_testkit::live_conformance::ConformanceReport {
    LiveConformance::opt_in().run_canonical_with_env(
        env!("CARGO_BIN_EXE_workflowctl").as_ref(),
        example,
        profile,
        workdir,
        &[(HANDLE, CANARY)],
        LiveConformance::command_budget(&fs::read(profile).expect("profile"))
            .expect("original command budget"),
    )
}

#[test]
fn host_file_digests_are_checked_before_child_admission() {
    for changed_source in [false, true] {
        let server = serve_script(publish_script(), false);
        let root = temp_root();
        let example = root.0.join("example");
        copy_example(&example_root(), &example);
        if changed_source {
            fs::write(example.join("repo/src/lib.rs"), "changed source").expect("source drift");
        } else {
            let path = example.join("input.example.json");
            let mut input: Value =
                serde_json::from_slice(&fs::read(&path).expect("input")).expect("JSON");
            input["snapshot"]["files"]["src/lib.rs"] = json!(format!("sha256:{}", "0".repeat(64)));
            fs::write(path, input.to_string()).expect("digest drift");
        }
        let workdir = root.0.join("runs");
        fs::create_dir(&workdir).expect("workdir");
        let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
        assert_fail(&run_at(&example, &profile, &workdir), "invalid_snapshot");
        assert_eq!(
            server.request_count(),
            0,
            "host mismatch precedes all child/provider IO"
        );
        assert_eq!(
            fs::read_dir(&workdir).expect("workdir entries").count(),
            1,
            "only the safe conformance report, no run root"
        );
        server.finish();
    }
}

#[test]
fn canonical_snapshot_is_verified_before_provider_admission() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let example = root.0.join("example");
    copy_example(&example_root(), &example);
    let input_path = example.join("input.example.json");
    let mut input: Value =
        serde_json::from_slice(&fs::read(&input_path).expect("input")).expect("input JSON");
    input["snapshot"]["id"] = json!(format!("sha256:{}", "0".repeat(64)));
    fs::write(input_path, input.to_string()).expect("corrupted host fact");
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let profile_value = openai_profile(&server.base_url, json!({}));
    let profile = write_profile(&root.0, &profile_value);
    let report = LiveConformance::opt_in().run_canonical_with_env(
        env!("CARGO_BIN_EXE_workflowctl").as_ref(),
        &example,
        &profile,
        &workdir,
        &[(HANDLE, CANARY)],
        LiveConformance::command_budget(&serde_json::to_vec(&profile_value).expect("profile"))
            .expect("original command budget"),
    );
    assert_fail(&report, "invalid_snapshot");
    assert_eq!(
        server.request_count(),
        0,
        "host admission precedes child/provider"
    );
    server.finish();
}

#[test]
fn published_answer_requires_host_verified_citations() {
    let mut answer = fixture_output(12);
    answer["claims"][0]["evidence"][0]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let mut script = publish_script();
    script[7] = finished(answer);
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_scripted_fail(&report, "invalid_evidence", server, 10);
}

#[test]
fn actual_completed_read_and_retained_draft_are_valid_evidence() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(
        report.disposition(),
        ConformanceDisposition::Pass,
        "{report:?}"
    );
    assert_eq!(server.request_count(), 10);
    server.finish();
}

#[test]
fn retained_answer_rejects_invalid_bindings_and_missing_expected_finding() {
    for case in [
        "snapshot",
        "missing_path",
        "outside_path",
        "range",
        "snippet",
        "claim_binding",
        "empty",
        "unrelated",
    ] {
        let mut answer = fixture_output(12);
        match case {
            "snapshot" => answer["snapshot_id"] = json!(format!("sha256:{}", "0".repeat(64))),
            "missing_path" => answer["claims"][0]["evidence"][0]["path"] = json!("src/missing.rs"),
            "outside_path" => answer["claims"][0]["evidence"][0]["path"] = json!("../src/retry.rs"),
            "range" => answer["claims"][0]["evidence"][0]["end_line"] = json!(99999),
            "snippet" => answer["claims"][0]["evidence"][0]["snippet"] = json!("fabricated source"),
            "claim_binding" => {
                answer["claims"][0]["evidence"][0]["claim_id"] = json!("different-claim")
            }
            "empty" => answer["claims"] = json!([]),
            "unrelated" => answer["claims"][0]["text"] = json!("An unrelated finding."),
            _ => unreachable!("finite test matrix"),
        }
        let mut script = publish_script();
        script[7] = finished(answer);
        let server = serve_script(script, false);
        let root = temp_root();
        let workdir = root.0.join("runs");
        fs::create_dir(&workdir).expect("workdir");
        let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
        let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
        assert_eq!(
            report.disposition(),
            ConformanceDisposition::Fail,
            "{case}: {report:?}"
        );
        assert_scripted_fail(&report, "invalid_evidence", server, 10);
    }
}

#[test]
fn actual_revision_is_selected_instead_of_an_earlier_draft() {
    for invalid_revision in [false, true] {
        let valid = fixture_output(12);
        let mut invalid = valid.clone();
        invalid["claims"][0]["evidence"][0]["snippet"] = json!("fabricated source");
        let mut script = publish_script();
        script[7] = finished(if invalid_revision {
            valid.clone()
        } else {
            invalid.clone()
        });
        script[9] = finished("revise");
        script.extend([
            finished(if invalid_revision { invalid } else { valid }),
            finished("valid"),
            finished("pass"),
        ]);
        let server = serve_script(script, false);
        let root = temp_root();
        let workdir = root.0.join("runs");
        fs::create_dir(&workdir).expect("workdir");
        let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
        let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
        if invalid_revision {
            assert_fail(&report, "invalid_evidence");
        } else {
            assert_eq!(
                report.disposition(),
                ConformanceDisposition::Pass,
                "{report:?}"
            );
        }
        assert_eq!(
            server.request_count(),
            13,
            "original revision request count"
        );
        server.finish();
    }
}

#[test]
fn declared_source_output_cannot_replace_an_actual_completed_read() {
    let mut script = publish_script();
    script.remove(4); // Model declares the usual inspection output without calling the tool.
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_scripted_fail(&report, "invalid_evidence", server, 9);
}

#[test]
fn artifact_backed_completed_read_supports_exact_citations() {
    use workflow_testkit::code_investigation::FixtureRepo;
    let root = temp_root();
    let example = root.0.join("example");
    copy_example(&example_root(), &example);
    let path = example.join("repo/src/retry.rs");
    let source = fs::read_to_string(&path).expect("source") + "\n" + &"// padding\n".repeat(600);
    let lines = source.lines().count();
    fs::write(path, source).expect("large real source");
    let files = ["Cargo.toml", "src/lib.rs", "src/retry.rs"].map(|path| {
        (
            path.to_owned(),
            fs::read_to_string(example.join("repo").join(path)).expect("host source"),
        )
    });
    let snapshot = FixtureRepo::from_files(files).snapshot();
    let input_path = example.join("input.example.json");
    let mut input: Value =
        serde_json::from_slice(&fs::read(&input_path).expect("input")).expect("JSON");
    input["snapshot"]["id"] = json!(snapshot.id());
    for path in ["Cargo.toml", "src/lib.rs", "src/retry.rs"] {
        input["snapshot"]["files"][path] = json!(snapshot.digest_for(path).expect("digest"));
    }
    fs::write(input_path, input.to_string()).expect("current host facts");
    let mut answer = fixture_output(12);
    answer["snapshot_id"] = json!(snapshot.id());
    answer["claims"][0]["evidence"][0]["digest"] =
        json!(snapshot.digest_for("src/retry.rs").expect("digest"));
    let mut script = publish_script();
    let arguments = json!({"path":"src/retry.rs","start_line":1,"end_line":lines}).to_string();
    script[4] = tool_call(
        "read-large",
        "read_source_range",
        &serde_json::to_string(&arguments).expect("encoded arguments"),
    );
    script[7] = finished(answer);
    let server = serve_script(script, false);
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_at(&example, &profile, &workdir);
    assert_eq!(
        report.disposition(),
        ConformanceDisposition::Pass,
        "{report:?}"
    );
    assert_eq!(server.request_count(), 10);
    let run = fs::read_dir(&workdir)
        .expect("workdir")
        .filter_map(Result::ok)
        .find(|entry| entry.path().is_dir())
        .expect("run root")
        .path();
    let events = fs::read_to_string(run.join("events.jsonl")).expect("events");
    assert!(
        events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event"))
            .any(|event| event["kind"] == "tool_completed"
                && event["payload"].get("artifact_reference").is_some()),
        "real completed read crossed the inline threshold"
    );
    server.finish();
}
