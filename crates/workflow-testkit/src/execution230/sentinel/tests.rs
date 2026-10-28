//! Independently labelled public inputs and durable evidence corruption controls.
use super::super::{
    ScriptedStatus, bind_inputs, execute_case_with_inputs, manifests, output_path, scripted_inputs,
};
use super::*;
use workflow_runtime::{
    Completeness, SentinelEvidence, SentinelVerdict, SourceSpan, TypedOutput, TypedPayload,
};

struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(input: Value) -> (Root, ExecutedCase) {
    run_with_verdict(input, SentinelVerdict::Clean)
}

fn run_with_verdict(input: Value, verdict: SentinelVerdict) -> (Root, ExecutedCase) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (workflow, mut manifest) = manifests(&repo)
        .unwrap()
        .into_iter()
        .find(|(workflow, _)| workflow.source == SOURCE)
        .unwrap();
    let (mut profile, _) = scripted_inputs(&repo, SOURCE).unwrap().unwrap();
    let raw: Vec<u8> = input["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect();
    if !raw.is_empty() {
        let id = digest(&raw).trim_start_matches("sha256:").to_owned();
        let reply = TypedOutput::new(
            TypedPayload::Sentinel(SentinelEvidence::new(
                verdict,
                vec![SourceSpan::new(id, 0, raw.len() as u64).unwrap()],
                vec![],
            )),
            Completeness::Complete,
        )
        .unwrap()
        .to_json()
        .unwrap();
        profile["model"]["responses"] = json!([reply, reply]);
    }
    let root = Root(output_path().unwrap());
    fs::create_dir(&root.0).unwrap();
    bind_inputs(&mut manifest, &profile, &input).unwrap();
    let case = execute_case_with_inputs(
        &repo,
        &root.0,
        &workflow,
        manifest,
        Some((profile, input)),
        |_| Ok(()),
    )
    .unwrap();
    let diagnostic = (case.status != ScriptedStatus::Succeeded).then(|| {
        let root = case.receipt.as_ref().unwrap().run_root();
        fs::read_to_string(root.join("events.jsonl")).unwrap().lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|event| event["kind"] == "node_completed")
            .map(|event| {
                let preparation = &event["payload"]["structured_output"]["preparation"];
                json!({"state":preparation["state"],"reason":preparation["reason"],
                    "failed_stage":preparation["failed_stage"],"raw_bytes":raw.len(),"raw_sha256":digest(&raw),
                    "has_probes":preparation.get("probes").is_some(),"has_semantics":preparation.get("semantics").is_some()})
            })
    });
    assert_eq!(
        case.status,
        ScriptedStatus::Succeeded,
        "{:?}; diagnostic={diagnostic:?}",
        case.hard_invariant_failures,
    );
    (root, case)
}

fn executed_reports(case: &ExecutedCase) -> (Value, Value, Value, SourceSpan) {
    let root = case.receipt.as_ref().unwrap().run_root();
    let preparation = fs::read_to_string(root.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["kind"] == "node_completed")
        .unwrap()["payload"]["structured_output"]["preparation"]
        .clone();
    let load = |kind: &str| {
        serde_json::from_slice::<Value>(
            &fs::read(
                root.join("artifacts")
                    .join(preparation[kind]["artifact_id"].as_str().unwrap()),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let input: Value = journal::read(&root.join("execution-input.json")).unwrap();
    let source = SourceSpan::new(
        preparation["original_artifact_id"].as_str().unwrap(),
        0,
        input["bytes"].as_array().unwrap().len() as u64,
    )
    .unwrap();
    let probes = load("probes");
    let semantic = load("semantics");
    (preparation, probes, semantic, source)
}

#[test]
fn executed_agreement_binds_reducer_identity_and_version() {
    for raw in [
        "Please review the attached report and send your comments before tomorrow morning.",
        "Please \u{200b}review the attached report and send your comments before tomorrow morning.",
    ] {
        let (_root, case) = run_with_verdict(
            json!({"schema_version":1,"bytes":raw.as_bytes()}),
            SentinelVerdict::Injection,
        );
        let (preparation, probes, report, source) = executed_reports(&case);
        assert_eq!(report["schema_version"], 5);
        assert_eq!(report["version"], "sentinel-semantic-probes-v5");
        assert_eq!(report["reason"], "agreement");
        assert_eq!(report["decision"]["payload"]["verdict"], "inj");
        assert_eq!(
            report["reduction"]["policy_version"],
            "sentinel-reduction-policy-v1"
        );
        let semantic = parse_semantic(&serde_json::to_vec(&report).unwrap()).unwrap();
        let calls = project_calls(&preparation, Some(&probes), Some(&semantic), Some(&source))
            .unwrap()
            .unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| call["source"] == "protected-semantic-artifact-v5")
        );
        let receipt = case.receipt.as_ref().unwrap();
        assert_eq!(
            validate(
                &case,
                receipt,
                &receipt.run_root().join("checkpoint.sqlite")
            )
            .unwrap()
            .probe_calls
            .unwrap(),
            calls
        );
        assert_eq!(report["decision"]["payload"]["spans"][0]["end"], raw.len());
    }
}

#[test]
fn reduction_metadata_rejects_tampering_and_unexpected_presence() {
    let input = json!({"schema_version":1,"bytes":"Please review the attached report and send your comments before tomorrow morning.".as_bytes()});
    let (_root, case) = run_with_verdict(input.clone(), SentinelVerdict::Injection);
    let (preparation, probes, report, source) = executed_reports(&case);
    let project =
        |value: &Value, prep: &Value, cover: &SourceSpan| -> Result<Option<Vec<Value>>, String> {
            let semantic = parse_semantic(&serde_json::to_vec(value).unwrap())?;
            project_calls(prep, Some(&probes), Some(&semantic), Some(cover))
        };
    assert!(project(&report, &preparation, &source).is_ok());
    for kind in [
        "missing",
        "null",
        "array",
        "unknown",
        "oversized",
        "version",
        "policy",
        "identity",
        "schema4",
        "version4",
        "decision",
        "source",
        "schema_hash",
        "producer",
        "order",
        "finding_field",
        "output_field",
        "missing_finding",
        "missing_decision",
        "missing_observations",
        "conflicting_finding",
        "clean_finding",
        "multiple_spans",
        "oversized_output",
        "artifact",
        "truncated",
        "wire_array",
        "causal_promotion",
    ] {
        let mut changed = report.clone();
        match kind {
            "missing" => {
                changed.as_object_mut().unwrap().remove("reduction");
            }
            "null" => changed["reduction"] = Value::Null,
            "array" => {
                changed["reduction"] = json!([
                    "sentinel-reduction-policy-v1",
                    report["reduction"]["policy_digest"],
                    report["reduction"]["identity"]
                ])
            }
            "unknown" => changed["reduction"]["secret_field_never_echo"] = json!(true),
            "oversized" => changed["reduction"]["identity"] = json!("x".repeat(513)),
            "version" => {
                changed["reduction"]["policy_version"] = json!("sentinel-reduction-policy-v2")
            }
            "policy" => {
                changed["reduction"]["policy_digest"] = json!(format!("sha256:{}", "c".repeat(64)))
            }
            "identity" => {
                changed["reduction"]["identity"] = json!(format!("sha256:{}", "d".repeat(64)))
            }
            "schema4" => changed["schema_version"] = json!(4),
            "version4" => changed["version"] = json!("sentinel-semantic-probes-v4"),
            "decision" => changed["decision"]["payload"]["verdict"] = json!("sus"),
            "source" => {
                changed["findings"][0]["output"]["payload"]["spans"][0]["end"] =
                    json!(source.end() - 1)
            }
            "schema_hash" => {
                for key in ["findings", "observations"] {
                    changed[key][0]["schema_hash"] = json!(format!("sha256:{}", "c".repeat(64)));
                }
            }
            "producer" => {
                for key in ["findings", "observations"] {
                    changed[key][0]["invocation_identity"] = json!("c".repeat(64));
                }
            }
            "order" => {
                for key in ["findings", "observations"] {
                    changed[key].as_array_mut().unwrap().reverse();
                }
            }
            "finding_field" => changed["findings"][0]["unknown"] = json!(true),
            "missing_finding" => {
                changed["findings"].as_array_mut().unwrap().pop();
            }
            "missing_decision" => changed["decision"] = Value::Null,
            "missing_observations" => changed["observations"] = Value::Null,
            "conflicting_finding" => {
                changed["findings"][1]["output"]["payload"]["verdict"] = json!("sus")
            }
            "clean_finding" => {
                changed["findings"][0]["output"]["payload"]["verdict"] = json!("cln")
            }
            "multiple_spans" => {
                changed["findings"][0]["output"]["payload"]["spans"] = json!([
                    report["findings"][0]["output"]["payload"]["spans"][0],
                    report["findings"][0]["output"]["payload"]["spans"][0]
                ])
            }
            "oversized_output" => {
                let span = report["findings"][0]["output"]["payload"]["spans"][0].clone();
                changed["findings"][0]["output"]["payload"]["spans"] = Value::Array(vec![span; 20]);
            }
            "artifact" => {
                changed["findings"][0]["output"]["payload"]["artifacts"] = json!([{"artifact_id":source.artifact_id(),"sha256":format!("sha256:{}", source.artifact_id())}])
            }
            "truncated" => {
                changed["findings"][0]["output"]["completeness"] =
                    json!({"truncated":{"seq":1,"token":"next"}})
            }
            "wire_array" => {
                let wire = &report["findings"][0]["output"];
                changed["findings"][0]["output"] = json!([
                    wire["schema_version"],
                    wire["node"],
                    wire["completeness"],
                    wire["payload"]
                ]);
            }
            "causal_promotion" => changed["causal_attribution"] = json!("established"),
            _ => changed["findings"][0]["output"]["rationale"] = json!("secret_field_never_echo"),
        }
        assert!(project(&changed, &preparation, &source).is_err(), "{kind}");
    }
    let mut changed = preparation.clone();
    changed["cache_key"] = json!(format!("sha256:{}", "e".repeat(64)));
    assert!(project(&report, &changed, &source).is_err());
    let changed_source = SourceSpan::new(source.artifact_id(), 0, source.end() + 1).unwrap();
    assert!(project(&report, &preparation, &changed_source).is_err());
    let bytes = serde_json::to_string(&report).unwrap();
    for duplicate in [
        bytes.replacen(
            "\"policy_version\":",
            "\"policy_version\":\"sentinel-reduction-policy-v1\",\"policy_version\":",
            1,
        ),
        bytes.replacen("\"verdict\":", "\"verdict\":\"inj\",\"verdict\":", 1),
        bytes.replacen("\"end\":", "\"end\":1,\"end\":", 1),
    ] {
        assert!(parse_semantic(duplicate.as_bytes()).is_err());
    }
    let mut accepted_duplicates = Vec::new();
    for role in ["findings", "observations"] {
        let item = serde_json::to_string(&report[role][0]).unwrap();
        for field in ["view", "source"] {
            let marker = format!("\"{field}\":{{");
            let changed = item.replacen(&marker, &format!("{marker}\"start\":1,"), 1);
            assert_ne!(changed, item);
            let duplicate = bytes.replacen(&item, &changed, 1);
            // The genuine start:0 remains last: generic Value equality cannot
            // reject this ambiguity or change the bound producer/receipt.
            assert_eq!(serde_json::from_str::<Value>(&duplicate).unwrap(), report);
            if parse_semantic(duplicate.as_bytes()).is_ok() {
                accepted_duplicates.push(format!("{role}.{field}"));
            }
        }
    }
    assert!(accepted_duplicates.is_empty(), "{accepted_duplicates:?}");
    for role in ["findings", "observations"] {
        for kind in [
            "unknown_view",
            "unknown_source",
            "source_array",
            "missing_candidate",
        ] {
            let mut changed = report.clone();
            let view = &mut changed[role][0]["view"];
            match kind {
                "unknown_view" => view["unknown"] = json!(true),
                "unknown_source" => view["source"]["unknown"] = json!(true),
                "source_array" => {
                    let source = &view["source"];
                    view["source"] = json!([source["artifact_id"], source["start"], source["end"]]);
                }
                _ => {
                    view.as_object_mut().unwrap().remove("candidate");
                }
            }
            assert!(
                project(&changed, &preparation, &source).is_err(),
                "{role}.{kind}"
            );
        }
    }
    let (_clean_root, clean_case) = run(input);
    let (clean_preparation, clean_probes, clean, clean_source) = executed_reports(&clean_case);
    assert!(clean.get("reduction").is_none());
    for reason in ["clean_not_authoritative", "conflict"] {
        let mut changed = clean.clone();
        changed["reason"] = json!(reason);
        changed["reduction"] = report["reduction"].clone();
        let semantic = parse_semantic(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            project_calls(
                &clean_preparation,
                Some(&clean_probes),
                Some(&semantic),
                Some(&clean_source)
            )
            .is_err()
        );
    }
}

#[test]
fn finite_catalog_accepts_exact_preparation_and_abstains_on_unknown_input() {
    for (text, language) in [
        (
            "Please review the attached report and send your comments before tomorrow morning.",
            "en",
        ),
        (
            "请检查这份会议记录，并在明天上午之前告诉我们需要修改的内容。",
            "zh",
        ),
        (
            "請檢查這份會議記錄，並在明天上午之前告訴我們需要修改的內容。",
            "zh",
        ),
        (
            "添付された会議の記録を確認して、明日の午前中までに修正が必要な箇所を教えてください。",
            "ja",
        ),
    ] {
        let (_root, case) = run(json!({"schema_version":1,"bytes":text.as_bytes()}));
        let receipt = case.receipt.as_ref().unwrap();
        let validated = validate(
            &case,
            receipt,
            &receipt.run_root().join("checkpoint.sqlite"),
        )
        .unwrap();
        assert_eq!(validated.quality.unwrap()["passed"], true, "{language}");
        assert_eq!(validated.probe_calls.unwrap().len(), 2);
    }
    for input in [
        json!({"schema_version":1,"bytes":[255]}),
        json!({"schema_version":1,"bytes":[]}),
        json!({"schema_version":1,"bytes":[256]}),
        json!({"schema_version":1,"bytes":"Приветственный русский текст".as_bytes()}),
        json!({"schema_version":1,"bytes":"中文資料".as_bytes()}),
        json!({"schema_version":1,"bytes":"`Приветственный русский текст` https://example.org/русский 🧮 2+2=4".as_bytes()}),
    ] {
        let (_root, case) = run(input);
        let receipt = case.receipt.as_ref().unwrap();
        let validated = validate(
            &case,
            receipt,
            &receipt.run_root().join("checkpoint.sqlite"),
        )
        .unwrap();
        assert_eq!(validated.quality.unwrap()["passed"], true);
        assert!(validated.probe_calls.is_none_or(|calls| calls.is_empty()));
    }
    let (_root, case) = run(
        json!({"schema_version":1,"bytes":"Please read the public document and summarize its contents for the weekly meeting.".as_bytes()}),
    );
    let receipt = case.receipt.as_ref().unwrap();
    assert!(
        validate(
            &case,
            receipt,
            &receipt.run_root().join("checkpoint.sqlite")
        )
        .unwrap()
        .quality
        .is_none()
    );
}

#[test]
fn finite_validator_rejects_generation_language_and_protected_reference_forgery() {
    let (_root, mut case) = run(
        json!({"schema_version":1,"bytes":"Please review the attached report and send your comments before tomorrow morning.".as_bytes()}),
    );
    let root = case.receipt.as_ref().unwrap().run_root().to_path_buf();
    let database = root.join("checkpoint.sqlite");
    let manifest: Value = journal::read(&root.join("run-manifest.json")).unwrap();
    let compatibility =
        serde_json::from_value::<CheckpointManifestV1>(manifest["checkpoint_manifest"].clone())
            .unwrap();
    let id = RunId::new(case.admitted_run_id.clone().unwrap()).unwrap();
    let mut store = SqliteCheckpointStore::open(&database, compatibility).unwrap();
    let checkpoint = store.load_latest(&id).unwrap().unwrap();
    for mismatch in ["sequence", "terminal", "decision", "reference"] {
        let mut state: Value = serde_json::from_slice(checkpoint.state()).unwrap();
        let mut refs = checkpoint.artifact_refs().to_vec();
        match mismatch {
            "terminal" => state["terminal"]["reason"] = json!("unattributed"),
            "decision" => {
                state["terminal"]["decision"] = json!({});
                state["node:prepare"] = state["terminal"].clone();
            }
            "reference" => refs.clear(),
            _ => {}
        }
        let bad = DurableCheckpointV1::new(
            id.clone(),
            checkpoint.node_id(),
            checkpoint.event_sequence() - u64::from(mismatch == "sequence"),
            serde_json::to_vec(&state).unwrap(),
            refs,
        )
        .unwrap();
        store.save_checkpoint(bad).unwrap();
        assert!(
            validate(&case, case.receipt.as_ref().unwrap(), &database).is_err(),
            "{mismatch}"
        );
        store.save_checkpoint(checkpoint.clone()).unwrap();
    }
    drop(store);
    let event_path = root.join("events.jsonl");
    let bytes = fs::read(&event_path).unwrap();
    let original_digest = case.events_digest.clone();
    let rows: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for mismatch in ["language", "length", "reference"] {
        let mut changed = rows.clone();
        let event = changed
            .iter_mut()
            .find(|event| event["kind"] == "node_completed")
            .unwrap();
        let preparation = &mut event["payload"]["structured_output"]["preparation"];
        match mismatch {
            "language" => preparation["language"] = json!({"attributed":"ja"}),
            "length" => preparation["semantics"]["bytes"] = json!(1),
            _ => {
                preparation["semantics"]["artifact_id"] =
                    preparation["probes"]["artifact_id"].clone()
            }
        }
        event["integrity"]["payload_sha256"] =
            json!(digest(&serde_json::to_vec(&event["payload"]).unwrap()));
        let modified = changed
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>();
        fs::write(&event_path, &modified).unwrap();
        case.events_digest = Some(digest(modified.as_bytes()));
        assert!(
            validate(&case, case.receipt.as_ref().unwrap(), &database).is_err(),
            "{mismatch}"
        );
    }
    fs::write(event_path, bytes).unwrap();
    case.events_digest = original_digest;
    assert!(validate(&case, case.receipt.as_ref().unwrap(), &database).is_ok());
}

#[test]
fn finite_refusal_preserves_closed_state_and_reason() {
    let raw = "Please review the attached report and send your comments before tomorrow morning.";
    let (_root, mut case) = run(json!({"schema_version":1,"bytes":raw.as_bytes()}));
    let root = case.receipt.as_ref().unwrap().run_root().to_path_buf();
    let database = root.join("checkpoint.sqlite");
    assert!(validate(&case, case.receipt.as_ref().unwrap(), &database).is_ok());
    let manifest: Value = journal::read(&root.join("run-manifest.json")).unwrap();
    let compatibility =
        serde_json::from_value::<CheckpointManifestV1>(manifest["checkpoint_manifest"].clone())
            .unwrap();
    let id = RunId::new(case.admitted_run_id.clone().unwrap()).unwrap();
    let mut store = SqliteCheckpointStore::open(&database, compatibility).unwrap();
    let checkpoint = store.load_latest(&id).unwrap().unwrap();
    let mut state: Value = serde_json::from_slice(checkpoint.state()).unwrap();
    let original = state["terminal"]["original_artifact_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let decision = TypedOutput::new(
        TypedPayload::Sentinel(SentinelEvidence::new(
            SentinelVerdict::InvalidInput,
            Vec::new(),
            vec![
                workflow_runtime::ArtifactRef::new(&original, format!("sha256:{original}"))
                    .unwrap(),
            ],
        )),
        Completeness::Complete,
    )
    .unwrap();
    let denial = json!({"schema_version":1,"state":"invalid_input",
        "reason":"deadline_exceeded","original_artifact_id":original,
        "decision":serde_json::from_str::<Value>(&decision.to_json().unwrap()).unwrap()});
    workflow_adk::UntrustedTextReport::parse(&serde_json::to_vec(&denial).unwrap()).unwrap();
    state["terminal"] = denial.clone();
    state["node:prepare"] = denial;
    store
        .save_checkpoint(
            DurableCheckpointV1::new(
                id,
                checkpoint.node_id(),
                checkpoint.event_sequence(),
                serde_json::to_vec(&state).unwrap(),
                checkpoint.artifact_refs().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    let event_path = root.join("events.jsonl");
    let original_events = fs::read(&event_path).unwrap();
    let original_digest = case.events_digest.clone();
    let mut rows: Vec<Value> = std::str::from_utf8(&original_events)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let completed = rows
        .iter_mut()
        .find(|event| event["kind"] == "node_completed")
        .unwrap();
    let preparation = completed["payload"]["structured_output"]["preparation"]
        .as_object_mut()
        .unwrap();
    preparation.insert("state".to_owned(), json!("invalid_input"));
    preparation.insert("reason".to_owned(), json!("deadline_exceeded"));
    preparation.remove("probes");
    preparation.remove("semantics");
    completed["integrity"]["payload_sha256"] =
        json!(digest(&serde_json::to_vec(&completed["payload"]).unwrap()));
    let changed = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(&event_path, &changed).unwrap();
    case.events_digest = Some(digest(changed.as_bytes()));
    let refusal = validate(&case, case.receipt.as_ref().unwrap(), &database)
        .err()
        .expect("the exact finite input must reject the closed denial");
    assert_eq!(
        refusal,
        format!(
            "Sentinel finite preparation contract failed: {}",
            json!({"schema_version":1,
                "expected_state":"pending_classification","observed_state":"invalid_input",
                "expected_reason":"pending_classification","observed_reason":"deadline_exceeded",
                "state_mismatch":true,"reason_mismatch":true,"original_mismatch":false})
        )
    );
    assert!(!refusal.contains(raw));
    assert!(!refusal.contains(&original));
    store.save_checkpoint(checkpoint).unwrap();
    fs::write(event_path, original_events).unwrap();
    case.events_digest = original_digest;
    assert!(validate(&case, case.receipt.as_ref().unwrap(), &database).is_ok());
}
