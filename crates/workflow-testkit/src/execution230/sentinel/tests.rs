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
                SentinelVerdict::Clean,
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
