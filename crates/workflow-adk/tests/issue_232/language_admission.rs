//! Production preparation and actual provider entry, using only the existing fake LLM.
use super::{ExecutionConfig, Mode, setup, state};
use serde_json::Value;

const CASES: &str = include_str!("../../../workflow-runtime/tests/issue_231/language_cases.json");

#[tokio::test]
async fn carrier_boundaries_and_unicode_lines_do_not_erase_unknown_material() {
    let mut cases = vec![];
    for raw in [
        "1hex:616263",
        "9hex:616263",
        "١hex:616263",
        "1hex:313233",
        "hex:616263",
        "1 hex:616263",
        "This is\na message",
        "This is\u{2028}a message",
        "This is\u{2029}a message",
    ] {
        cases.push((raw.to_owned(), "unattributed", 0));
    }
    // Standard padded UTF-8 base64 of the LF, line-separator and paragraph-separator controls.
    for encoded in [
        "VGhpcyBpcwphIG1lc3NhZ2U=",
        "VGhpcyBpc+KAqGEgbWVzc2FnZQ==",
        "VGhpcyBpc+KAqWEgbWVzc2FnZQ==",
    ] {
        cases.push((format!("base64:{encoded}"), "unattributed", 0));
    }
    for raw in ["hex:313233", "1 hex:313233", "1/hex:313233"] {
        cases.push((raw.to_owned(), "pending_classification", 3));
    }
    cases.push((
        "This is a message\u{2028}This is the request".to_owned(),
        "pending_classification",
        2,
    ));
    let mut mismatches = vec![];
    for (raw, expected, expected_calls) in cases {
        let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 1);
        graph
            .invoke_observed(
                state(raw.as_bytes()),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        let events = serde_json::to_value(mapper.events()).unwrap();
        let preparation = &events
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "node_completed")
            .unwrap()["payload"]["structured_output"]["preparation"];
        let calls = probe.requests.lock().unwrap().len();
        if preparation["state"] != expected || calls != expected_calls {
            mismatches.push(serde_json::json!({"raw":raw,"state":preparation["state"],"calls":calls,"expected":expected,"expected_calls":expected_calls}));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:?}");
}

#[tokio::test]
async fn unknown_decoded_word_stops_the_original_four_view_carrier_fixture() {
    let raw = format!("`{}` %61%62%63", "0123456789 ".repeat(30));
    let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 1);
    graph
        .invoke_observed(
            state(raw.as_bytes()),
            ExecutionConfig::new("probe-run"),
            &mut mapper,
            &mut store,
        )
        .await
        .unwrap();
    assert!(probe.requests.lock().unwrap().is_empty());
    let events = serde_json::to_value(mapper.events()).unwrap();
    let preparation = &events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "node_completed")
        .unwrap()["payload"]["structured_output"]["preparation"];
    assert_eq!(preparation["state"], "unattributed");
    assert_eq!(super::report(&store, &mapper)["reason"], "language_gate");
}

#[tokio::test]
async fn decoded_material_rejects_before_any_public_semantic_dispatch() {
    let corpus: Value = serde_json::from_str(CASES).unwrap();
    let mut mismatches = vec![];
    for case in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"].as_str().unwrap().starts_with("math_"))
    {
        let (graph, probe, mut store, mut mapper) = setup(Mode::Agree, 1);
        graph
            .invoke_observed(
                state(case["raw"].as_str().unwrap().as_bytes()),
                ExecutionConfig::new("probe-run"),
                &mut mapper,
                &mut store,
            )
            .await
            .unwrap();
        let events = serde_json::to_value(mapper.events()).unwrap();
        let preparation = &events
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "node_completed")
            .unwrap()["payload"]["structured_output"]["preparation"];
        let calls = probe.requests.lock().unwrap().len();
        let expected = match case["id"].as_str().unwrap() {
            "math_supported_control" => "pending_classification",
            "math_decoded_unattributed" | "math_raw_unattributed" => "unattributed",
            _ => "unsupported_language",
        };
        if preparation["state"] != expected
            || (calls == 0) != (expected != "pending_classification")
        {
            mismatches.push(serde_json::json!({"id":case["id"],"expected":expected,"actual":preparation["state"],"calls":calls}));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:?}");
}

#[tokio::test]
async fn frozen_language_ingress_table_covers_every_allowlist_and_transport() {
    let corpus: Value = serde_json::from_str(CASES).unwrap();
    let mut mismatches = vec![];
    let mut count = 0;
    let mut outcomes = vec![];
    for case in corpus["cases"].as_array().unwrap() {
        for transport in case["transports"].as_array().unwrap() {
            let raw = if transport == "plain" {
                &case["raw"]
            } else {
                &case["bare_base64_raw"]
            }
            .as_str()
            .unwrap();
            for mask in 0..8 {
                let workflow = super::WORKFLOW
                    .replace("en = true", &format!("en = {}", mask & 1 != 0))
                    .replace("zh = true", &format!("zh = {}", mask & 2 != 0))
                    .replace("ja = true", &format!("ja = {}", mask & 4 != 0));
                let (graph, probe, mut store, mut mapper) = super::setup_workflow_checked(
                    Mode::Agree,
                    1,
                    super::ModelRuntimeConfig::default(),
                    &workflow,
                );
                graph
                    .unwrap()
                    .invoke_observed(
                        state(raw.as_bytes()),
                        ExecutionConfig::new("probe-run"),
                        &mut mapper,
                        &mut store,
                    )
                    .await
                    .unwrap();
                let events = serde_json::to_value(mapper.events()).unwrap();
                let preparation = &events
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|e| e["kind"] == "node_completed")
                    .unwrap()["payload"]["structured_output"]["preparation"];
                let actual = preparation["state"].as_str().unwrap();
                let calls = probe.requests.lock().unwrap().len();
                let kind = case["oracle"]["kind"].as_str().unwrap();
                let accepted = match kind {
                    "known_language_set" => {
                        let denied = case["oracle"]["languages"].as_array().unwrap().iter().any(
                            |language| match language.as_str().unwrap() {
                                "en" => mask & 1 == 0,
                                "zh" => mask & 2 == 0,
                                "ja" => mask & 4 == 0,
                                _ => true,
                            },
                        );
                        actual
                            == if denied {
                                "unsupported_language"
                            } else {
                                "pending_classification"
                            }
                    }
                    "must_abstain" => actual == "unattributed",
                    "no_natural_language" => preparation["language"] == "no_natural_language",
                    "short_chinese_milestone_residual" => {
                        actual == "unattributed"
                            || actual
                                == if mask & 2 != 0 {
                                    "pending_classification"
                                } else {
                                    "unsupported_language"
                                }
                    }
                    "ambiguous_ground_truth" | "lexical_partition_only" => matches!(
                        actual,
                        "pending_classification" | "unattributed" | "unsupported_language"
                    ),
                    "uncertain_with_known_language" => {
                        actual == "unattributed"
                            || (mask & 1 == 0 && actual == "unsupported_language")
                    }
                    other => panic!("unhandled frozen oracle {other}"),
                };
                let dispatch =
                    !matches!(actual, "unsupported_language" | "unattributed") || calls == 0;
                if !accepted || !dispatch {
                    mismatches.push(serde_json::json!({"id":case["id"],"transport":transport,"mask":mask,"kind":kind,"actual":actual,"language":preparation["language"],"calls":calls}));
                }
                outcomes.push(serde_json::json!({"id":case["id"],"transport":transport,"mask":mask,"state":actual,"language":preparation["language"],"calls":calls}));
                count += 1;
            }
        }
    }
    println!(
        "language_ingress_outcomes {}",
        serde_json::json!({"count":count,"outcomes":outcomes,"mismatches":mismatches})
    );
    assert_eq!(count, 1280);
    assert!(
        mismatches.is_empty(),
        "{} mismatches: {mismatches:?}",
        mismatches.len()
    );
}
