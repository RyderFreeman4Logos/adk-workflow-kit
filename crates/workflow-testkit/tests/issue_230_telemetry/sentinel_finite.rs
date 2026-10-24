//! One fixed four-language table; ordinary tests terminate at owned loopback HTTP.
use super::{Value, fs, json, success, wire_scenario};
use sha2::{Digest, Sha256};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

const SOURCE: &str = "examples/03-sentinel-preparation/workflow.toml";
const BINDING: &str = "WORKFLOW_KIT_SENTINEL_FINITE_BINDING";
const OUTPUT: &str = "WORKFLOW_KIT_SENTINEL_FINITE_OUTPUT";
const LANGUAGES: [(&str, &str, &str, &str); 4] = [
    (
        "en_note",
        "Please review the attached report and send your comments before tomorrow morning.",
        "7251652ee00dc7d5171f18b95e8453366d3fd95b2e024fe6f43bce2c07b50507",
        "en",
    ),
    (
        "zh_hans_note",
        "请检查这份会议记录，并在明天上午之前告诉我们需要修改的内容。",
        "589b4a064d2571dea84ee58fc416c86cabbbd204d731ddd3173229425db576df",
        "zh",
    ),
    (
        "zh_hant_note",
        "請檢查這份會議記錄，並在明天上午之前告訴我們需要修改的內容。",
        "42e55aeab660ea85f682be14be878589d0f8a92cc35443dec89b75f9eeb304de",
        "zh",
    ),
    (
        "ja_note",
        "添付された会議の記録を確認して、明日の午前中までに修正が必要な箇所を教えてください。",
        "631751b1aad74ecf4d6686204b0196739806ba5a3b0fa4dbd10188c02d4b3779",
        "ja",
    ),
];

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn retain(directory: &Path, name: &str, value: &Value) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

fn explicit_binding() -> Option<Value> {
    std::env::var_os(BINDING).map(|path| {
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(value["origin"], "live_provider");
        assert_eq!(value["workflow_source"], SOURCE);
        validate_model(&value["profile"]["model"]);
        value
    })
}

fn validate_model(model: &Value) {
    assert_eq!(model["provider"], "openai-compatible");
    assert_eq!(model["name"], "sentinel-worker");
    assert_eq!(model["version"], "1");
    assert_eq!(
        model["runtime"],
        json!({"timeout_ms":30000,
        "sampling":{"max_output_tokens":128},
        "provider_extensions":{"openai":{"reasoning_effort":"low","return_token_ids":true}}})
    );
    assert!(model.get("tokenizer").is_none());
}

// A live admission substitutes only endpoint/auth at the owned HTTP boundary.
// Model name and runtime are identical to the explicitly supplied public profile.
fn configure_loopback(path: &Path, admitted: Option<&Value>) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let endpoint = value["profile"]["model"]["base_url"].clone();
    if let Some(admitted) = admitted {
        value["profile"] = admitted["profile"].clone();
    }
    value["profile"]["model"]["base_url"] = endpoint;
    value["profile"]["model"]["credential_env"] = json!("BENCH230_WIRE_TEST_KEY");
    value["profile"]["model"]["runtime"] = json!({"timeout_ms":30000,
        "sampling":{"max_output_tokens":128},
        "provider_extensions":{"openai":{"reasoning_effort":"low","return_token_ids":true}}});
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn frame<'a>(text: &'a str, tag: &str) -> &'a str {
    let (_, tail) = text.split_once(&format!("{tag}_BYTES:")).unwrap();
    let (length, tail) = tail.split_once('\n').unwrap();
    tail.get(..length.parse::<usize>().unwrap()).unwrap()
}

fn check_requests(request: &Value, model: &str) -> Value {
    let count = 2;
    let requests = request["wire_requests"].as_array().unwrap();
    assert_eq!(requests.len(), count);
    assert_eq!(request["wire_request_count"], count);
    let mut largest = 0;
    let mut source_prefix = None;
    let mut branches = std::collections::BTreeSet::new();
    for request in requests {
        let bytes = request["wire_body_bytes"].as_u64().unwrap();
        assert!((1..=16_384).contains(&bytes));
        largest = largest.max(bytes);
        assert_eq!(request["model"], model);
        assert_eq!(request["max_completion_tokens"], 128);
        assert_eq!(request["reasoning_effort"], "low");
        assert_eq!(request["return_token_ids"], true);
        assert!(
            request
                .get("tools")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
        );
        let messages = request["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "user");
        let system = messages[0]["content"].as_str().unwrap();
        let user = messages[1]["content"].as_str().unwrap();
        let suffix = frame(user, "TASK_SUFFIX");
        let common = frame(user, "COMMON_DATA_JSON");
        let schema: Value = serde_json::from_str(frame(system, "OUTPUT_SCHEMA_JSON")).unwrap();
        let branch = suffix.split_once('/').unwrap().1.split(';').next().unwrap();
        branches.insert(branch.to_owned());
        assert!(!system.contains("AUTHENTICATED_GOAL_BYTES:"));
        assert_eq!(schema["$id"], "urn:sentinel-semantic-probes-v4:source");
        let prefix = format!(
            "{system}\n{}",
            user.split_once("TASK_SUFFIX_BYTES:").unwrap().0
        );
        assert!(!common.is_empty());
        if let Some(previous) = source_prefix.replace(prefix.clone()) {
            assert_eq!(prefix, previous, "same-view source prefixes diverged");
        }
    }
    assert_eq!(
        branches,
        ["ordered".to_owned(), "shuffled".to_owned()]
            .into_iter()
            .collect()
    );
    json!({"accepted_http_requests":count,"largest_request_body_bytes":largest,
        "request_body_cap":16384,"goal_isolated":true})
}

fn retain_admission(table: &str, rows: &[Value], admitted: Option<&Value>) {
    if let Some(directory) = std::env::var_os(OUTPUT) {
        let directory = Path::new(&directory);
        if !directory.exists() {
            fs::create_dir(directory).unwrap();
        }
        retain(
            directory,
            &format!("{table}-http-admission.json"),
            &json!({
            "table":table,"binding_sha256":admitted.map(|v|digest(&serde_json::to_vec(v).unwrap())),
            "loopback_only":true,"rows":rows}),
        );
    }
}

fn language_quality(report: &Value, raw: &str) -> bool {
    let quality = &report["measured"]["quality"];
    report["hard_invariant_failed"] == false
        && report["completed_model_observed"] == true
        && report["model_calls"] == json!([])
        && quality["predicate"] == "sentinel-preparation-contract-v1"
        && quality["passed"] == true
        && quality["input_digest"]
            == format!(
                "sha256:{}",
                digest(
                    &serde_json::to_vec(&json!({"schema_version":1,"bytes":raw.as_bytes()}))
                        .unwrap()
                )
            )
        && report["sentinel_probe_calls"]
            .as_array()
            .is_some_and(|calls| {
                calls.len() == 2
                    && calls[0]["branch"] == "ordered"
                    && calls[1]["branch"] == "shuffled"
            })
}

#[test]
fn sentinel_language_http_contract() {
    let admitted = explicit_binding();
    let mut rows = Vec::new();
    for (name, raw, sha, language) in LANGUAGES {
        assert_eq!(digest(raw.as_bytes()), sha);
        let (root, output, request) = wire_scenario(
            None,
            false,
            json!({}),
            (
                SOURCE,
                "sentinel-worker",
                json!({"schema_version":1,"bytes":raw.as_bytes()}),
                Value::Null,
            ),
            2,
            |binding, output| {
                configure_loopback(binding, admitted.as_ref());
                super::cli(&[
                    "measure",
                    binding.to_str().unwrap(),
                    output.to_str().unwrap(),
                ])
            },
        );
        let report = success(output);
        assert!(
            language_quality(&report, raw),
            "{name}: finite language contract"
        );
        let model = admitted
            .as_ref()
            .and_then(|v| v["profile"]["model"]["model"].as_str())
            .unwrap_or("wire-fixture-model");
        let evidence = check_requests(&request.unwrap(), model);
        rows.push(json!({"case":name,"raw_sha256":sha,"expected_language":language,"output":root.join("run"),"wire":evidence}));
    }
    retain_admission("231-language", &rows, admitted.as_ref());
}
