//! Derived measurements join accepted runtime output to a versioned host predicate.
//! External scores/sidecars are never authority. Legacy fixture reports retain their schema.
use super::*;
use workflow_runtime::{
    CheckpointManifestV1, RunId, SqliteCheckpointStore, WorkflowRuntimeEventKindV1 as Kind,
};

const PREDICATE: &str = "sort-7-2-7-1-and-sum-exact-v1";
const REQUEST: &str = "Sort [7,2,7,1] ascending and compute their sum. Return the output object with exactly sorted and sum.";

#[derive(Deserialize)]
struct Manifest {
    run_id: String,
    status: String,
    checkpoint_manifest: CheckpointManifestV1,
}

/// Preserve the original receipt projection; the additional row is recomputed, not recorded input.
pub(super) fn append(output: &Path, case: &ExecutedCase, report: Value) -> Result<Value, String> {
    // Keep the same directory owner as the original admission/receipt.
    if case
        .receipt
        .as_ref()
        .is_some_and(|r| r.run_root().parent() != Some(output.join("runs").as_path()))
    {
        return Err("measured output owner mismatch".to_owned());
    }
    let (quality, security) = if case.status == ScriptedStatus::Succeeded {
        let root = case
            .receipt
            .as_ref()
            .ok_or("missing measured receipt")?
            .run_root();
        selection(root, &root.join("checkpoint.sqlite"), &report)?
    } else {
        (None, None)
    };
    row(case, report, quality, security)
}

fn row(
    case: &ExecutedCase,
    mut report: Value,
    quality: Option<Value>,
    security: Option<Value>,
) -> Result<Value, String> {
    // The recorded base projection stays unchanged. Both execution and report-only
    // callers derive the hard result from this freshly revalidated label.
    if security
        .as_ref()
        .is_some_and(|s| s["catastrophic_count"].as_u64().is_some_and(|n| n > 0))
    {
        report["hard_invariant_failed"] = json!(true);
    }
    let calls = report["model_calls"]
        .as_array()
        .ok_or("missing model observations")?;
    // Never add latest snapshots or mix attempts to invent a single response observation.
    let telemetry = if calls.len() == 1 {
        Some(
            serde_json::from_value::<ModelTelemetryV1>(calls[0]["telemetry"].clone())
                .map_err(error)?,
        )
    } else {
        None
    };
    report["measured"] = json!({
        "schema_version":1, "case_id":case.case_id, "run_id":case.admitted_run_id,
        "evidence_kind":report["evidence_kind"], "origin_assertion":report["origin_assertion"],
        "live_executed":report["live_executed"], "live_opt_in":report["live_opt_in"],
        "binding_digest":report["binding_digest"],
        "manifest":case.manifest, "events_digest":case.events_digest, "quality":quality,
        "model_calls":report["model_calls"], "result_cache":report["result_cache"],
        "elapsed_ns":case.elapsed_ns, "hitl":report["hitl"], "escalation":report["escalation"],
        "prefix_hash":report["prefix_hash"],
        "host_prefix_hash":telemetry.as_ref().and_then(|t|t.host_prefix_hash.as_ref()),
        "cache_write_count":telemetry.as_ref().and_then(|t|t.cache_write_tokens),
        "input_count":telemetry.as_ref().and_then(|t|t.input_tokens),
        "cached_input_count":telemetry.as_ref().and_then(|t|t.cached_input_tokens),
        "reasoning_count":telemetry.as_ref().and_then(|t|t.reasoning_tokens),
        "provider_completion_count":telemetry.as_ref().and_then(|t|t.output_tokens),
        "visible_output_count":telemetry.as_ref().and_then(|t|t.visible_output_tokens),
        "prefill_ns":telemetry.as_ref().and_then(|t|t.prefill_ns),
        "decode_ns":telemetry.as_ref().and_then(|t|t.decode_ns),
        "provider_cost_usd":telemetry.as_ref().and_then(|t|t.provider_cost_usd),
        "sdk_estimated_cost_usd":telemetry.as_ref().and_then(|t|t.sdk_estimated_cost_usd),
        "total_count":telemetry.as_ref().and_then(|t|t.total_tokens),
        "kv_cache_hit":telemetry.as_ref().and_then(|t|t.kv_cache_hit),
        "retries":telemetry.as_ref().map(|t|t.retries),
        "sampling":report.get("sampling").cloned().unwrap_or(Value::Null),
        "security_failures":security.as_ref().and_then(|s|s["catastrophic_count"].as_u64()),
        "security":security,
        "security_failure_confidence_bound":null,
        "unavailable":{
            "quality":"null means no supported host predicate for this exact workflow/input",
            "security_failures":"null means no host security observation; a finite rule count is not an overall safety pass",
            "counts":"null means missing raw count or no single response; individual model_calls remain authoritative",
            "visible_output_count":"provider completion includes reasoning; no subtraction or normalization",
            "confidence":"one run/correlated samples do not establish an independent-trial bound"
        }
    });
    let kv = report.get("kv_intent").cloned().unwrap_or(Value::Null);
    let row = &mut report["measured"];
    row["field_sources"] = field_sources(row);
    row["kv_intent"] = kv;
    Ok(report)
}

// Sources describe observations, never requested capabilities or inferred provider metrics.
fn field_sources(row: &Value) -> Value {
    let mut sources = serde_json::Map::new();
    for (field, source, unit) in [
        ("input_count", "provider_usage.prompt_tokens", "tokens"),
        (
            "cached_input_count",
            "provider_usage.prompt_tokens_details.cached_tokens",
            "tokens",
        ),
        (
            "cache_write_count",
            "provider_usage.prompt_tokens_details.cache_write_tokens",
            "tokens",
        ),
        (
            "reasoning_count",
            "provider_usage.completion_tokens_details.reasoning_tokens",
            "tokens",
        ),
        (
            "provider_completion_count",
            "provider_usage.completion_tokens",
            "tokens_including_reasoning",
        ),
        (
            "host_prefix_hash",
            "host_actual_llm_request.leading_system_tools_schema_model.v1",
            "sha256",
        ),
        ("elapsed_ns", "host_workflow_elapsed", "nanoseconds"),
        ("retries", "host_binding_retry_count", "retries"),
        ("total_count", "provider_usage.total_tokens", "tokens"),
        (
            "sdk_estimated_cost_usd",
            "sdk.UsageMetadata.cost.estimate",
            "USD_estimate_not_billing",
        ),
        ("visible_output_count", "unavailable", "tokens"),
        ("prefill_ns", "unavailable", "nanoseconds"),
        ("decode_ns", "unavailable", "nanoseconds"),
        ("provider_cost_usd", "unavailable_provider_billing", "USD"),
        (
            "kv_cache_hit",
            "unavailable_provider_cache_state",
            "boolean",
        ),
    ] {
        sources.insert(
            field.to_owned(),
            json!({"source":source,"unit":unit,"observed":!row[field].is_null()}),
        );
    }
    Value::Object(sources)
}

/// The public store closes before this derived projection is returned or published.
/// `database` is the run's checkpoint in production; tests may use an explicitly copied DB.
fn selection(
    root: &Path,
    database: &Path,
    report: &Value,
) -> Result<(Option<Value>, Option<Value>), String> {
    let input: Value = journal::read(&root.join("execution-input.json"))?;
    let input_digest = digest(&serde_json::to_vec(&input).map_err(error)?);
    if report["case"]["manifest"]["dataset_digest"] != input_digest {
        return Err("measured input identity mismatch".to_owned());
    }
    if report["case"]["manifest"]["workflow_source"] != "templates/minimal/workflow.toml" {
        return Ok((None, None));
    }
    let manifest: Manifest = journal::read(&root.join("run-manifest.json"))?;
    if manifest.status != "succeeded" || report["case"]["admitted_run_id"] != manifest.run_id {
        return Err("measured run identity mismatch".to_owned());
    }
    let id = RunId::new(manifest.run_id.clone()).map_err(error)?;
    if !database.is_file() {
        return Err("measured checkpoint unavailable".to_owned());
    }
    let checkpoint = {
        let store = SqliteCheckpointStore::open_read_only(database, manifest.checkpoint_manifest)
            .map_err(error)?;
        store
            .load_latest(&id)
            .map_err(error)?
            .ok_or("missing measured checkpoint")?
    };
    let bytes = fs::read(root.join("events.jsonl")).map_err(error)?;
    if report["case"]["events_digest"] != digest(&bytes) {
        return Err("measured event digest mismatch".to_owned());
    }
    let events = std::str::from_utf8(&bytes)
        .map_err(error)?
        .lines()
        .map(serde_json::from_str::<WorkflowRuntimeEventV1>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    WorkflowRuntimeEventLogV1::resume(&manifest.run_id, "minimal-workflow", events.clone())
        .map_err(error)?;
    let terminal = events
        .iter()
        .rev()
        .find(|e| {
            matches!(
                e.kind(),
                Kind::WorkflowCompleted
                    | Kind::WorkflowFailed
                    | Kind::WorkflowCancelled
                    | Kind::WorkflowIncomplete
                    | Kind::WorkflowAbstained
            )
        })
        .ok_or("missing measured terminal")?;
    let completed = |node| {
        events.iter().rev().find(|e| {
            e.node_id() == Some(node)
                && matches!(
                    e.kind(),
                    Kind::NodeStarted | Kind::NodeCompleted | Kind::NodeFailed
                )
        })
    };
    let start = completed("start").ok_or("missing selected model completion")?;
    let done = completed("done").ok_or("missing selected terminal completion")?;
    let state: Value = serde_json::from_slice(checkpoint.state()).map_err(error)?;
    if report["hard_invariant_failed"] != false
        || checkpoint.run_id() != &id
        || checkpoint.event_sequence() != events.last().ok_or("empty measured events")?.sequence()
        || checkpoint.node_id()
            != events
                .iter()
                .rev()
                .find_map(|e| e.node_id())
                .unwrap_or("terminal")
        || terminal.kind() != Kind::WorkflowCompleted
        || start.kind() != Kind::NodeCompleted
        || done.kind() != Kind::NodeCompleted
        || start.sequence() >= done.sequence()
        || done.sequence() >= terminal.sequence()
        || state["terminal"] != "done"
    {
        return Err("measured terminal generation mismatch".to_owned());
    }
    let selected = state
        .get("node:start")
        .ok_or("missing selected measured output")?;
    // This version names a fixed, independently checked host task, not an external score.
    let mut numbers = [7, 2, 7, 1];
    numbers.sort();
    let expected = json!({"sorted":numbers,"sum":numbers.iter().sum::<i32>()});
    let passed = selected == &expected;
    let binding = json!({
        "schema_version":1, "input_digest":input_digest,
        "selected_output_digest":digest(&serde_json::to_vec(selected).map_err(error)?),
        "selected_node":"start", "state_key":"node:start", "run_id":manifest.run_id,
        "checkpoint_sequence":checkpoint.event_sequence(), "checkpoint_node":checkpoint.node_id(),
        "events_digest":digest(&bytes), "execution_manifest":report["case"]["manifest"]
    });
    let quality = (input == json!({"request":REQUEST})).then(|| {
        let mut quality = binding.clone();
        quality["predicate"] = json!(PREDICATE);
        quality["passed"] = json!(passed);
        quality["quality_millis"] = json!(if passed { 1000 } else { 0 });
        quality
    });
    let security = super::sampling::security_label(report, &input, selected, &binding)?;
    Ok((quality, security))
}

/// Pair only the same task/input. Source/config changes are explicit comparison dimensions.
pub(super) fn compare(left: &Value, right: &Value) -> Result<Value, String> {
    let l = &left["measured"];
    let r = &right["measured"];
    if l["case_id"] != r["case_id"]
        || l["run_id"] == r["run_id"]
        || l["manifest"]["workflow_source"] != r["manifest"]["workflow_source"]
        || l["manifest"]["dataset_digest"] != r["manifest"]["dataset_digest"]
        || l["quality"]["predicate"] != r["quality"]["predicate"]
    {
        return Err("measured comparison case/input/predicate mismatch".to_owned());
    }
    let points = [l, r];
    let dimensions = |p: &Value| {
        Some((
            u32::try_from(p["quality"]["quality_millis"].as_u64()?).ok()?,
            p["provider_completion_count"].as_u64()?,
        ))
    };
    let mut frontier = Vec::new();
    let mut excluded = Vec::new();
    for (index, point) in points.iter().enumerate() {
        let Some(value) = dimensions(point) else {
            excluded.push(
                json!({"side":index,"reason":"quality or raw provider completion unavailable"}),
            );
            continue;
        };
        if !points.iter().enumerate().any(|(other, candidate)| {
            other != index
                && dimensions(candidate).is_some_and(|v| crate::harness230::dominates(v, value))
        }) {
            frontier.push(json!({"side":index,"run_id":point["run_id"]}));
        }
    }
    let changes = [
        "source_revision",
        "source_tree",
        "source_files_digest",
        "executable_digest",
        "workflow_digest",
        "config_digest",
        "model_digest",
    ]
    .into_iter()
    .filter(|key| l["manifest"][key] != r["manifest"][key])
    .collect::<Vec<_>>();
    let quality_delta = l["quality"]["quality_millis"]
        .as_i64()
        .zip(r["quality"]["quality_millis"].as_i64())
        .map(|(a, b)| b - a);
    let token_delta = l["provider_completion_count"]
        .as_u64()
        .zip(r["provider_completion_count"].as_u64())
        .map(|(a, b)| (i128::from(b) - i128::from(a)).to_string());
    Ok(json!({
        "schema_version":1,"evidence_kind":"paired_runtime_measurements",
        "rows":[{"case_id":l["case_id"],"left":l,"right":r,
            "quality_millis_delta":quality_delta,"provider_completion_count_delta_decimal":token_delta,
            "security_failures_delta":null,"confidence_interval":null}],
        "allowed_source_config_differences":changes,
        "pareto":{"maximize":"host_predicate_quality_millis","minimize":"provider_completion_count",
            "frontier":frontier,"excluded":excluded},
        "hard_invariant_failed":left["hard_invariant_failed"] != false || right["hard_invariant_failed"] != false,
        "safety_accepted":null,"causal_performance_claim":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_u64_comparison_deltas_remain_exact_without_visible_or_safety_substitution() {
        let point = |run: &str, count| {
            json!({"hard_invariant_failed":false,"measured":{
                "case_id":"same","run_id":run,"manifest":{"workflow_source":"same","dataset_digest":"same"},
                "quality":{"predicate":"same","quality_millis":1000},"provider_completion_count":count
            }})
        };
        let high = point("high", u64::MAX);
        let zero = point("zero", 0);
        let report = compare(&high, &zero).unwrap();
        assert_eq!(
            report["rows"][0]["provider_completion_count_delta_decimal"],
            "-18446744073709551615"
        );
        assert_eq!(
            report["pareto"]["frontier"],
            json!([{"side":1,"run_id":"zero"}])
        );
        assert!(report["safety_accepted"].is_null());
        assert_eq!(
            compare(&zero, &high).unwrap()["rows"][0]["provider_completion_count_delta_decimal"],
            "18446744073709551615"
        );
    }
}
