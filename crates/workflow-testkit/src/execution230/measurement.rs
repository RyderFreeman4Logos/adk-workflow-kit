//! Explicit-input measurement through the same production executor as scripted smoke.
//! ponytail: one case per fresh directory; ambiguous admissions are never replayed.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use workflow_adk::model_telemetry::ModelTelemetryV1;
use workflow_runtime::{WorkflowRuntimeEventLogV1, WorkflowRuntimeEventV1};

mod measured;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Origin {
    LocalWireTest,
    LiveProvider,
}

/// Caller-supplied public binding; credential values are never admitted here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema_version: u8,
    origin: Origin,
    workflow_source: String,
    profile: Value,
    input: Value,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u8,
    origin: Origin,
    binding_digest: String,
    manifest: ExecutionManifest,
    case_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    plan_digest: String,
    run_id: String,
}

pub(crate) fn command(args: &[&str]) -> Result<(String, bool), String> {
    let report = match args {
        ["measure-report", output] => verified_report(Path::new(output))?,
        ["measure-compare", left, right] => measured::compare(
            &verified_report(Path::new(left))?,
            &verified_report(Path::new(right))?,
        )?,
        [mode @ ("measure" | "measure-live"), binding, output] => run(
            Path::new(binding),
            Path::new(output),
            *mode == "measure-live",
        )?,
        _ => return Err("invalid measurement command".to_owned()),
    };
    let failed = report["hard_invariant_failed"].as_bool().unwrap_or(true);
    Ok((
        serde_json::to_string_pretty(&report).map_err(error)? + "\n",
        failed,
    ))
}

fn validate(binding: &Binding, live: bool) -> Result<(), String> {
    if binding.schema_version != 1 || live != (binding.origin == Origin::LiveProvider) {
        return Err("measurement origin requires matching explicit command".to_owned());
    }
    for role in ["model", "reviewer_model"] {
        let Some(model) = binding.profile.get(role) else {
            continue;
        };
        if model["provider"] != "openai-compatible" {
            return Err("measurement requires an explicit OpenAI-compatible binding".to_owned());
        }
        let url = model["base_url"]
            .as_str()
            .ok_or("missing public endpoint")?;
        // No host lookup or environment inspection. Offline wire tests admit only this literal form.
        let local = url
            .strip_prefix("http://127.0.0.1:")
            .and_then(|s| s.strip_suffix("/v1"))
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|p| p > 0);
        if !live && !local {
            return Err("local wire test requires a literal loopback endpoint".to_owned());
        }
        // Freeze the actual model name. Do not admit OpenAI extension overrides of model/messages/stream.
        if let Some(extensions) = model.pointer("/runtime/provider_extensions") {
            let extensions = extensions
                .as_object()
                .ok_or("invalid provider extensions")?;
            if extensions.keys().any(|k| k != "openai") {
                return Err("unsupported measurement extension".to_owned());
            }
            if let Some(openai) = extensions.get("openai") {
                let openai = openai.as_object().ok_or("invalid OpenAI extensions")?;
                if openai.keys().any(|k| {
                    !matches!(
                        k.as_str(),
                        "reasoning_effort" | "cache_salt" | "return_token_ids"
                    )
                }) || openai.get("reasoning_effort").is_some_and(|v| {
                    !matches!(
                        v.as_str(),
                        Some("none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max")
                    )
                }) || openai
                    .get("return_token_ids")
                    .is_some_and(|v| !v.is_boolean())
                    || openai.get("cache_salt").is_some_and(|v| {
                        !v.as_str().is_some_and(|s| {
                            !s.is_empty()
                                && s.len() <= 128
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
                        })
                    })
                {
                    return Err("unsupported measurement request override".to_owned());
                }
            }
        }
    }
    Ok(())
}

// A caller designates a public trust domain; the actual wire salt also isolates
// stable configuration, workflow and role. It is not a cache-hit observation.
fn bind_cache_salts(profile: &mut Value, manifest: &ExecutionManifest) -> Result<(), String> {
    let mut configuration = profile.clone();
    for role in ["model", "reviewer_model"] {
        if let Some(options) = configuration
            .get_mut(role)
            .and_then(|model| model.pointer_mut("/runtime/provider_extensions/openai"))
            .and_then(Value::as_object_mut)
        {
            options.remove("cache_salt");
        }
    }
    for role in ["model", "reviewer_model"] {
        if let Some(salt) = profile
            .get_mut(role)
            .and_then(|model| model.pointer_mut("/runtime/provider_extensions/openai/cache_salt"))
        {
            let namespace = salt.as_str().ok_or("invalid public cache domain")?;
            *salt = json!(digest(
                &serde_json::to_vec(&json!({
                    "domain":namespace, "role":role, "configuration":configuration,
                    "workflow_source":manifest.workflow_source,
                    "workflow_digest":manifest.workflow_digest
                }))
                .map_err(error)?
            ));
        }
    }
    Ok(())
}

fn run(path: &Path, output: &Path, live: bool) -> Result<Value, String> {
    // Parse errors are deliberately payload-free; serde can quote unknown secret-bearing keys.
    let bytes = workflow_spec::read_bounded_regular_file(
        &workflow_spec::SourcePath::from(path),
        1024 * 1024,
    )
    .map_err(|_| "cannot read bounded regular measurement binding")?;
    let mut binding: Binding =
        serde_json::from_slice(&bytes).map_err(|_| "invalid measurement binding")?;
    validate(&binding, live)?;
    let profile_bytes = serde_json::to_vec(&binding.profile).map_err(error)?;
    ExecutionProfileV1::parse(&profile_bytes).map_err(|_| "invalid measurement profile")?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (workflow, mut manifest) = manifests(&repo)?
        .into_iter()
        .find(|(w, _)| w.source == binding.workflow_source)
        .ok_or("workflow is not registered")?;
    canonical_admission(&repo, &workflow.source, &binding.input)?;
    bind_cache_salts(&mut binding.profile, &manifest)?;
    bind_inputs(&mut manifest, &binding.profile, &binding.input)?;
    let plan = Plan {
        schema_version: 1,
        origin: binding.origin,
        binding_digest: digest(&bytes),
        manifest: manifest.clone(),
        case_id: workflow.case_id.clone(),
    };
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(error)?;
    let canonical = fs::canonicalize(output).map_err(error)?;
    let _lock = journal::lock(&canonical)?;
    let output = canonical.as_path();
    // Publish the directory entry durably before any admission or provider work.
    fs::File::open(output.parent().ok_or("measurement parent missing")?)
        .and_then(|parent| parent.sync_all())
        .map_err(error)?;
    fs::create_dir(output.join("runs")).map_err(error)?;
    journal::atomic(output, "measurement-plan.json", &plan)?;
    let plan_digest = digest(&serde_json::to_vec(&plan).map_err(error)?);
    let case = execute_bound_case(
        &repo,
        &output.join("runs"),
        &workflow,
        manifest,
        Some((binding.profile, binding.input)),
        true,
        |run_id| {
            journal::atomic(
                output,
                "measurement-admission.json",
                &Admission {
                    plan_digest,
                    run_id: run_id.to_owned(),
                },
            )
            .map_err(std::io::Error::other)
        },
    )?;
    journal::atomic(output, "execution.json", &case)?;
    if source_digest(&repo)? != plan.manifest.source_files_digest
        || git(&repo, &["rev-parse", "HEAD"])? != plan.manifest.source_revision
    {
        return Err("source changed during measurement; retain ambiguous evidence".to_owned());
    }
    let report = build_report(output, &plan, &case)?;
    journal::atomic(output, "measurement.json", &report)?;
    measured::append(output, &case, report)
}

fn verified_report(output: &Path) -> Result<Value, String> {
    let canonical = fs::canonicalize(output).map_err(error)?;
    let _lock = journal::lock(&canonical)?;
    let output = canonical.as_path();
    let plan: Plan = journal::read(&output.join("measurement-plan.json"))?;
    let case: ExecutedCase = journal::read(&output.join("execution.json"))?;
    let expected = build_report(output, &plan, &case)?;
    let recorded: Value = journal::read(&output.join("measurement.json"))?;
    if recorded != expected {
        return Err("measurement projection mismatch".to_owned());
    }
    measured::append(output, &case, expected)
}

fn build_report(output: &Path, plan: &Plan, case: &ExecutedCase) -> Result<Value, String> {
    journal::validate_evidence(case)?;
    if plan.schema_version != 1 || case.manifest != plan.manifest || case.case_id != plan.case_id {
        return Err("measurement identity mismatch".to_owned());
    }
    let mut calls = Vec::new();
    let mut cache = json!(null);
    let mut approval_events = Vec::new();
    if let Some(receipt) = &case.receipt {
        let admission: Admission = journal::read(&output.join("measurement-admission.json"))?;
        if admission.plan_digest != digest(&serde_json::to_vec(plan).map_err(error)?)
            || Some(admission.run_id.as_str()) != case.admitted_run_id.as_deref()
            || receipt.run_id() != admission.run_id
            || receipt.run_root().parent() != Some(output.join("runs").as_path())
            || !journal::durable_receipt_matches(&output.join("runs"), receipt)?
        {
            return Err("measurement admission or durable receipt mismatch".to_owned());
        }
        let bytes = fs::read(receipt.run_root().join("events.jsonl")).map_err(error)?;
        if case.events_digest.as_deref() != Some(digest(&bytes).as_str()) {
            return Err("measurement event digest mismatch".to_owned());
        }
        let events = String::from_utf8(bytes)
            .map_err(error)?
            .lines()
            .map(serde_json::from_str::<WorkflowRuntimeEventV1>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)?;
        let raw_receipt = serde_json::to_value(receipt).map_err(error)?;
        WorkflowRuntimeEventLogV1::resume(
            receipt.run_id(),
            raw_receipt["workflow_id"]
                .as_str()
                .ok_or("missing workflow identity")?,
            events.clone(),
        )
        .map_err(error)?;
        if case.status == ScriptedStatus::Succeeded {
            let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            if plan.manifest.workflow_source == "examples/01-code-investigation/workflow.toml" {
                let input: Value = journal::read(&receipt.run_root().join("execution-input.json"))?;
                if plan.manifest.dataset_digest.as_deref()
                    != Some(digest(&serde_json::to_vec(&input).map_err(error)?).as_str())
                {
                    return Err("measurement input identity mismatch".to_owned());
                }
                canonical_admission(&repo, &plan.manifest.workflow_source, &input)?
                    .ok_or("missing canonical admission")?
                    .validate(receipt.run_root())
                    .map_err(|_| "canonical answer evidence rejected")?;
            }
        }
        cache = raw_receipt["cache_dispositions"].clone();
        for event in events {
            if let Some(telemetry) = event.payload().get("model_telemetry") {
                let parsed: ModelTelemetryV1 = serde_json::from_value(telemetry.clone())
                    .map_err(|_| "invalid runtime model telemetry")?;
                if parsed.schema_version != 1 || parsed.route.provider.as_deref() == Some("fake") {
                    return Err("unmeasured model route".to_owned());
                }
                calls.push(json!({"event_id":event.event_id(),"sequence":event.sequence(),"node_id":event.node_id(),"telemetry":parsed}));
            }
            if matches!(
                event.kind(),
                workflow_runtime::WorkflowRuntimeEventKindV1::ApprovalRequested
                    | workflow_runtime::WorkflowRuntimeEventKindV1::ApprovalResolved
            ) {
                approval_events.push(json!({"event_id":event.event_id(),"kind":event.kind()}));
            }
        }
    } else if case.admitted_run_id.is_some() || case.status == ScriptedStatus::Succeeded {
        return Err("measurement lacks durable receipt".to_owned());
    }
    let failed = case.status != ScriptedStatus::Succeeded || calls.is_empty();
    Ok(json!({
        "schema_version":1,
        "evidence_kind":if plan.origin == Origin::LocalWireTest { "local_wire_execution" } else { "opt_in_provider_execution" },
        "origin_assertion":"caller-declared; client binding is observed, remote model weights are not attested",
        "live_executed":if plan.origin == Origin::LocalWireTest { Some(false) } else { None::<bool> },
        "live_opt_in":plan.origin == Origin::LiveProvider,
        "completed_model_observed":!calls.is_empty(),
        "binding_digest":plan.binding_digest,
        "case":{"case_id":case.case_id,"manifest":case.manifest,"status":case.status,"admitted_run_id":case.admitted_run_id,"elapsed_ns":case.elapsed_ns,"events_digest":case.events_digest,"unsupported_reason":case.unsupported_reason},
        "model_calls":calls,"result_cache":cache,"approval_events":approval_events,
        "hitl":null,"escalation":null,"prefix_hash":null,"hard_invariant_failed":failed,
        "unavailable":{
            "missing_usage":"null means absent or invalid in the provider response; zero is retained only when reported",
            "visible_output_count":"completion count is not a provider-neutral visible-token count; no subtraction inferred",
            "prefill_ns":"ADK response has no prefill clock", "decode_ns":"ADK response has no decode clock",
            "provider_cost_usd":"no provider billing receipt; reported_cost_usd is unavailable because normalized SDK estimates lack raw-response provenance",
            "kv_cache_hit":"cached input token count does not attest KV hit or cold/warm class",
            "prefix_hash":"runtime response does not emit a verified wire-prefix hash",
            "hitl":"approval events are retained, not proof of human intervention",
            "escalation":"runtime has no authoritative escalation observation",
            "reasoning_mode":"only explicit OpenAI request effort is observed; absent means provider/ADK default unknown",
            "model_revision":"route/profile version is not remote weights/tokenizer attestation"
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_domains_are_stable_and_bound_to_configuration_workflow_and_role() {
        let profile = json!({"model":{"model":"one","runtime":{"provider_extensions":{"openai":{"cache_salt":"public-domain","return_token_ids":true}}}},"reviewer_model":{"model":"one","runtime":{"provider_extensions":{"openai":{"cache_salt":"public-domain","return_token_ids":true}}}}});
        let manifest: ExecutionManifest = serde_json::from_value(json!({
            "source_revision":"one", "source_tree":"one", "source_files_digest":"one",
            "executable_digest":"one", "workflow_source":"one/workflow.toml", "workflow_digest":"one",
            "config_digest":null, "dataset_digest":null, "model_digest":null
        })).unwrap();
        let prepare = |mut profile: Value, manifest: &ExecutionManifest| {
            bind_cache_salts(&mut profile, manifest).unwrap();
            profile
        };
        let prepared = prepare(profile.clone(), &manifest);
        assert_eq!(prepared, prepare(profile.clone(), &manifest));
        let salt = |profile: &Value, role| {
            profile[role]["runtime"]["provider_extensions"]["openai"]["cache_salt"].clone()
        };
        assert_ne!(salt(&prepared, "model"), salt(&prepared, "reviewer_model"));
        let mut other = profile.clone();
        other["model"]["runtime"]["provider_extensions"]["openai"]["cache_salt"] =
            json!("other-domain");
        assert_ne!(
            salt(&prepared, "model"),
            salt(&prepare(other, &manifest), "model")
        );
        let mut other = profile.clone();
        other["model"]["model"] = json!("two");
        assert_ne!(
            salt(&prepared, "model"),
            salt(&prepare(other, &manifest), "model")
        );
        let mut other = manifest.clone();
        other.workflow_digest = "two".to_owned();
        assert_ne!(
            salt(&prepared, "model"),
            salt(&prepare(profile, &other), "model")
        );
        let omitted = json!({"model":{"model":"one"}});
        assert_eq!(omitted, prepare(omitted.clone(), &manifest));
    }
}
