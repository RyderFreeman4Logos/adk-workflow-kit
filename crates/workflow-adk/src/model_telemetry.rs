//! Bounded, payload-free telemetry attached by the host model binding, never the provider.
use adk_rust::{LlmRequest, LlmResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::model_invocation::ProviderTokenUsage;
use crate::model_profiles::{ModelBinding, ModelProfileIdentity};

/// Client-resolved public aliases, not endpoint or server-weight attestations.
/// Labels must be caller-designated public identities of 1..=256 ASCII bytes from
/// `[A-Za-z0-9_./-]`; unsuitable labels are unavailable. This domain excludes URI
/// userinfo, queries and controls; it cannot detect secrets disguised as valid aliases.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredRouteV1 {
    pub profile: Option<ModelProfileIdentity>,
    pub provider: Option<String>,
    pub requested_model: Option<String>,
    pub resolved_model: Option<String>,
}

pub(crate) const METADATA_KEY: &str = "workflow_kit.model_telemetry_v1";

/// One completed host invocation. Only allowlisted raw provider counters are measured.
/// Output includes reasoning tokens; visible output is never inferred by subtraction.
/// `route` is the resolved client binding, not an attestation of server model weights.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTelemetryV1 {
    pub schema_version: u8,
    pub route: MeasuredRouteV1,
    pub wire_model: Option<String>,
    pub reasoning_mode: Option<String>,
    pub input_tokens: Option<u64>,
    #[serde(rename = "cached_input_count")]
    pub cached_input_tokens: Option<u64>,
    #[serde(rename = "reasoning_count")]
    pub reasoning_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    #[serde(rename = "total_count")]
    pub total_tokens: Option<u64>,
    #[serde(rename = "cache_write_count")]
    pub cache_write_tokens: Option<u64>,
    #[serde(rename = "visible_output_count")]
    pub visible_output_tokens: Option<u64>,
    pub prefill_ns: Option<u64>,
    pub decode_ns: Option<u64>,
    pub provider_cost_usd: Option<f64>,
    pub reported_cost_usd: Option<f64>,
    pub kv_cache_hit: Option<bool>,
    /// Retries performed by this binding (at most its existing one 429 retry).
    pub retries: u64,
}

pub(crate) fn attach(
    binding: &ModelBinding,
    request: &LlmRequest,
    items: &mut [LlmResponse],
    retried: bool,
) -> adk_rust::Result<()> {
    // Only the terminal payload owns invocation telemetry. Strip provider lookalikes first.
    for response in items.iter_mut() {
        if let Some(map) = response
            .provider_metadata
            .as_mut()
            .and_then(Value::as_object_mut)
        {
            map.remove(METADATA_KEY);
        }
    }
    // Whole snapshots replace; absent/invalid trailers neither merge nor erase them.
    let measured = items
        .iter()
        .filter_map(|response| {
            response
                .usage_metadata
                .as_ref()
                .and_then(|metadata| metadata.provider_usage.as_ref())
                .and_then(ProviderTokenUsage::from_provider_usage)
        })
        .next_back();
    let Some(response) = items.last_mut() else {
        return Ok(());
    };
    let extension = request
        .config
        .as_ref()
        .and_then(|c| c.extensions.get("openai"));
    let reasoning_mode = extension
        .and_then(|v| v.get("reasoning_effort"))
        .and_then(Value::as_str)
        .filter(|v| {
            matches!(
                *v,
                "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
            )
        })
        .map(str::to_owned);
    let wire_model = match extension.and_then(|value| value.get("model")) {
        Some(value) => value.as_str().and_then(public_alias),
        None => public_alias(binding.resolved_model_identity()),
    };
    let profile = binding.profile_identity();
    let profile = public_alias(profile.name())
        .zip(public_alias(profile.version()))
        .map(|(name, version)| ModelProfileIdentity::new(name, version));
    let telemetry = ModelTelemetryV1 {
        schema_version: 1,
        route: MeasuredRouteV1 {
            profile,
            provider: public_alias(binding.identity().provider()),
            requested_model: public_alias(binding.requested_model_identity()),
            resolved_model: public_alias(binding.resolved_model_identity()),
        },
        wire_model,
        reasoning_mode,
        input_tokens: measured.as_ref().and_then(ProviderTokenUsage::input_tokens),
        cached_input_tokens: measured
            .as_ref()
            .and_then(ProviderTokenUsage::cache_read_tokens),
        reasoning_tokens: measured
            .as_ref()
            .and_then(ProviderTokenUsage::reasoning_tokens),
        output_tokens: measured
            .as_ref()
            .and_then(ProviderTokenUsage::output_tokens),
        total_tokens: measured.as_ref().and_then(ProviderTokenUsage::total_tokens),
        cache_write_tokens: measured
            .as_ref()
            .and_then(ProviderTokenUsage::cache_write_tokens),
        visible_output_tokens: None,
        prefill_ns: None,
        decode_ns: None,
        provider_cost_usd: None,
        // Normalized SDK cost has no provider-billing provenance here.
        reported_cost_usd: None,
        kv_cache_hit: None,
        retries: u64::from(retried),
    };
    let value = serde_json::to_value(telemetry)
        .map_err(|_| adk_rust::AdkError::model("invalid telemetry"))?;
    let metadata = response.provider_metadata.get_or_insert_with(|| json!({}));
    if !metadata.is_object() {
        *metadata = json!({});
    }
    metadata[METADATA_KEY] = value;
    Ok(())
}

fn public_alias(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte)))
    .then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_profiles::{CredentialBroker, FakeModelProfile, ModelProfileRegistry};
    use adk_rust::{Content, UsageMetadata};

    #[test]
    fn latest_raw_snapshot_replaces_without_merging_and_spoofs_are_removed() {
        let binding = ModelProfileRegistry::new()
            .with_worker(FakeModelProfile::new("worker", "1", "fake-model", ["done"]))
            .expect("valid fixture")
            .bind_worker(&CredentialBroker::new())
            .expect("fake binding");
        let response = |raw| {
            let mut response = LlmResponse::new(Content::new("assistant").with_text("done"));
            response.usage_metadata = Some(UsageMetadata {
                provider_usage: Some(raw),
                cost: Some(0.0),
                ..Default::default()
            });
            response.provider_metadata = Some(json!({METADATA_KEY:{"private":"spoof-canary"}}));
            response
        };
        let mut items = vec![
            response(json!({"prompt_tokens":11,"completion_tokens":13})),
            response(json!({"completion_tokens":0})),
            response(json!({"prompt_tokens":-1})),
            response(Value::Null),
        ];
        attach(
            &binding,
            &LlmRequest::new("fake-model", vec![]),
            &mut items,
            true,
        )
        .expect("host telemetry");
        for item in &items[..3] {
            assert!(
                item.provider_metadata
                    .as_ref()
                    .unwrap()
                    .get(METADATA_KEY)
                    .is_none()
            );
        }
        let encoded = &items.last().unwrap().provider_metadata.as_ref().unwrap()[METADATA_KEY];
        let telemetry: ModelTelemetryV1 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(telemetry.input_tokens, None);
        assert_eq!(telemetry.output_tokens, Some(0));
        assert_eq!(telemetry.total_tokens, None);
        assert_eq!(telemetry.retries, 1);
        assert_eq!(telemetry.reported_cost_usd, None);
        assert!(!encoded.to_string().contains("spoof-canary"));

        // A new invocation cannot inherit any snapshot from the prior attempt.
        let mut next = vec![response(Value::Null)];
        attach(
            &binding,
            &LlmRequest::new("fake-model", vec![]),
            &mut next,
            false,
        )
        .unwrap();
        let telemetry: ModelTelemetryV1 = serde_json::from_value(
            next[0].provider_metadata.as_ref().unwrap()[METADATA_KEY].clone(),
        )
        .unwrap();
        assert_eq!(telemetry.input_tokens, None);
        assert_eq!(telemetry.output_tokens, None);
        assert_eq!(telemetry.retries, 0);
    }
    #[test]
    fn public_alias_domain_and_invalid_wire_override_are_explicit() {
        for valid in ["provider", "profile-v1.0", "org/model_1", &"a".repeat(256)] {
            assert_eq!(public_alias(valid).as_deref(), Some(valid));
        }
        for invalid in [
            "",
            "https://user:private@example.invalid",
            "a?secret=b",
            "a\nb",
            "é",
            &"a".repeat(257),
        ] {
            assert_eq!(public_alias(invalid), None);
        }
        let binding = ModelProfileRegistry::new()
            .with_worker(FakeModelProfile::new("worker", "1", "org/model", ["done"]))
            .unwrap()
            .bind_worker(&CredentialBroker::new())
            .unwrap();
        for override_value in [json!(7), json!(null), json!("model?private=1")] {
            let mut request = LlmRequest::new("org/model", vec![]);
            request
                .config
                .get_or_insert_with(Default::default)
                .extensions
                .insert("openai".into(), json!({"model": override_value}));
            let mut items = [LlmResponse::new(
                Content::new("assistant").with_text("done"),
            )];
            attach(&binding, &request, &mut items, false).unwrap();
            let telemetry: ModelTelemetryV1 = serde_json::from_value(
                items[0].provider_metadata.as_ref().unwrap()[METADATA_KEY].clone(),
            )
            .unwrap();
            assert_eq!(telemetry.wire_model, None);
            assert_eq!(telemetry.route.resolved_model.as_deref(), Some("org/model"));
            assert_eq!(telemetry.route.provider.as_deref(), Some("fake"));
            assert_eq!(telemetry.route.profile.as_ref().unwrap().name(), "worker");
        }
    }
}
