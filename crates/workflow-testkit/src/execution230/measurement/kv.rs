//! Pre-admitted request-order/cache-namespace intent, separate from provider cache observations.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Assignment {
    schema_version: u8,
    schedule: String,
    namespace: String,
    arm: Arm,
    order: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<PathBuf>,
}
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Arm {
    ColdNamespace,
    WarmRepeat,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Role {
    profile: Value,
    request_cache_salt_hash: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    declaration: Assignment,
    identity_digest: String,
    roles: BTreeMap<String, Role>,
    predecessor_run_id: Option<String>,
}

impl Assignment {
    pub(super) fn apply(&self, profile: &mut Value) -> Result<(), String> {
        if self.schema_version != 1
            || self.order > 16
            || !public_label(&self.schedule)
            || !public_label(&self.namespace)
            || match self.arm {
                Arm::ColdNamespace => self.order != 0 || self.predecessor.is_some(),
                Arm::WarmRepeat => self.order == 0 || self.predecessor.is_none(),
            }
        {
            return Err("invalid KV request intent".to_owned());
        }
        for role in ["model", "reviewer_model"] {
            let Some(model) = profile.get_mut(role) else {
                continue;
            };
            let salt = model
                .pointer_mut("/runtime/provider_extensions/openai/cache_salt")
                .ok_or("KV intent requires an explicit public cache trust domain for every role")?;
            let domain = salt
                .as_str()
                .filter(|s| public_label(s))
                .ok_or("invalid KV trust domain")?;
            // Neither arm, run ID nor order enters the stable namespace. The existing
            // salt owner subsequently binds configuration/workflow/role as usual.
            *salt = json!(digest(
                &serde_json::to_vec(&json!({"domain":domain,"namespace":self.namespace}))
                    .map_err(error)?
            ));
        }
        Ok(())
    }
}

fn public_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
}
fn identity(manifest: &ExecutionManifest) -> Result<String, String> {
    digest_value(&serde_json::to_value(manifest).map_err(error)?)
}
fn digest_value(value: &Value) -> Result<String, String> {
    Ok(digest(&serde_json::to_vec(value).map_err(error)?))
}

pub(super) fn prepare(
    declaration: Assignment,
    profile: &Value,
    manifest: &ExecutionManifest,
    origin: Origin,
) -> Result<Intent, String> {
    let mut roles = BTreeMap::new();
    for role in ["model", "reviewer_model"] {
        let Some(model) = profile.get(role) else {
            continue;
        };
        let public = |key| {
            model
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| public_label(s))
        };
        let name = public("name").ok_or("KV profile identity unavailable")?;
        let version = public("version").ok_or("KV profile version unavailable")?;
        let profile = json!({"name":name,"version":version});
        if roles.values().any(|r: &Role| r.profile == profile) {
            return Err("ambiguous KV role identity".to_owned());
        }
        let salt = model
            .pointer("/runtime/provider_extensions/openai/cache_salt")
            .and_then(Value::as_str)
            .ok_or("missing admitted KV salt")?;
        roles.insert(
            role.to_owned(),
            Role {
                profile,
                request_cache_salt_hash: digest(salt.as_bytes()),
            },
        );
    }
    let mut intent = Intent {
        declaration,
        identity_digest: identity(manifest)?,
        roles,
        predecessor_run_id: None,
    };
    if let Some(previous) = predecessor(&intent, origin)? {
        intent.predecessor_run_id = previous["case"]["admitted_run_id"]
            .as_str()
            .map(str::to_owned);
        if intent.predecessor_run_id.is_none() {
            return Err("KV predecessor run unavailable".to_owned());
        }
    }
    Ok(intent)
}

// Validate the decreasing order before taking the previous journal lock. Together
// with the finite order cap this rejects cycles without recursive lock acquisition.
fn predecessor(intent: &Intent, origin: Origin) -> Result<Option<Value>, String> {
    let Some(path) = &intent.declaration.predecessor else {
        return Ok(None);
    };
    let plan: Plan = journal::read(&path.join("measurement-plan.json"))?;
    let prior = plan
        .kv_intent
        .as_ref()
        .ok_or("missing predecessor KV intent")?;
    if intent.declaration.order.checked_sub(1) != Some(prior.declaration.order)
        || intent.declaration.schedule != prior.declaration.schedule
        || intent.declaration.namespace != prior.declaration.namespace
        || intent.identity_digest != prior.identity_digest
        || serde_json::to_value(&intent.roles).map_err(error)?
            != serde_json::to_value(&prior.roles).map_err(error)?
        || origin != plan.origin
    {
        return Err("KV predecessor identity/order mismatch".to_owned());
    }
    let report = verified_report(path)?;
    if report["hard_invariant_failed"] != false || report["case"]["status"] != "succeeded" {
        return Err("KV predecessor is not a verified completed execution".to_owned());
    }
    Ok(Some(report))
}

// Normal and report-only paths share the same actual request checks. Allocation or
// a declaration is not delivery: only durable completed model observations count.
pub(super) fn validate(
    intent: &Intent,
    manifest: &ExecutionManifest,
    origin: Origin,
    calls: &[Value],
    succeeded: bool,
) -> Result<(), String> {
    if intent.identity_digest != identity(manifest)? {
        return Err("KV manifest mismatch".to_owned());
    }
    let previous = predecessor(intent, origin)?;
    if previous
        .as_ref()
        .and_then(|p| p["case"]["admitted_run_id"].as_str())
        != intent.predecessor_run_id.as_deref()
    {
        return Err("KV predecessor run mismatch".to_owned());
    }
    if !succeeded {
        return Ok(());
    }
    let observed = observations(intent, calls)?;
    if let Some(previous) = previous {
        let prior_calls = previous["model_calls"]
            .as_array()
            .ok_or("missing KV predecessor observations")?;
        if observations(intent, prior_calls)? != observed {
            return Err("KV actual host prefix changed across repeat".to_owned());
        }
    }
    Ok(())
}

fn observations(intent: &Intent, calls: &[Value]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut observations: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if calls.is_empty() {
        return Err("missing KV model observation".to_owned());
    }
    for call in calls {
        let telemetry: ModelTelemetryV1 =
            serde_json::from_value(call["telemetry"].clone()).map_err(error)?;
        let profile = serde_json::to_value(&telemetry.route.profile).map_err(error)?;
        let (role, admitted) = intent
            .roles
            .iter()
            .find(|(_, r)| r.profile == profile)
            .ok_or("KV observed role mismatch")?;
        if telemetry.request_cache_salt_hash.as_deref()
            != Some(admitted.request_cache_salt_hash.as_str())
        {
            return Err("KV actual request salt mismatch".to_owned());
        }
        let prefix = telemetry
            .host_prefix_hash
            .ok_or("KV host prefix unavailable")?;
        let node = call["node_id"]
            .as_str()
            .ok_or("KV node identity unavailable")?;
        let key = serde_json::to_string(&(node, role)).map_err(error)?;
        observations.entry(key).or_default().push(prefix);
    }
    // Preserve distinct prefixes but ignore superstep completion order and identical repeats.
    for hashes in observations.values_mut() {
        hashes.sort();
        hashes.dedup();
    }
    Ok(observations)
}
