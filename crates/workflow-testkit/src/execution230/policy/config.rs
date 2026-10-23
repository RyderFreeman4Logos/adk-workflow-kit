//! Explicit campaign-only loop budgets; no provider, input, tool or trust overrides.
use super::*;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    schema_version: u32,
    loop_policy: Value,
}

impl Config {
    pub(super) fn apply(&self, profile: &mut Value) -> Result<(), String> {
        if self.schema_version != 1 || !self.loop_policy.is_object() {
            return Err("invalid comparison config version or loop policy".to_owned());
        }
        profile
            .as_object_mut()
            .ok_or("invalid scripted profile")?
            .insert("loop_policy".to_owned(), self.loop_policy.clone());
        // The existing executor owns budget schema and range validation.
        ExecutionProfileV1::parse(&serde_json::to_vec(profile).map_err(error)?).map_err(error)?;
        Ok(())
    }
}

pub(super) fn registry(repo: &Path, config: Option<&Config>) -> Result<Vec<CaseIdentity>, String> {
    let mut registry = journal::registry(repo)?;
    if let Some(config) = config {
        for case in &mut registry {
            if let Some((mut profile, input)) = scripted_inputs(repo, &case.workflow.source)? {
                config.apply(&mut profile)?;
                bind_inputs(&mut case.manifest, &profile, &input)?;
            }
        }
    }
    Ok(registry)
}

pub(in crate::execution230) fn inputs(
    repo: &Path,
    source: &str,
    identity: Option<&RunIdentity>,
) -> Result<Option<(Value, Value)>, String> {
    let mut inputs = scripted_inputs(repo, source)?;
    if let Some(identity) = identity {
        let campaign: Campaign = read(&identity.campaign.join("campaign.json"))?;
        if let (Some(config), Some((profile, _))) = (&campaign.config, &mut inputs) {
            config.apply(profile)?;
        }
    }
    Ok(inputs)
}
