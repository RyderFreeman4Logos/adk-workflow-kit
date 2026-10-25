//! Public host declaration and single-batch model observation contracts.
use std::time::Duration;
use workflow_adk::model_profiles::{CredentialHandle, OpenAiCompatibleProfile};
use workflow_adk::{
    ModelProfileRegistry, ModelRole, ModelRouteAuthorization, ModelRouteCandidate,
    ModelRouteSnapshot, ModelRouteSnapshotErrorKind, ModelRuntimeConfig,
};

fn snapshot(profile: OpenAiCompatibleProfile) -> ModelRouteSnapshot {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "probe", "1");
    ModelRouteSnapshot::new(
        ModelProfileRegistry::new().with_worker(profile).unwrap(),
        [candidate.clone()],
        ModelRouteAuthorization::new([candidate]),
    )
    .unwrap()
}

fn profile() -> OpenAiCompatibleProfile {
    OpenAiCompatibleProfile::new_no_auth("probe", "1", "model", "http://127.0.0.1:9/v1")
}

#[test]
fn declaration_binds_complete_selected_profile_without_io() {
    let baseline = snapshot(profile()).probe_declaration_digest().unwrap();
    assert!(baseline.starts_with("sha256:"));
    assert_eq!(baseline.len(), 71);
    assert_eq!(
        baseline,
        snapshot(profile()).probe_declaration_digest().unwrap()
    );
    for changed in [
        OpenAiCompatibleProfile::new_no_auth("probe", "1", "model", "http://127.0.0.1:10/v1"),
        OpenAiCompatibleProfile::new_no_auth("probe", "1", "other-model", "http://127.0.0.1:9/v1"),
        profile().with_provider("another-provider"),
        profile().with_tokenizer("another-tokenizer"),
        profile().with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_secs(2))),
        profile()
            .with_runtime(ModelRuntimeConfig::default().with_sampling(|s| s.with_temperature(0.1))),
        OpenAiCompatibleProfile::new(
            "probe",
            "1",
            "model",
            "http://127.0.0.1:9/v1",
            CredentialHandle::secret_provider("opaque-a"),
        ),
        OpenAiCompatibleProfile::new(
            "probe",
            "1",
            "model",
            "http://127.0.0.1:9/v1",
            CredentialHandle::secret_provider("opaque-b"),
        ),
    ] {
        assert_ne!(
            baseline,
            snapshot(changed).probe_declaration_digest().unwrap()
        );
    }
    let credential_digest = |handle| {
        snapshot(OpenAiCompatibleProfile::new(
            "probe",
            "1",
            "model",
            "http://127.0.0.1:9/v1",
            CredentialHandle::secret_provider(handle),
        ))
        .probe_declaration_digest()
        .unwrap()
    };
    assert_ne!(credential_digest("opaque-a"), credential_digest("opaque-b"));
}

#[test]
fn declaration_rejects_original_extensions_parser_template_and_multiple_candidates() {
    for runtime in [
        ModelRuntimeConfig::default()
            .with_provider_extension("openai", serde_json::json!({"reasoning_effort":"high"})),
        ModelRuntimeConfig::default().with_tool_parser("parser"),
        ModelRuntimeConfig::default().with_tool_template("template"),
    ] {
        assert_eq!(
            snapshot(profile().with_runtime(runtime))
                .probe_declaration_digest()
                .unwrap_err()
                .kind(),
            ModelRouteSnapshotErrorKind::InvalidProbeContract,
        );
    }
    let mut registry = ModelProfileRegistry::new().with_worker(profile()).unwrap();
    registry
        .register(OpenAiCompatibleProfile::new_no_auth(
            "other",
            "1",
            "model",
            "http://127.0.0.1:9/v1",
        ))
        .unwrap();
    let candidates = [
        ModelRouteCandidate::new(ModelRole::Worker, "probe", "1"),
        ModelRouteCandidate::new(ModelRole::Worker, "other", "1"),
    ];
    let snapshot = ModelRouteSnapshot::new(
        registry,
        candidates.clone(),
        ModelRouteAuthorization::new(candidates),
    )
    .unwrap();
    assert_eq!(
        snapshot.probe_declaration_digest().unwrap_err().kind(),
        ModelRouteSnapshotErrorKind::InvalidProbeContract
    );
}
