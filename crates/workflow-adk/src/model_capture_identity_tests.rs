use super::*;

#[test]
fn capture_declaration_binds_fixed_protocol_and_aggregate_cap_only_when_enabled() {
    let candidate = ModelRouteCandidate::new(crate::ModelRole::Worker, "probe", "1");
    let snapshot = ModelRouteSnapshot::new(
        ModelProfileRegistry::new()
            .with_worker(crate::model_profiles::OpenAiCompatibleProfile::new_no_auth(
                "probe",
                "1",
                "model",
                "http://127.0.0.1:9/v1",
            ))
            .unwrap(),
        [candidate.clone()],
        ModelRouteAuthorization::new([candidate]),
    )
    .unwrap();
    let ordinary = snapshot.probe_declaration_digest().unwrap();
    let enabled = snapshot
        .probe_reasoning_capture_declaration_digest()
        .unwrap();
    assert_ne!(ordinary, enabled);
    assert_eq!(
        enabled,
        snapshot
            .probe_reasoning_capture_declaration_digest()
            .unwrap()
    );
    for (field, value) in [
        ("protocol", serde_json::json!("other-protocol")),
        ("max_reasoning_bytes", serde_json::json!(16385)),
        ("max_page_bytes", serde_json::json!(4097)),
    ] {
        let mut contract = crate::behavioral::reasoning_capture::declaration_contract();
        contract["reasoning_capture"][field] = value;
        assert_ne!(enabled, snapshot.probe_declaration_for(contract).unwrap().1);
        assert_eq!(ordinary, snapshot.probe_declaration_digest().unwrap());
    }
}
