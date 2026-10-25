//! Model observation has separate host authority and no executable worker yet.
use super::{
    AdkGraphTranslator, ArtifactId, BEHAVIORAL, ContentObject, ProbeLimits, RAW, TrustPolicy,
    WORKFLOW, WorkflowIr, approval, assert_rejected, compile_spec_with_sentinel_script,
    compile_str, resolved,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use workflow_compiler::compile_spec_with_sentinel_model_probe;
use workflow_runtime::{ContentProvenance, behavioral::TrustedModelProbe};
use workflow_spec::{WorkflowSpec, parse_str};

fn model_text() -> String {
    format!(
        "{WORKFLOW}{}",
        BEHAVIORAL.replace("schema_version = 1", "schema_version = 2")
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn ir_hash(spec: &WorkflowSpec) -> String {
    format!(
        "sha256:{}",
        WorkflowIr::from(spec)
            .canonical_hash()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn source(bytes: &[u8]) -> ArtifactId {
    ArtifactId::parse(format!("{:x}", Sha256::digest(bytes))).unwrap()
}

fn provenance(author: &str, trusted: bool) -> ContentProvenance {
    TrustPolicy::new(
        "offline",
        if trusted {
            vec![author.to_owned()]
        } else {
            vec![]
        },
    )
    .unwrap()
    .classify(ContentObject::Comment {
        object_id: "233",
        author,
    })
    .unwrap()
}

fn authority(spec: &WorkflowSpec, revision: &str, route: &str) -> TrustedModelProbe {
    TrustedModelProbe::authorize(
        &ir_hash(spec),
        source(RAW),
        provenance("untrusted", false),
        revision,
        route,
        ProbeLimits::default(),
    )
    .unwrap()
}

#[test]
fn model_admission_compiles_only_matching_independent_host_authority() {
    let spec = parse_str("model.toml", &model_text()).unwrap();
    let route = digest(b"independently approved route");
    let probe = authority(&spec, "model-revision", &route);
    let plan = compile_spec_with_sentinel_model_probe(&spec, &probe, &route).unwrap();
    assert_eq!(
        plan.sentinel_model_probe_identity(),
        Some(probe.identity().as_str())
    );
    assert_eq!(plan.sentinel_script_identity(), None);
    assert_eq!(plan.ir(), &WorkflowIr::from(&spec));
    assert_eq!(plan.ir().canonical_wire_version(), 12);
    assert!(probe.approves_source(&source(RAW)));
    assert!(!probe.approves_source(&source(b"different source")));
    assert!(probe.matches_approval(&ir_hash(&spec), ProbeLimits::default(), &route));
    assert!(!probe.matches_approval(
        &ir_hash(&spec),
        ProbeLimits::default(),
        &digest(b"other route")
    ));
    assert!(
        compile_spec_with_sentinel_model_probe(&spec, &probe, &digest(b"other route")).is_err()
    );
    assert!(matches!(
        compile_str("without-authority.toml", &model_text()),
        Err(workflow_compiler::CompileError::Binding(
            workflow_compiler::BindingValidationError::InvalidSentinelModelProbe
        ))
    ));
    assert!(format!("{probe:?}").contains(&probe.identity()));
    assert!(!format!("{probe:?}").contains("model-revision"));
}

#[test]
fn model_admission_rejects_policy_changes_and_both_cross_mode_authorities() {
    let text = model_text();
    let spec = parse_str("model.toml", &text).unwrap();
    let route = digest(b"route");
    let probe = authority(&spec, "r", &route);
    for changed in [
        text.replace("max_steps = 8", "max_steps = 9"),
        text.replace("timeout_ms = 100", "timeout_ms = 101"),
        text.replace("schema_version = 2", "schema_version = 3"),
        format!("{text}\n[nodes.untrusted_text.behavioral.trajectory]\nschema_version = 1\n"),
        WORKFLOW.to_owned(),
        format!("{WORKFLOW}{BEHAVIORAL}"),
    ] {
        let changed = parse_str("changed.toml", &changed).unwrap();
        assert!(compile_spec_with_sentinel_model_probe(&changed, &probe, &route).is_err());
        let matching_ir = authority(&changed, "r", &route);
        assert!(compile_spec_with_sentinel_model_probe(&changed, &matching_ir, &route).is_err());
    }
    let script_spec = parse_str("script.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let script = approval(&spec, RAW, "r", json!([]));
    assert!(compile_spec_with_sentinel_script(&spec, &script).is_err());
    let script = approval(&script_spec, RAW, "r", json!([]));
    assert!(compile_spec_with_sentinel_script(&script_spec, &script).is_ok());
    assert_ne!(
        WorkflowIr::from(&spec).canonical_hash(),
        WorkflowIr::from(&script_spec).canonical_hash()
    );
    for field in [
        "model_probe",
        "model_route_digest",
        "authority",
        "sentinel_model_probe_identity",
    ] {
        assert!(parse_str("forged.toml", &format!("{text}{field} = 'forged'\n")).is_err());
    }
}

#[test]
fn model_authority_rejects_invalid_digests_trust_revision_and_limits() {
    let spec = parse_str("model.toml", &model_text()).unwrap();
    let ir = ir_hash(&spec);
    let route = digest(b"route");
    for bad in [
        "".to_owned(),
        "sha256:abc".to_owned(),
        format!("sha256:{}", "A".repeat(64)),
        format!("{} ", route),
    ] {
        assert!(
            TrustedModelProbe::authorize(
                &bad,
                source(RAW),
                provenance("untrusted", false),
                "r",
                &route,
                ProbeLimits::default()
            )
            .is_err()
        );
        assert!(
            TrustedModelProbe::authorize(
                &ir,
                source(RAW),
                provenance("untrusted", false),
                "r",
                &bad,
                ProbeLimits::default()
            )
            .is_err()
        );
    }
    for revision in ["".to_owned(), " \n".to_owned(), "r".repeat(129)] {
        assert!(
            TrustedModelProbe::authorize(
                &ir,
                source(RAW),
                provenance("untrusted", false),
                &revision,
                &route,
                ProbeLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        TrustedModelProbe::authorize(
            &ir,
            source(RAW),
            provenance("trusted", true),
            "r",
            &route,
            ProbeLimits::default()
        )
        .is_err()
    );
    for limits in [
        ProbeLimits {
            max_steps: 0,
            timeout_ms: 100,
        },
        ProbeLimits {
            max_steps: 33,
            timeout_ms: 100,
        },
        ProbeLimits {
            max_steps: 8,
            timeout_ms: 0,
        },
        ProbeLimits {
            max_steps: 8,
            timeout_ms: 1001,
        },
    ] {
        assert!(
            TrustedModelProbe::authorize(
                &ir,
                source(RAW),
                provenance("untrusted", false),
                "r",
                &route,
                limits
            )
            .is_err()
        );
    }
    for limits in [
        ProbeLimits {
            max_steps: 1,
            timeout_ms: 1,
        },
        ProbeLimits {
            max_steps: 32,
            timeout_ms: 1000,
        },
    ] {
        assert!(
            TrustedModelProbe::authorize(
                &ir,
                source(RAW),
                provenance("untrusted", false),
                &"r".repeat(128),
                &route,
                limits
            )
            .is_ok()
        );
    }
}

#[test]
fn model_authority_identity_binds_every_host_approved_input() {
    let spec = parse_str("model.toml", &model_text()).unwrap();
    let ir = ir_hash(&spec);
    let route = digest(b"route");
    let baseline = authority(&spec, "r", &route).identity();
    assert_eq!(baseline, authority(&spec, "r", &route).identity());
    let altered = [
        TrustedModelProbe::authorize(
            &digest(b"other ir"),
            source(RAW),
            provenance("untrusted", false),
            "r",
            &route,
            ProbeLimits::default(),
        ),
        TrustedModelProbe::authorize(
            &ir,
            source(b"other source"),
            provenance("untrusted", false),
            "r",
            &route,
            ProbeLimits::default(),
        ),
        TrustedModelProbe::authorize(
            &ir,
            source(RAW),
            provenance("other author", false),
            "r",
            &route,
            ProbeLimits::default(),
        ),
        TrustedModelProbe::authorize(
            &ir,
            source(RAW),
            provenance("untrusted", false),
            "other revision",
            &route,
            ProbeLimits::default(),
        ),
        TrustedModelProbe::authorize(
            &ir,
            source(RAW),
            provenance("untrusted", false),
            "r",
            &digest(b"other route"),
            ProbeLimits::default(),
        ),
        TrustedModelProbe::authorize(
            &ir,
            source(RAW),
            provenance("untrusted", false),
            "r",
            &route,
            ProbeLimits {
                max_steps: 9,
                timeout_ms: 100,
            },
        ),
    ];
    for probe in altered {
        assert_ne!(baseline, probe.unwrap().identity());
    }
}

#[tokio::test]
async fn model_modes_fail_before_every_translation_backend_without_a_worker() {
    let spec = parse_str("model.toml", &model_text()).unwrap();
    let route = digest(b"route");
    let probe = authority(&spec, "r", &route);
    let plan = compile_spec_with_sentinel_model_probe(&spec, &probe, &route).unwrap();
    let translator = AdkGraphTranslator::new();
    let agents = BTreeMap::new();
    assert_rejected(translator.translate(&plan)).await;
    assert_rejected(translator.translate_with_agents(&plan, &agents)).await;
    assert_rejected(translator.translate_profile(
        &plan,
        &agents,
        Some(b"invalid module"),
        &json!({}),
    ))
    .await;
    assert_rejected(translator.translate_profile_with_checkpointer(
        &plan,
        &agents,
        None,
        &json!({}),
        None,
    ))
    .await;
    let (resolved_plan, ir) = resolved(&model_text());
    assert_rejected(translator.translate_resolved(&resolved_plan, &ir)).await;
    assert_rejected(translator.translate_resolved_with_profile(
        &resolved_plan,
        &ir,
        &agents,
        Some(b"invalid module"),
        &json!({}),
        None,
    ))
    .await;
    let script_spec = parse_str("script.toml", &format!("{WORKFLOW}{BEHAVIORAL}")).unwrap();
    let script = approval(&script_spec, RAW, "r", json!([]));
    assert!(
        AdkGraphTranslator::new()
            .with_sentinel_trusted_script(&plan, script)
            .is_err()
    );
}
