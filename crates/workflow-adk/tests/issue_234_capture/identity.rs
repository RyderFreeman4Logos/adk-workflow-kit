use super::*;

#[test]
fn capture_policy_and_live_host_approval_are_both_required_at_compile() {
    for trajectory in [None, Some(1), Some(2), Some(3)] {
        for host_enabled in [false, true] {
            let base = format!(
                "{}\n[nodes.untrusted_text.behavioral]\nschema_version=2\nmax_steps=8\ntimeout_ms=1000\n",
                include_str!("../fixtures/sentinel.workflow.toml")
            );
            let text = match trajectory {
                None => base,
                Some(v) => format!(
                    "{base}[nodes.untrusted_text.behavioral.trajectory]\nschema_version={v}\n"
                ),
            };
            let spec = workflow_spec::parse_str("matrix", &text).unwrap();
            let ir = workflow_ir::WorkflowIr::from(&spec);
            let (_, default) =
                approved("sha256:0000000000000000000000000000000000000000000000000000000000000000");
            let provenance = TrustPolicy::new("host-model-probe", ["trusted"])
                .unwrap()
                .classify(ContentObject::Comment {
                    object_id: "233",
                    author: "untrusted",
                })
                .unwrap();
            let digest = if host_enabled {
                snapshot(profile())
                    .probe_reasoning_capture_declaration_digest()
                    .unwrap()
            } else {
                snapshot(profile()).probe_declaration_digest().unwrap()
            };
            let approval = TrustedModelProbe::authorize(
                &format!(
                    "sha256:{}",
                    ir.canonical_hash()
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
                workflow_runtime::ArtifactId::parse(format!("{:x}", Sha256::digest(RAW))).unwrap(),
                provenance,
                "host-owned-revision",
                &digest,
                ProbeLimits {
                    max_steps: 8,
                    timeout_ms: 1000,
                },
            )
            .unwrap();
            let approval = if host_enabled {
                approval.with_reasoning_capture()
            } else {
                approval
            };
            let result = workflow_compiler::compile_spec_with_sentinel_model_probe(
                &spec, &approval, &digest,
            );
            assert_eq!(
                result.is_ok(),
                matches!((trajectory, host_enabled), (None, false) | (Some(2), true))
            );
            assert!(!default.reasoning_capture_enabled());
        }
    }
}

#[test]
fn default_and_v1_identity_goldens_remain_exact() {
    let baseline = snapshot(profile()).probe_declaration_digest().unwrap();
    let (plan, approval) = approved(&baseline);
    let base = format!(
        "{}\n[nodes.untrusted_text.behavioral]\nschema_version=1\nmax_steps=8\ntimeout_ms=1000\n",
        include_str!("../fixtures/sentinel.workflow.toml")
    );
    let offline = workflow_ir::WorkflowIr::from(
        &workflow_spec::parse_str(
            "golden",
            &format!("{base}[nodes.untrusted_text.behavioral.trajectory]\nschema_version=1\n"),
        )
        .unwrap(),
    );
    let none = workflow_ir::WorkflowIr::from(&workflow_spec::parse_str("golden", &base).unwrap());
    assert_eq!(
        baseline,
        "sha256:c8fce20969e1024712add3145c9178791e29e8ce382b5be5a9ad8007671ccfc9"
    );
    assert_eq!(
        approval.identity(),
        "sha256:d2454dbadc3024d1539e366b1a42e4c2944d4e684d46574cfb08aa341c0336eb"
    );
    assert_eq!(
        plan.ir().canonical_hash().as_bytes(),
        &[
            88, 254, 28, 149, 111, 233, 97, 171, 195, 133, 96, 136, 164, 71, 152, 11, 209, 223,
            111, 67, 57, 183, 46, 198, 255, 33, 142, 208, 177, 89, 159, 23
        ]
    );
    assert_eq!(
        none.canonical_hash().as_bytes(),
        &[
            240, 109, 3, 242, 212, 52, 200, 187, 158, 232, 98, 239, 203, 247, 55, 203, 118, 94,
            194, 250, 169, 203, 184, 28, 136, 117, 189, 104, 82, 31, 252, 168
        ]
    );
    assert_eq!(
        offline.canonical_hash().as_bytes(),
        &[
            13, 115, 114, 205, 65, 140, 112, 196, 20, 194, 152, 22, 88, 179, 83, 82, 242, 73, 18,
            208, 182, 214, 205, 22, 32, 228, 210, 123, 175, 220, 86, 21
        ]
    );
    assert_eq!(none.canonical_wire_version(), 12);
    assert_eq!(offline.canonical_wire_version(), 13);
    assert_ne!(
        baseline,
        snapshot(profile())
            .probe_reasoning_capture_declaration_digest()
            .unwrap()
    );
}

#[test]
fn capture_declaration_rejects_unsupported_profile_extensions_and_is_idempotent() {
    for runtime in [
        ModelRuntimeConfig::default().with_tool_parser("parser"),
        ModelRuntimeConfig::default().with_tool_template("template"),
        ModelRuntimeConfig::default()
            .with_provider_extension("openai", json!({"reasoning_effort":"high"})),
    ] {
        assert_eq!(
            snapshot(profile().with_runtime(runtime))
                .probe_reasoning_capture_declaration_digest()
                .unwrap_err()
                .kind(),
            ModelRouteSnapshotErrorKind::InvalidProbeContract
        );
    }
    let digest = snapshot(profile())
        .probe_reasoning_capture_declaration_digest()
        .unwrap();
    let (_, approval) = approval_for_capture(&digest);
    let first = approval.identity();
    assert_eq!(approval.with_reasoning_capture().identity(), first);
}
