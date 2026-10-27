//! Public capture caller; the same test bytes must fail strict collection then pass.
use super::*;
use workflow_adk::behavioral::ReasoningCaptureCompletion;

const REASONING: &str = "private-reasoning-marker-234";

mod admission;
mod collector;
mod identity;
mod lifecycle;
mod live;
mod observer;
mod trajectory;

fn approval_for_capture(declaration: &str) -> (workflow_compiler::CompiledPlan, TrustedModelProbe) {
    let text = format!(
        "{}\n[nodes.untrusted_text.behavioral]\nschema_version=2\nmax_steps=8\ntimeout_ms=1000\n[nodes.untrusted_text.behavioral.trajectory]\nschema_version=2\n",
        include_str!("../fixtures/sentinel.workflow.toml")
    );
    let spec = workflow_spec::parse_str("capture", &text).unwrap();
    let ir = workflow_ir::WorkflowIr::from(&spec);
    let provenance = TrustPolicy::new("host-model-probe", ["trusted"])
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "233",
            author: "untrusted",
        })
        .unwrap();
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
        declaration,
        ProbeLimits {
            max_steps: 8,
            timeout_ms: 1000,
        },
    )
    .unwrap()
    .with_reasoning_capture();
    let plan =
        workflow_compiler::compile_spec_with_sentinel_model_probe(&spec, &approval, declaration)
            .unwrap();
    (plan, approval)
}

#[tokio::test]
async fn public_opt_in_reads_actual_reasoning_only_after_validated_worker() {
    use adk_rust::{Content, LlmResponse, Part};
    let fixture = Fixture::new();
    let mut content = Content::new("assistant");
    content.parts.push(Part::Thinking {
        thinking: REASONING.to_owned(),
        signature: None,
    });
    content.parts.push(Part::Text {
        text: BATCH.to_owned(),
    });
    let llm = Arc::new(Responses {
        responses: vec![LlmResponse::new(content)],
        calls: AtomicUsize::new(0),
    });
    let snapshot = snapshot(profile())
        .with_test_llm(
            ModelRouteCandidate::new(ModelRole::Worker, "probe", "1"),
            llm.clone(),
        )
        .unwrap();
    let digest = snapshot
        .probe_reasoning_capture_declaration_digest()
        .unwrap();
    let (plan, approval) = approval_for_capture(&digest);
    let route = ModelRoutePublisher::new(snapshot).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let mut reads = 0;
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &route,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe_with_reasoning_capture(|reader| {
        assert_eq!(
            reader.status(),
            workflow_runtime::behavioral::trajectory::ReasoningStatus::Present
        );
        assert_eq!(
            reader.read(0, 4096.try_into().unwrap()).unwrap(),
            REASONING.as_bytes()
        );
        reads += 1;
        ReasoningCaptureCompletion::Complete
    })
    .await;
    assert_eq!(llm.calls.load(Ordering::SeqCst), 1);
    assert!(
        result.is_ok(),
        "explicit capture must accept Thinking alongside strict valid Text"
    );
    assert_eq!(result.unwrap().report.event_count(), 1);
    assert_eq!(reads, 1);
}

struct CaptureFixture {
    fixture: Fixture,
    llm: Arc<Responses>,
    plan: workflow_compiler::CompiledPlan,
    approval: TrustedModelProbe,
    route: workflow_adk::ModelRoutePolicy,
    source: workflow_runtime::CanonicalUntrustedText,
    cancel: ModelRouteCancellation,
    broker: CredentialBroker,
}
impl CaptureFixture {
    fn new(responses: Vec<adk_rust::LlmResponse>) -> Self {
        let llm = Arc::new(Responses {
            responses,
            calls: AtomicUsize::new(0),
        });
        let snapshot = snapshot(profile())
            .with_test_llm(
                ModelRouteCandidate::new(ModelRole::Worker, "probe", "1"),
                llm.clone(),
            )
            .unwrap();
        let (plan, approval) = approval_for_capture(
            &snapshot
                .probe_reasoning_capture_declaration_digest()
                .unwrap(),
        );
        Self {
            fixture: Fixture::new(),
            llm,
            plan,
            approval,
            route: ModelRoutePublisher::new(snapshot)
                .policy(Instant::now() + Duration::from_secs(5)),
            source: prepared(RAW, Instant::now()),
            cancel: ModelRouteCancellation::new(),
            broker: CredentialBroker::new(),
        }
    }
    fn host(&self) -> HostModelProbe<'_> {
        HostModelProbe {
            plan: &self.plan,
            approval: &self.approval,
            source: &self.source,
            route: &self.route,
            broker: &self.broker,
            cancellation: &self.cancel,
            worker: worker(),
            workdir: &self.fixture.workdir,
        }
    }
}
fn thinking(text: &str) -> adk_rust::Part {
    adk_rust::Part::Thinking {
        thinking: text.into(),
        signature: Some("signature-never-retained".into()),
    }
}
fn text(text: &str) -> adk_rust::Part {
    adk_rust::Part::Text { text: text.into() }
}
fn response(parts: Vec<adk_rust::Part>) -> adk_rust::LlmResponse {
    adk_rust::LlmResponse::new(adk_rust::Content {
        role: "assistant".into(),
        parts,
    })
}

#[tokio::test]
async fn feedback_rejects_capture_mode_before_credentials_or_model() {
    let mut fixture = CaptureFixture::new(vec![response(vec![thinking(REASONING), text(BATCH)])]);
    (fixture.plan, fixture.approval) = approval_for_capture(
        &fixture
            .route
            .snapshot()
            .probe_feedback_declaration_digest()
            .unwrap(),
    );
    assert!(fixture.host().observe_with_feedback().await.is_err());
    assert_eq!(
        fixture.llm.calls.load(Ordering::SeqCst),
        0,
        "capture policy must not admit the separate feedback entry"
    );
}
