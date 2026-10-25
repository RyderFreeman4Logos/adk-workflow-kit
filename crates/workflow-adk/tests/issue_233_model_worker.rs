//! Public host declaration and single-batch model observation contracts.
#![cfg(feature = "test-support")]
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

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use workflow_adk::{
    CredentialBroker, ModelRouteCancellation, ModelRoutePublisher, behavioral::HostModelProbe,
};
use workflow_runtime::{
    ContentObject, InMemoryArtifactStore, Materialization, NormalizationLimits, RunId, RunWorkdir,
    SentinelPreparation, TrustPolicy, WorkdirManager,
    behavioral::worker::SealedProbeWorker,
    behavioral::{ProbeLimits, TrustedModelProbe},
    prepare_untrusted_text,
};

const RAW: &[u8] = b"Untrusted text with instructions to ignore.";
const BATCH: &str =
    r#"{"schema_version":1,"steps":[{"kind":"call","tool":"complete","arguments":{}}]}"#;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    base: PathBuf,
    workdir: RunWorkdir,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "host-model-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let workdir = WorkdirManager::new(&base)
            .unwrap()
            .materialize(
                &RunId::new("host-model-probe".to_owned()).unwrap(),
                &Materialization::default(),
            )
            .unwrap();
        Self { base, workdir }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.base).unwrap();
    }
}

fn worker() -> SealedProbeWorker {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let bytes = fs::read(root.join("target/debug/sentinel-probe-worker")).unwrap();
    let stamp = fs::read_to_string(root.join("target/debug/sentinel-probe-worker.sha256")).unwrap();
    let mut fields = stamp.split_whitespace();
    let expected = format!("sha256:{}", fields.next().unwrap());
    assert_eq!(fields.next(), Some("target/debug/sentinel-probe-worker"));
    assert_eq!(fields.next(), None);
    SealedProbeWorker::authorize(&bytes, &expected).unwrap()
}

struct Wire {
    endpoint: String,
    count: Arc<AtomicUsize>,
    task: JoinHandle<Value>,
    release: Option<oneshot::Sender<()>>,
    admitted: Option<oneshot::Receiver<()>>,
}

#[derive(Clone, Copy, Debug)]
enum Framing {
    Length,
    Chunked,
    ChunkedWithoutEof,
    EventStream,
    HeldBody,
    TruncatedLength,
    Redirect,
}

fn completion(text: &str, finish: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"id":"fixture","object":"chat.completion","created":0,"model":"model","choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":finish}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}})).unwrap()
}

impl Wire {
    async fn new(text: &str) -> Self {
        Self::response(completion(text, "stop"), 200, Framing::Length).await
    }

    async fn response(body: Vec<u8>, status: u16, framing: Framing) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
        let redirect_location = format!("{endpoint}/redirected");
        let count = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&count);
        let (release, released) = oneshot::channel();
        let (admit, admitted) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            let mut request = Vec::new();
            let (header_end, length) = timeout(Duration::from_secs(3), async {
                loop {
                    let mut chunk = [0; 4096];
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert!(n > 0 && request.len() + n <= 524288);
                    request.extend_from_slice(&chunk[..n]);
                    if let Some(end) = request.windows(4).position(|x| x == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break (end + 4, length);
                        }
                    }
                }
            })
            .await
            .unwrap();
            let value: Value =
                serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
            admit.send(()).unwrap();
            let mut released = Some(released);
            if matches!(framing, Framing::HeldBody) {
                let _ = released.take().unwrap().await;
            }
            let framing_header = match framing {
                Framing::Length | Framing::EventStream | Framing::HeldBody | Framing::Redirect => {
                    format!("Content-Length: {}", body.len())
                }
                Framing::TruncatedLength => format!("Content-Length: {}", body.len() + 1),
                _ => "Transfer-Encoding: chunked".to_owned(),
            };
            let content_type = if matches!(framing, Framing::EventStream) {
                "text/event-stream"
            } else {
                "application/json"
            };
            let location = if matches!(framing, Framing::Redirect) {
                format!("Location: {redirect_location}\r\n")
            } else {
                String::new()
            };
            // Only the held-response timeout control may close the client before
            // this write; other controls retain the original complete-header check.
            let sent = socket.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\n{framing_header}\r\n{location}Connection: close\r\n\r\n").as_bytes()).await;
            if !matches!(framing, Framing::HeldBody) {
                sent.unwrap();
            }
            // A known-length overflow may be rejected before the peer reads a body.
            // The asserted host outcome distinguishes this from a truncated fixture.
            if matches!(
                framing,
                Framing::Length
                    | Framing::EventStream
                    | Framing::HeldBody
                    | Framing::TruncatedLength
                    | Framing::Redirect
            ) {
                let _ = socket.write_all(&body).await;
            } else {
                let _ = socket
                    .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                    .await;
                let _ = socket.write_all(&body).await;
                let _ = socket.write_all(b"\r\n").await;
                if matches!(framing, Framing::Chunked) {
                    let _ = socket.write_all(b"0\r\n\r\n").await;
                }
            }
            if matches!(framing, Framing::ChunkedWithoutEof) {
                // Only the caller may release EOF, after the host has returned.
                let _ = released.take().unwrap().await;
            }
            let _ = socket.shutdown().await;
            if let Ok(extra) = timeout(Duration::from_millis(150), listener.accept()).await {
                let (mut socket, _) = extra.unwrap();
                let mut header = [0; 4096];
                let bytes = timeout(Duration::from_secs(1), socket.read(&mut header))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(bytes > 0, "an unexpected connection must contain a request");
                calls.fetch_add(1, Ordering::SeqCst);
                panic!(
                    "no retry, fallback or redirect request: actual physical requests={}",
                    calls.load(Ordering::SeqCst)
                );
            }
            value
        });
        Self {
            endpoint,
            count,
            task,
            release: Some(release),
            admitted: Some(admitted),
        }
    }
    async fn finish(mut self) -> Value {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let request = timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.count.load(Ordering::SeqCst), 1);
        request
    }

    async fn unused(mut self) {
        assert!(
            timeout(Duration::from_millis(150), &mut self.task)
                .await
                .is_err()
        );
        assert_eq!(self.count.load(Ordering::SeqCst), 0);
        self.task.abort();
        assert!((&mut self.task).await.as_mut().unwrap_err().is_cancelled());
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn wire_profile(endpoint: &str) -> OpenAiCompatibleProfile {
    OpenAiCompatibleProfile::new_no_auth("probe", "1", "model", endpoint)
}

fn prepared(bytes: &[u8], started: Instant) -> workflow_runtime::CanonicalUntrustedText {
    let mut store =
        InMemoryArtifactStore::new(100000.try_into().unwrap(), 100000.try_into().unwrap());
    let SentinelPreparation::Prepared(source) =
        prepare_untrusted_text(&mut store, bytes, NormalizationLimits::default(), started).unwrap()
    else {
        panic!("prepared")
    };
    source
}

fn approved(declaration: &str) -> (workflow_compiler::CompiledPlan, TrustedModelProbe) {
    let spec = workflow_spec::parse_str("host-model.toml", &format!("{}\n[nodes.untrusted_text.behavioral]\nschema_version = 2\nmax_steps = 8\ntimeout_ms = 1000\n", include_str!("fixtures/sentinel.workflow.toml"))).unwrap();
    let ir = workflow_ir::WorkflowIr::from(&spec);
    let hash = ir.canonical_hash();
    let ir_hash = format!(
        "sha256:{}",
        hash.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let provenance = TrustPolicy::new("host-model-probe", ["trusted"])
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "233",
            author: "untrusted",
        })
        .unwrap();
    let source_id =
        workflow_runtime::ArtifactId::parse(format!("{:x}", Sha256::digest(RAW))).unwrap();
    let approval = TrustedModelProbe::authorize(
        &ir_hash,
        source_id,
        provenance,
        "host-owned-revision",
        declaration,
        ProbeLimits {
            max_steps: 8,
            timeout_ms: 1000,
        },
    )
    .unwrap();
    let plan =
        workflow_compiler::compile_spec_with_sentinel_model_probe(&spec, &approval, declaration)
            .unwrap();
    (plan, approval)
}

#[tokio::test]
async fn approved_public_host_observes_one_complete_raw_batch_on_actual_sdk_wire() {
    let fixture = Fixture::new();
    let wire = Wire::new(BATCH).await;
    // This reference declaration is owned by the host's loopback deployment policy,
    // independently of the separately captured caller-supplied configuration.
    let declaration = snapshot(wire_profile(&wire.endpoint))
        .probe_declaration_digest()
        .unwrap();
    let captured = snapshot(wire_profile(&wire.endpoint));
    assert_eq!(captured.probe_declaration_digest().unwrap(), declaration);
    let (plan, approval) = approved(&declaration);
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe()
    .await;
    assert!(
        result.is_ok(),
        "an independently approved benign batch must reach the real sealed worker"
    );
    let observation = result.unwrap();
    assert_eq!(observation.report.event_count(), 1);
    assert_eq!(observation.usage.as_ref().unwrap().output_tokens(), Some(1));
    let request = wire.finish().await;
    assert_eq!(request.get("reasoning_effort"), Some(&json!("low")));
    assert_eq!(request.get("max_completion_tokens"), Some(&json!(512)));
    assert!(request.get("max_response_bytes").is_none());
    let messages = request.get("messages").unwrap().as_array().unwrap();
    let content = |role| {
        messages
            .iter()
            .find(|message| message.get("role") == Some(&json!(role)))
            .unwrap()
            .get("content")
            .unwrap()
            .as_str()
            .unwrap()
    };
    let full_envelope = serde_json::to_string(&source.envelope()).unwrap();
    assert!(content("user").contains(&full_envelope));
    assert!(!content("system").contains(&full_envelope));
}

fn padded_body(size: usize, status: u16) -> Vec<u8> {
    let mut value = if status == 200 {
        serde_json::from_slice::<Value>(&completion(BATCH, "stop")).unwrap()
    } else {
        json!({"error":{"message":"fixture","type":"fixture_error","code":"fixture"}})
    };
    value["padding"] = json!("");
    let minimum = serde_json::to_vec(&value).unwrap().len();
    value["padding"] = json!("x".repeat(size.checked_sub(minimum).unwrap()));
    let body = serde_json::to_vec(&value).unwrap();
    assert_eq!(body.len(), size);
    body
}

#[tokio::test]
async fn public_host_bounds_success_and_error_bodies_before_eof_without_retry() {
    for status in [200, 429, 503] {
        for framing in [Framing::Length, Framing::Chunked] {
            for size in [65535, 65536, 65537] {
                let fixture = Fixture::new();
                let wire = Wire::response(padded_body(size, status), status, framing).await;
                let captured = snapshot(wire_profile(&wire.endpoint));
                let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
                let policy = ModelRoutePublisher::new(captured)
                    .policy(Instant::now() + Duration::from_secs(5));
                let source = prepared(RAW, Instant::now());
                let result = HostModelProbe {
                    plan: &plan,
                    approval: &approval,
                    source: &source,
                    route: &policy,
                    broker: &CredentialBroker::new(),
                    cancellation: &ModelRouteCancellation::new(),
                    worker: worker(),
                    workdir: &fixture.workdir,
                }
                .observe()
                .await;
                assert_eq!(
                    result.is_ok(),
                    status == 200 && size <= 65536,
                    "status={status} {framing:?} size={size}"
                );
                if let Ok(observation) = result {
                    assert_eq!(observation.report.event_count(), 1);
                }
                wire.finish().await;
            }
        }
        let fixture = Fixture::new();
        let wire = Wire::response(
            padded_body(65537, status),
            status,
            Framing::ChunkedWithoutEof,
        )
        .await;
        let captured = snapshot(wire_profile(&wire.endpoint));
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let policy =
            ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
        let source = prepared(RAW, Instant::now());
        let result = timeout(
            Duration::from_secs(1),
            HostModelProbe {
                plan: &plan,
                approval: &approval,
                source: &source,
                route: &policy,
                broker: &CredentialBroker::new(),
                cancellation: &ModelRouteCancellation::new(),
                worker: worker(),
                workdir: &fixture.workdir,
            }
            .observe(),
        )
        .await
        .expect("overflow must return while the peer still withholds EOF");
        assert!(result.is_err());
        wire.finish().await;
    }
}

#[tokio::test]
async fn public_host_rejects_raw_duplicate_unknown_oversize_and_length_batches() {
    let too_many = json!({"schema_version":1,"steps":(0..33).map(|_| json!({"kind":"output","text":"x"})).collect::<Vec<_>>()}).to_string();
    let oversized = format!("{BATCH}{}", " ".repeat(32769 - BATCH.len()));
    for (text, finish) in [
        (
            r#"{"schema_version":1,"schema_version":1,"steps":[]}"#,
            "stop",
        ),
        (r#"{"schema_version":1,"steps":[],"unknown":true}"#, "stop"),
        (
            r#"{"schema_version":1,"steps":[{"kind":"call","tool":"complete","tool":"complete","arguments":{}}]}"#,
            "stop",
        ),
        (
            r#"{"schema_version":1,"steps":[{"kind":"call","tool":"read","arguments":{"path":"a","path":"b"}}]}"#,
            "stop",
        ),
        (r#"{"schema_version":1,"steps":["#, "stop"),
        (too_many.as_str(), "stop"),
        (oversized.as_str(), "stop"),
        (BATCH, "length"),
    ] {
        let fixture = Fixture::new();
        let wire = Wire::response(completion(text, finish), 200, Framing::Length).await;
        let captured = snapshot(wire_profile(&wire.endpoint));
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let policy =
            ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
        let source = prepared(RAW, Instant::now());
        let result = HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &CredentialBroker::new(),
            cancellation: &ModelRouteCancellation::new(),
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe()
        .await;
        assert!(
            result.is_err(),
            "invalid raw text or terminal {finish} must produce no report"
        );
        wire.finish().await;
    }
    // An independent positive control reaches the worker at the semantic limit.
    let fixture = Fixture::new();
    let mut steps = vec![
        json!({"kind":"call","tool":"read_document","arguments":{"path":"workspace/report.txt"}});
        31
    ];
    steps.push(json!({"kind":"call","tool":"complete","arguments":{}}));
    let batch = json!({"schema_version":1,"steps":steps}).to_string();
    let exact = format!("{batch}{}", " ".repeat(32768 - batch.len()));
    let wire = Wire::new(&exact).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let observation = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe()
    .await
    .unwrap();
    // The 32-action batch is legal; the independently approved step cap is eight.
    assert_eq!(observation.report.event_count(), 8);
    assert_eq!(
        observation.report.stop(),
        workflow_runtime::behavioral::ProbeStop::StepLimit
    );
    wire.finish().await;
}

struct Secrets(AtomicUsize);
impl workflow_adk::model_profiles::SecretProvider for Secrets {
    fn resolve(
        &self,
        _: &str,
    ) -> Result<
        workflow_adk::model_profiles::SecretValue,
        workflow_adk::model_profiles::CredentialError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(workflow_adk::model_profiles::SecretValue::new(
            "fixture-only-token",
        ))
    }
    fn resolve_for_route<'a>(
        &'a self,
        handle: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        workflow_adk::model_profiles::SecretValue,
                        workflow_adk::model_profiles::CredentialError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(std::future::ready(self.resolve(handle)))
    }
}

fn credential_profile(endpoint: &str, handle: &str) -> OpenAiCompatibleProfile {
    OpenAiCompatibleProfile::new(
        "probe",
        "1",
        "model",
        endpoint,
        CredentialHandle::secret_provider(handle),
    )
}

#[tokio::test]
async fn stale_profile_source_approval_cancel_and_deadline_reject_before_broker_or_provider() {
    for case in 0..13 {
        let fixture = Fixture::new();
        let wire = Wire::new(BATCH).await;
        let reference = credential_profile(&wire.endpoint, "approved-handle");
        let declaration = snapshot(reference.clone())
            .probe_declaration_digest()
            .unwrap();
        let (plan, approval) = approved(&declaration);
        let changed = match case {
            0 => credential_profile(&format!("{}-stale", wire.endpoint), "approved-handle"),
            1 => reference
                .with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_secs(2))),
            2 => reference.with_runtime(
                ModelRuntimeConfig::default().with_sampling(|s| s.with_temperature(0.1)),
            ),
            3 => credential_profile(&wire.endpoint, "stale-handle"),
            4 => wire_profile(&wire.endpoint),
            5 => reference.with_runtime(
                ModelRuntimeConfig::default().with_sampling(|s| s.with_max_output_tokens(64)),
            ),
            6 => reference.with_provider("other-provider"),
            _ => reference,
        };
        let captured = snapshot(changed);
        let deadline = match case {
            8 => Instant::now() - Duration::from_millis(1),
            9 => Instant::now() + Duration::from_millis(500),
            _ => Instant::now() + Duration::from_secs(5),
        };
        let policy = ModelRoutePublisher::new(captured).policy(deadline);
        let cancellation = ModelRouteCancellation::new();
        if case == 7 {
            cancellation.cancel();
        }
        let source = prepared(
            if case == 10 { b"different source" } else { RAW },
            Instant::now(),
        );
        // A separately approved old contract is intentionally opaque here. The
        // public producer itself, not a copied test canonicalizer, owns versions.
        let stale_declaration = format!("sha256:{}", "0".repeat(64));
        let (old_plan, old_approval) = approved(&stale_declaration);
        if case == 12 {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
        let broker = CredentialBroker::new().with_secret_provider(secrets.clone());
        let result = HostModelProbe {
            plan: if case == 11 { &old_plan } else { &plan },
            approval: if case == 11 { &old_approval } else { &approval },
            source: &source,
            route: &policy,
            broker: &broker,
            cancellation: &cancellation,
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe()
        .await;
        assert!(result.is_err(), "case {case} must reject before IO");
        assert_eq!(secrets.0.load(Ordering::SeqCst), 0, "case {case}");
        wire.unused().await;
    }
    // A matching independently approved credential resolves exactly once.
    let fixture = Fixture::new();
    let wire = Wire::new(BATCH).await;
    let captured = snapshot(credential_profile(&wire.endpoint, "approved-handle"));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
    let broker = CredentialBroker::new().with_secret_provider(secrets.clone());
    assert!(
        HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &broker,
            cancellation: &ModelRouteCancellation::new(),
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe()
        .await
        .is_ok()
    );
    assert_eq!(secrets.0.load(Ordering::SeqCst), 1);
    wire.finish().await;
}

struct Responses {
    responses: Vec<adk_rust::LlmResponse>,
    calls: AtomicUsize,
}
#[adk_rust::async_trait]
impl adk_rust::Llm for Responses {
    fn name(&self) -> &str {
        "host-strict-text-fixture"
    }
    async fn generate_content(
        &self,
        _: adk_rust::LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(adk_rust::futures::stream::iter(
            self.responses.clone().into_iter().map(Ok),
        )))
    }
}

#[tokio::test]
async fn public_host_uses_complete_text_policy_for_partial_and_nontext_responses() {
    use adk_rust::{Content, LlmResponse, Part};
    let text = LlmResponse::new(Content::new("assistant").with_text(BATCH));
    let mut partial = text.clone();
    partial.partial = true;
    let mut unfinished = text.clone();
    unfinished.turn_complete = false;
    unfinished.finish_reason = None;
    let mut mixed = text.clone();
    mixed
        .content
        .as_mut()
        .unwrap()
        .parts
        .push(Part::FunctionCall {
            name: "complete".into(),
            args: json!({}),
            id: None,
            thought_signature: None,
        });
    for responses in [
        vec![partial],
        vec![unfinished],
        vec![mixed],
        vec![text.clone(), text],
    ] {
        let fixture = Fixture::new();
        let wire = Wire::new(BATCH).await;
        let llm = Arc::new(Responses {
            responses,
            calls: AtomicUsize::new(0),
        });
        let captured = snapshot(wire_profile(&wire.endpoint))
            .with_test_llm(
                ModelRouteCandidate::new(ModelRole::Worker, "probe", "1"),
                llm.clone(),
            )
            .unwrap();
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let policy =
            ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
        let source = prepared(RAW, Instant::now());
        assert!(
            HostModelProbe {
                plan: &plan,
                approval: &approval,
                source: &source,
                route: &policy,
                broker: &CredentialBroker::new(),
                cancellation: &ModelRouteCancellation::new(),
                worker: worker(),
                workdir: &fixture.workdir,
            }
            .observe()
            .await
            .is_err()
        );
        assert_eq!(llm.calls.load(Ordering::SeqCst), 1);
        wire.unused().await;
    }
}

#[tokio::test]
async fn ordinary_sync_and_async_bindings_retain_larger_nonstream_body_default() {
    use adk_rust::{Content, LlmRequest, futures::StreamExt};
    for asynchronous in [false, true] {
        let wire = Wire::response(padded_body(65537, 200), 200, Framing::Length).await;
        let registry = ModelProfileRegistry::new()
            .with_worker(wire_profile(&wire.endpoint))
            .unwrap();
        let broker = CredentialBroker::new();
        let captured = snapshot(wire_profile(&wire.endpoint));
        let policy =
            ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
        if asynchronous {
            // This public route performs the ordinary async binding with None.
            let protocol = workflow_adk::PromptProtocol::new(
                "policy",
                vec![],
                json!({"type":"object"}),
                json!({}),
                workflow_runtime::TrustDomain::UntrustedContent,
            )
            .unwrap();
            let output =
                workflow_adk::StructuredOutputContract::new(json!({"type":"object"}), 32768)
                    .unwrap();
            let invocation = workflow_adk::ModelInvocationSpec::new(
                protocol,
                "task",
                workflow_adk::ProviderRouteIdentity::new(
                    workflow_adk::ModelProfileIdentity::new("placeholder", "1"),
                    "unbound",
                    "unbound",
                    "unbound",
                    "unbound",
                ),
                workflow_adk::InferenceBudget::new(workflow_adk::ReasoningEffort::Low, 512, 0)
                    .unwrap(),
                output,
            )
            .unwrap();
            assert!(
                policy
                    .invoke_complete_text(&invocation, &broker, &ModelRouteCancellation::new())
                    .await
                    .is_ok()
            );
        } else {
            let binding = registry.bind_worker(&broker).unwrap();
            let mut responses = binding
                .generate_content(
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
                    false,
                )
                .await
                .unwrap();
            assert!(responses.next().await.unwrap().is_ok());
        }
        wire.finish().await;
    }
}

#[tokio::test]
async fn ordinary_binding_retains_large_default_event_stream() {
    use adk_rust::{Content, LlmRequest, Part, futures::StreamExt};
    let delta = json!({"id":"fixture","object":"chat.completion.chunk","created":0,"model":"model","choices":[{"index":0,"delta":{"role":"assistant","content":BATCH},"finish_reason":null}],"padding":"x".repeat(65537)});
    let stop = json!({"id":"fixture","object":"chat.completion.chunk","created":0,"model":"model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let body = format!("data: {delta}\n\ndata: {stop}\n\ndata: [DONE]\n\n").into_bytes();
    assert!(body.len() > 65536);
    let wire = Wire::response(body, 200, Framing::EventStream).await;
    let binding = ModelProfileRegistry::new()
        .with_worker(wire_profile(&wire.endpoint))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap();
    let mut responses = binding
        .generate_content(
            LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
            true,
        )
        .await
        .unwrap();
    let mut text = String::new();
    while let Some(response) = responses.next().await {
        if let Some(content) = response.unwrap().content {
            for part in content.parts {
                if let Part::Text { text: chunk } = part {
                    text.push_str(&chunk);
                }
            }
        }
    }
    assert_eq!(text, BATCH);
    let request = wire.finish().await;
    assert_eq!(request.get("stream"), Some(&json!(true)));
}

#[tokio::test]
async fn model_phase_cancel_and_insufficient_remaining_worker_time_return_no_report() {
    for cancel in [true, false] {
        let fixture = Fixture::new();
        let framing = if cancel {
            Framing::ChunkedWithoutEof
        } else {
            Framing::HeldBody
        };
        let mut wire = Wire::response(completion(BATCH, "stop"), 200, framing).await;
        let captured = snapshot(wire_profile(&wire.endpoint));
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let duration = if cancel {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(1200)
        };
        let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + duration);
        let source = prepared(RAW, Instant::now());
        let cancellation = ModelRouteCancellation::new();
        let admitted = wire.admitted.take().unwrap();
        let release = if cancel { None } else { wire.release.take() };
        let steering = async {
            timeout(Duration::from_secs(1), admitted)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                cancellation.cancel();
            } else {
                tokio::time::sleep(Duration::from_millis(350)).await;
                release.unwrap().send(()).unwrap();
            }
        };
        let broker = CredentialBroker::new();
        let host = HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &broker,
            cancellation: &cancellation,
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe();
        let (result, ()) = tokio::join!(host, steering);
        assert!(result.is_err());
        if !cancel {
            assert!(matches!(
                result,
                Err(workflow_adk::AdkGraphError::AuthorizationDenied)
            ));
        }
        wire.finish().await;
    }
}

#[tokio::test]
async fn public_host_rejects_redirect_without_a_second_physical_request() {
    let fixture = Fixture::new();
    let wire = Wire::response(completion(BATCH, "stop"), 307, Framing::Redirect).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe()
    .await;
    assert!(result.is_err(), "a redirect must grant no worker report");
    assert_eq!(wire.count.load(Ordering::SeqCst), 1);
    wire.finish().await;
}

#[tokio::test]
async fn public_host_rejects_transport_truncation_without_retry_or_worker_report() {
    let fixture = Fixture::new();
    // Even a complete semantic batch is rejected when HTTP framing is truncated.
    let wire = Wire::response(completion(BATCH, "stop"), 200, Framing::TruncatedLength).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe()
    .await;
    assert!(
        result.is_err(),
        "premature HTTP EOF must grant no worker report"
    );
    wire.finish().await;
}

#[tokio::test]
async fn public_host_route_deadline_expires_during_pending_actual_http_transport() {
    let fixture = Fixture::new();
    let mut wire = Wire::response(completion(BATCH, "stop"), 200, Framing::HeldBody).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    // The original approved worker budget remains 1000ms. The ordinary profile
    // timeout exceeds this route deadline; the peer sends nothing until released.
    let deadline = Instant::now() + Duration::from_millis(1200);
    let policy = ModelRoutePublisher::new(captured).policy(deadline);
    let source = prepared(RAW, Instant::now());
    let result = timeout(
        Duration::from_secs(3),
        HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &CredentialBroker::new(),
            cancellation: &ModelRouteCancellation::new(),
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe(),
    )
    .await
    .expect("actual route deadline must bound pending transport");
    assert!(
        result.is_err(),
        "transport timeout must grant no worker report"
    );
    assert!(
        Instant::now() >= deadline,
        "an early unrelated rejection is not a timeout control"
    );
    timeout(Duration::from_secs(1), wire.admitted.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire.count.load(Ordering::SeqCst), 1);
    wire.finish().await;
}

#[path = "issue_233_model_worker/publication.rs"]
mod publication;
