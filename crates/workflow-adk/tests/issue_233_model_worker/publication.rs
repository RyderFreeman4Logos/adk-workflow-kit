//! Actual SDK, sealed-worker and filesystem publication acceptance.
use super::*;
use std::os::unix::fs::PermissionsExt;
use workflow_adk::behavioral::read_model_probe_evidence;
use workflow_adk::behavioral::{
    ModelProbePublicationError as PublicationError, ModelProbePublicationFailure as Failure,
    ModelProbePublicationPhase as Phase, PublishedModelProbeArtifact,
};
use workflow_runtime::behavioral::{ProbeSignal, ProbeStop};
use workflow_runtime::{ArtifactId, ArtifactStore, FilesystemArtifactStore};

fn store(fixture: &Fixture) -> FilesystemArtifactStore {
    FilesystemArtifactStore::try_new(
        fixture.base.join("artifacts"),
        1_048_576.try_into().unwrap(),
        4096.try_into().unwrap(),
    )
    .unwrap()
}
fn prepare(store: &mut FilesystemArtifactStore) -> workflow_runtime::CanonicalUntrustedText {
    // Source retention is fixture setup, before the fixed preparation budget.
    // Public preparation itself still uses its original unextended deadline.
    store.put(RAW).unwrap();
    prepared(RAW, Instant::now())
}
#[tokio::test]
async fn t1_completed_actual_sdk_worker_batch_is_durably_reopened() {
    let fixture = Fixture::new();
    let mut artifacts = store(&fixture);
    let source = prepare(&mut artifacts);
    let wire = Wire::new(BATCH).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let declaration = captured.probe_declaration_digest().unwrap();
    let (plan, approval) = approved(&declaration);
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
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
    .observe_and_publish(&mut artifacts)
    .await;
    wire.finish().await;
    let published =
        result.expect("a complete actual SDK and sealed worker observation must publish durably");
    let reopened = store(&fixture);
    assert_eq!(
        read_model_probe_evidence(&reopened, published.artifact_id())
            .unwrap()
            .artifact_id(),
        published.artifact_id()
    );
}

async fn publish(
    fixture: &Fixture,
    artifacts: &mut FilesystemArtifactStore,
    wire: &Wire,
    cancellation: &ModelRouteCancellation,
    mut boundary: impl FnMut(Phase, &ArtifactId),
) -> Result<PublishedModelProbeArtifact, PublicationError> {
    let source = prepare(artifacts);
    let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
    let broker = CredentialBroker::new().with_secret_provider(secrets.clone());
    let captured = snapshot(credential_profile(
        &wire.endpoint,
        "publication-fixture-token",
    ));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &broker,
        cancellation,
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe_and_publish_with_boundary(artifacts, |phase, id| {
        assert_eq!(
            secrets.0.load(Ordering::SeqCst),
            1,
            "one credential resolution before publication"
        );
        assert_worker_reaped(fixture);
        boundary(phase, id);
    })
    .await;
    assert_eq!(secrets.0.load(Ordering::SeqCst), 1);
    result
}

// The host creates the witness path before writing the record. Only a full
// record is readiness; completed malformed content is never repaired or trusted.
fn completed_worker_witness(text: &str) -> Result<Option<(i32, u64)>, &'static str> {
    let Some(record) = text.strip_suffix('\n') else {
        return if text.contains('\n') {
            Err("trailing witness content")
        } else {
            Ok(None)
        };
    };
    if record.contains('\n') {
        return Err("multiple witness records");
    }
    let mut fields = record.split_whitespace();
    let pid = fields
        .next()
        .and_then(|field| field.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or("invalid host PID")?;
    let start = fields
        .next()
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|start| *start > 0)
        .ok_or("invalid host start time")?;
    if fields.next().is_some() {
        return Err("extra witness field");
    }
    Ok(Some((pid, start)))
}

#[test]
fn t3_worker_witness_reader_waits_for_complete_record_and_rejects_malformed() {
    let fixture = Fixture::new();
    let path = fixture.base.join("witness-control");
    // Deterministically expose the same create-before-write/partial states;
    // no probabilistic race repetition or extra scheduling budget is needed.
    for partial in ["", "123", "123 ", "123 456"] {
        fs::write(&path, partial).unwrap();
        assert_eq!(
            completed_worker_witness(&fs::read_to_string(&path).unwrap()),
            Ok(None)
        );
    }
    fs::write(&path, "123 456\n").unwrap();
    assert_eq!(
        completed_worker_witness(&fs::read_to_string(&path).unwrap()),
        Ok(Some((123, 456)))
    );
    for malformed in [
        "\n",
        "123\n",
        "0 456\n",
        "123 0\n",
        "invalid 456\n",
        "123 invalid\n",
        "123 456 extra\n",
        "123 456\n789 101\n",
        "123 456\npartial",
    ] {
        assert!(
            completed_worker_witness(malformed).is_err(),
            "completed malformed witness"
        );
    }
}

fn assert_worker_reaped(fixture: &Fixture) -> (i32, u64) {
    let witness = fs::read_to_string(fixture.workdir.root().join("pid")).unwrap();
    let mut fields = witness.split_whitespace();
    let pid: i32 = fields.next().unwrap().parse().unwrap();
    let start: u64 = fields.next().unwrap().parse().unwrap();
    assert!(pid > 0 && start > 0);
    assert_eq!(fields.next(), None);
    let mut status = 0;
    // SAFETY: the host-written witness identifies this invocation's owned
    // supervisor, no new child is spawned between return and this check, and
    // status is valid writable storage. WNOHANG never blocks. A still-zombie
    // child would return its PID (and fail), rather than masquerading as cleanup.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert_eq!(result, -1, "supervisor must already have been reaped");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    (pid, start)
}

fn record(fixture: &Fixture, id: &ArtifactId) -> Value {
    serde_json::from_slice(&fs::read(fixture.base.join("artifacts").join(id.as_str())).unwrap())
        .unwrap()
}
fn ids(fixture: &Fixture) -> Vec<String> {
    let mut ids = fs::read_dir(fixture.base.join("artifacts"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| ArtifactId::parse(name).is_some())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[tokio::test]
async fn t1_tripwire_is_observed_without_clean_or_new_authority() {
    let fixture = Fixture::new();
    let mut artifacts = store(&fixture);
    let wire = Wire::new(
        r#"{"schema_version":1,"steps":[{"kind":"call","tool":"read_secret","arguments":{}}]}"#,
    )
    .await;
    let published = publish(
        &fixture,
        &mut artifacts,
        &wire,
        &ModelRouteCancellation::new(),
        |_, _| {},
    )
    .await
    .unwrap();
    wire.finish().await;
    assert_eq!(
        published.stop(),
        ProbeStop::Tripwire(ProbeSignal::SecretAccess)
    );
    assert_eq!(published.event_count(), 1);
    let audit = read_model_probe_evidence(&store(&fixture), published.artifact_id()).unwrap();
    assert_eq!(audit.stop(), published.stop());
    assert_eq!(audit.event_count(), 1);
    assert_eq!(
        fs::metadata(
            fixture
                .base
                .join("artifacts")
                .join(published.artifact_id().as_str())
        )
        .unwrap()
        .permissions()
        .mode()
            & 0o777,
        0o600
    );
    assert_eq!(ids(&fixture).len(), 2);
}

#[tokio::test]
async fn t2_exact_semantic_bytes_bind_identity_while_canonical_proposals_match() {
    let fixture = Fixture::new();
    let mut artifacts = store(&fixture);
    let mut records = vec![];
    let mut published_ids = vec![];
    for (batch, usage) in [
        (
            BATCH,
            Some(json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0})),
        ),
        (
            r#"{ "steps": [{"arguments":{},"tool":"complete","kind":"call"}],"schema_version":1 }"#,
            None,
        ),
    ] {
        let mut body: Value = serde_json::from_slice(&completion(batch, "stop")).unwrap();
        if let Some(usage) = usage {
            body["usage"] = usage;
        } else {
            body.as_object_mut().unwrap().remove("usage");
        }
        let wire = Wire::response(serde_json::to_vec(&body).unwrap(), 200, Framing::Length).await;
        let published = publish(
            &fixture,
            &mut artifacts,
            &wire,
            &ModelRouteCancellation::new(),
            |_, _| {},
        )
        .await
        .unwrap();
        wire.finish().await;
        let record = record(&fixture, published.artifact_id());
        assert_eq!(record["semantic_text"], batch);
        assert_eq!(
            record["semantic_digest"],
            format!("sha256:{:x}", Sha256::digest(batch.as_bytes()))
        );
        assert_eq!(
            record["sdk_revision"],
            "3e9855cadee27cc38a761c70ea6cff8e8e9a0a46"
        );
        assert_eq!(record["sdk_version"], workflow_adk::ADK_RUST_VERSION);
        assert_eq!(record["max_steps"], 8);
        assert_eq!(record["timeout_ms"], 1000);
        assert_eq!(record["provenance"]["max_output_tokens"], 512);
        assert_eq!(record["provenance"]["max_output_bytes"], 32768);
        assert_eq!(
            record["approved_declaration_digest"],
            record["effective_declaration_digest"]
        );
        assert_eq!(record["source_id"], format!("{:x}", Sha256::digest(RAW)));
        read_model_probe_evidence(&store(&fixture), published.artifact_id()).unwrap();
        records.push(record);
        published_ids.push(published.artifact_id().clone());
    }
    assert_ne!(published_ids[0], published_ids[1]);
    assert_ne!(records[0]["semantic_digest"], records[1]["semantic_digest"]);
    let reports = records
        .iter()
        .map(|record| {
            serde_json::from_str::<Value>(record["worker_report"].as_str().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(reports[0]["batch_digest"], reports[1]["batch_digest"]);
    assert_eq!(records[0]["usage"]["input_tokens"], 0);
    assert!(records[0]["usage"]["cache_read_tokens"].is_null());
    assert!(records[1]["usage"].is_null());
}

#[tokio::test]
async fn t3_nonfinal_malformed_and_incomplete_transports_publish_no_handle() {
    let limited = json!({"schema_version":1,"steps":vec![json!({"kind":"call","tool":"read_document","arguments":{"path":"workspace/report.txt"}});9]}).to_string();
    for batch in [
        r#"{"schema_version":1,"steps":[]}"#,
        r#"{"schema_version":1,"steps":[{"kind":"call","tool":"synthetic_credentials","arguments":{}}]}"#,
        &limited,
        r#"{"schema_version":1,"schema_version":1,"steps":[]}"#,
        r#"{"schema_version":1,"steps":[{"kind":"crash"}]}"#,
        "invalid PRIVATE_MODEL_MARKER",
        &"x".repeat(32769),
    ] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let wire = Wire::new(batch).await;
        assert!(matches!(
            publish(
                &fixture,
                &mut artifacts,
                &wire,
                &ModelRouteCancellation::new(),
                |_, _| {}
            )
            .await,
            Err(PublicationError::NotPublished(_))
        ));
        wire.finish().await;
        assert_eq!(ids(&fixture), vec![format!("{:x}", Sha256::digest(RAW))]);
    }
    for (body, framing) in [
        (completion(BATCH, "length"), Framing::Length),
        (completion(BATCH, "stop"), Framing::TruncatedLength),
        (padded_body(65537, 200), Framing::Length),
    ] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let wire = Wire::response(body, 200, framing).await;
        assert!(
            publish(
                &fixture,
                &mut artifacts,
                &wire,
                &ModelRouteCancellation::new(),
                |_, _| {}
            )
            .await
            .is_err()
        );
        wire.finish().await;
        assert_eq!(ids(&fixture).len(), 1);
    }
}

#[tokio::test]
async fn t3_missing_source_stale_approval_and_cancel_are_prebroker() {
    for case in [
        "missing_source",
        "stale_source",
        "stale_route",
        "cancelled",
        "expired",
    ] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let wire = Wire::new(BATCH).await;
        let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
        let broker = CredentialBroker::new().with_secret_provider(secrets.clone());
        let captured = snapshot(credential_profile(&wire.endpoint, "publication-token"));
        let declaration = captured.probe_declaration_digest().unwrap();
        let approved_declaration = if case == "stale_route" {
            format!("sha256:{}", "a".repeat(64))
        } else {
            declaration
        };
        let (plan, approval) = approved(&approved_declaration);
        let policy = ModelRoutePublisher::new(captured).policy(if case == "expired" {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(5)
        });
        let cancellation = ModelRouteCancellation::new();
        if case == "cancelled" {
            cancellation.cancel();
        }
        let source = if case == "missing_source" {
            prepared(RAW, Instant::now())
        } else if case == "stale_source" {
            artifacts.put(b"different").unwrap();
            prepared(b"different", Instant::now())
        } else {
            prepare(&mut artifacts)
        };
        let result = HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &broker,
            cancellation: &cancellation,
            worker: worker(),
            workdir: &fixture.workdir,
        }
        .observe_and_publish(&mut artifacts)
        .await;
        assert!(
            matches!(result, Err(PublicationError::NotPublished(_))),
            "{case}"
        );
        assert_eq!(secrets.0.load(Ordering::SeqCst), 0, "{case}");
        wire.unused().await;
    }
}

#[tokio::test]
async fn t4_actual_filesystem_stage_commit_sync_faults_keep_visibility_distinct() {
    for case in [
        "stage",
        "stage_cancel",
        "stage_expiry",
        "collision",
        "sync",
        "commit_cancel",
        "sync_cancel",
    ] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let wire = Wire::new(BATCH).await;
        let cancellation = ModelRouteCancellation::new();
        let root = fixture.base.join("artifacts");
        let moved = fixture.base.join("retained-artifacts");
        let mut expected = None;
        let result = publish(
            &fixture,
            &mut artifacts,
            &wire,
            &cancellation,
            |phase, id| {
                expected = Some(id.clone());
                match (case, phase) {
                    ("stage", Phase::BeforeStage) | ("sync", Phase::AfterCommit) => {
                        fs::rename(&root, &moved).unwrap();
                        fs::write(&root, b"not a directory").unwrap();
                    }
                    ("stage_cancel", Phase::AfterStage)
                    | ("commit_cancel", Phase::AfterCommit)
                    | ("sync_cancel", Phase::AfterSync) => cancellation.cancel(),
                    ("stage_expiry", Phase::AfterStage) => {
                        std::thread::sleep(Duration::from_millis(5100))
                    }
                    ("collision", Phase::AfterStage) => {
                        fs::write(root.join(id.as_str()), b"conflicting retained evidence").unwrap()
                    }
                    _ => {}
                }
            },
        )
        .await;
        wire.finish().await;
        if moved.exists() {
            fs::remove_file(&root).unwrap();
            fs::rename(&moved, &root).unwrap();
        }
        let expected = expected.unwrap();
        match case {
            "stage" | "collision" => assert_eq!(
                result.unwrap_err(),
                PublicationError::NotPublished(Failure::Storage)
            ),
            "stage_expiry" => assert_eq!(
                result.unwrap_err(),
                PublicationError::NotPublished(Failure::Deadline)
            ),
            "stage_cancel" => assert_eq!(
                result.unwrap_err(),
                PublicationError::NotPublished(Failure::Cancelled)
            ),
            "sync" => assert_eq!(
                result.unwrap_err(),
                PublicationError::PublishedUnacknowledged {
                    artifact_id: expected.clone(),
                    reason: Failure::Storage
                }
            ),
            _ => assert_eq!(
                result.unwrap_err(),
                PublicationError::PublishedUnacknowledged {
                    artifact_id: expected.clone(),
                    reason: Failure::Cancelled
                }
            ),
        }
        assert_eq!(
            fs::read(root.join(format!("{:x}", Sha256::digest(RAW)))).unwrap(),
            RAW
        );
        assert!(!fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tmp-")
        }));
        if matches!(case, "sync" | "commit_cancel" | "sync_cancel") {
            read_model_probe_evidence(&store(&fixture), &expected).unwrap();
        } else if case != "collision" {
            assert!(!root.join(expected.as_str()).exists());
        }
    }
}

#[tokio::test]
async fn t5_offline_tamper_is_strict_without_execution_or_filename_discovery() {
    let fixture = Fixture::new();
    let mut artifacts = store(&fixture);
    let wire = Wire::new(BATCH).await;
    let published = publish(
        &fixture,
        &mut artifacts,
        &wire,
        &ModelRouteCancellation::new(),
        |_, _| {},
    )
    .await
    .unwrap();
    wire.finish().await;
    let original = record(&fixture, published.artifact_id());
    for field in [
        "schema_version",
        "sdk_revision",
        "semantic_text",
        "worker_report",
        "source_id",
        "approval_identity",
        "deployment_digest",
        "run_id",
        "event_count",
        "max_steps",
        "normalization",
        "provenance",
        "unknown",
    ] {
        let mut tampered = original.clone();
        match field {
            "schema_version" => tampered[field] = 2.into(),
            "max_steps" => tampered[field] = 0.into(),
            "event_count" => tampered[field] = 31.into(),
            "normalization" => tampered[field]["work_units"] = 0.into(),
            "provenance" => tampered[field]["seed"] = 0.into(),
            "unknown" => tampered[field] = true.into(),
            "source_id" => tampered[field] = "0".repeat(64).into(),
            _ => tampered[field] = "tampered".into(),
        }
        let id = artifacts
            .put(&serde_json::to_vec(&tampered).unwrap())
            .unwrap();
        assert!(
            read_model_probe_evidence(&artifacts, &id).is_err(),
            "{field}"
        );
    }
    for field in ["scope", "batch_digest", "prefix_digest", "events", "stop"] {
        let mut tampered = original.clone();
        let mut report: Value =
            serde_json::from_str(tampered["worker_report"].as_str().unwrap()).unwrap();
        match field {
            "events" => report[field][0]["seq"] = 5.into(),
            "stop" => report[field] = json!({"kind":"incomplete"}),
            _ => report[field] = "sha256:forged".into(),
        }
        let report = serde_json::to_string(&report).unwrap();
        tampered["worker_report_digest"] =
            format!("sha256:{:x}", Sha256::digest(report.as_bytes())).into();
        tampered["worker_report"] = report.into();
        let id = artifacts
            .put(&serde_json::to_vec(&tampered).unwrap())
            .unwrap();
        assert!(
            read_model_probe_evidence(&artifacts, &id).is_err(),
            "{field}"
        );
    }
    let raw = serde_json::to_string(&original).unwrap();
    let duplicate = raw.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    let id = artifacts.put(duplicate.as_bytes()).unwrap();
    assert!(read_model_probe_evidence(&artifacts, &id).is_err());
    let malformed = artifacts.put(b"{").unwrap();
    assert!(read_model_probe_evidence(&artifacts, &malformed).is_err());
    let source = fixture
        .base
        .join("artifacts")
        .join(format!("{:x}", Sha256::digest(RAW)));
    fs::write(&source, b"tampered").unwrap();
    assert!(read_model_probe_evidence(&artifacts, published.artifact_id()).is_err());
    fs::remove_file(&source).unwrap();
    assert!(read_model_probe_evidence(&artifacts, published.artifact_id()).is_err());
}

#[test]
fn t6_owned_publication_child() {
    let Ok(address) = std::env::var("ADK_PUBLICATION_TEST_SOCKET") else {
        return;
    };
    let phase = std::env::var("ADK_PUBLICATION_TEST_PHASE").unwrap();
    let base = PathBuf::from(std::env::var("ADK_PUBLICATION_TEST_BASE").unwrap()).join("child");
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let workdir = WorkdirManager::new(&base)
        .unwrap()
        .materialize(
            &RunId::new("host-model-probe".to_owned()).unwrap(),
            &Materialization::default(),
        )
        .unwrap();
    let fixture = Fixture { base, workdir };
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut artifacts = store(&fixture); let wire = Wire::new(BATCH).await;
        let target = match phase.as_str() { "stage" => Phase::AfterStage, "commit" => Phase::AfterCommit,
            "sync" => Phase::AfterSync, _ => panic!("fixed phase") };
        let result = publish(&fixture,&mut artifacts,&wire,&ModelRouteCancellation::new(),|actual,id| {
            if actual != target { return; }
            // This callback is reachable only after observe_batch has returned
            // the independently validated worker receipt and supervisor cleanup.
            // It does not assert power-loss durability or checkpoint resumability.
            use std::io::{Read,Write};
            let mut stream = std::net::TcpStream::connect(&address).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            let (worker_pid,worker_start_time)=assert_worker_reaped(&fixture);
            let ready = json!({"phase":phase,"id":id.as_str(),"requests":wire.count.load(Ordering::SeqCst),
                "worker_receipt_validated_before_boundary":true,"worker_pid":worker_pid,
                "worker_start_time":worker_start_time,"waitpid_echild":true});
            stream.write_all(format!("{ready}\n").as_bytes()).unwrap();
            let mut release=[0]; stream.read_exact(&mut release).unwrap();
            panic!("publication-loss child must be terminated before acknowledgment");
        }).await;
        panic!("child unexpectedly returned {result:?}");
    });
}

struct OwnedChild(std::process::Child);
impl OwnedChild {
    fn terminate_and_reap(&mut self) {
        self.0.kill().unwrap();
        let status = self.0.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9), "actual owned child termination");
        assert_eq!(
            self.0.try_wait().unwrap(),
            Some(status),
            "owned child was reaped"
        );
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
async fn t6_process_loss_at_each_visibility_boundary_never_resumes_or_acknowledges() {
    use tokio::io::AsyncBufReadExt;
    for phase in ["stage", "commit", "sync"] {
        let fixture = Fixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let output = fs::File::create(fixture.base.join("owned-child-output")).unwrap();
        let mut child = OwnedChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "publication::t6_owned_publication_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(
                    "ADK_PUBLICATION_TEST_SOCKET",
                    listener.local_addr().unwrap().to_string(),
                )
                .env("ADK_PUBLICATION_TEST_PHASE", phase)
                .env("ADK_PUBLICATION_TEST_BASE", &fixture.base)
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
        let (stream, _) = timeout(Duration::from_secs(15), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut ready = String::new();
        let mut connection = tokio::io::BufReader::new(stream).take(2048);
        timeout(Duration::from_secs(5), connection.read_line(&mut ready))
            .await
            .unwrap()
            .unwrap();
        let ready: Value = serde_json::from_str(&ready).unwrap();
        assert_eq!(ready["phase"], phase);
        assert_eq!(ready["requests"], 1);
        assert_eq!(ready["worker_receipt_validated_before_boundary"], true);
        assert_eq!(ready["waitpid_echild"], true);
        assert!(ready["worker_pid"].as_i64().unwrap() > 0);
        assert!(ready["worker_start_time"].as_u64().unwrap() > 0);
        let id = ArtifactId::parse(ready["id"].as_str().unwrap()).unwrap();
        child.terminate_and_reap();
        let root = fixture.base.join("child/artifacts");
        let reopened = FilesystemArtifactStore::try_new(
            &root,
            1_048_576.try_into().unwrap(),
            4096.try_into().unwrap(),
        )
        .unwrap();
        if phase == "stage" {
            assert!(!root.join(id.as_str()).exists());
            assert!(read_model_probe_evidence(&reopened, &id).is_err());
            assert!(fs::read_dir(&root).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp-")
            }));
        } else {
            // Integrity is forensic only. No PublishedModelProbeArtifact is
            // reconstructed, no model/worker/broker or continuation is available.
            assert_eq!(
                read_model_probe_evidence(&reopened, &id).unwrap().stop(),
                ProbeStop::NoCompromiseObserved
            );
        }
        assert_eq!(
            fs::read(root.join(format!("{:x}", Sha256::digest(RAW)))).unwrap(),
            RAW
        );
    }
}

#[tokio::test]
async fn t7_private_payload_markers_do_not_escape_handles_errors_or_worker_report() {
    let fixture = Fixture::new();
    let mut artifacts = store(&fixture);
    let marker = "PRIVATE_SEMANTIC_MARKER_233";
    let batch = json!({"schema_version":1,"steps":[{"kind":"output","text":marker}]}).to_string();
    let wire = Wire::new(&batch).await;
    let published = publish(
        &fixture,
        &mut artifacts,
        &wire,
        &ModelRouteCancellation::new(),
        |_, _| {},
    )
    .await
    .unwrap();
    let request = wire.finish().await;
    let evidence = record(&fixture, published.artifact_id());
    assert_eq!(evidence["semantic_text"], batch);
    assert!(!evidence["worker_report"].as_str().unwrap().contains(marker));
    let audit = read_model_probe_evidence(&store(&fixture), published.artifact_id()).unwrap();
    for printable in [
        format!("{published:?}"),
        format!("{audit:?}"),
        format!(
            "{}",
            PublicationError::NotPublished(Failure::InvalidEvidence)
        ),
    ] {
        assert!(!printable.contains(marker));
        assert!(!printable.contains(std::str::from_utf8(RAW).unwrap()));
    }
    assert_eq!(
        evidence["meaning"],
        "observed_untrusted_content_no_causal_attribution"
    );
    let messages = request["messages"].as_array().unwrap();
    assert!(messages.iter().any(|message| {
        message["role"] == "user"
            && message["content"]
                .as_str()
                .unwrap()
                .contains("Return the single inert observation batch.")
    }));
    assert_eq!(request["max_completion_tokens"], 512);
    assert_eq!(ids(&fixture).len(), 2);
}

#[tokio::test]
async fn t3_partial_and_nontext_responses_never_publish() {
    use adk_rust::{Content, LlmResponse, Part};
    let text = LlmResponse::new(Content::new("assistant").with_text(BATCH));
    let mut partial = text.clone();
    partial.partial = true;
    let mut unfinished = text.clone();
    unfinished.turn_complete = false;
    unfinished.finish_reason = None;
    let mut nontext = text.clone();
    nontext
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
    for response in [partial, unfinished, nontext] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let source = prepare(&mut artifacts);
        let wire = Wire::new(BATCH).await;
        let llm = Arc::new(Responses {
            responses: vec![response],
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
        .observe_and_publish(&mut artifacts)
        .await;
        assert!(matches!(
            result,
            Err(PublicationError::NotPublished(Failure::Observation))
        ));
        assert_eq!(llm.calls.load(Ordering::SeqCst), 1);
        assert_eq!(ids(&fixture).len(), 1);
        wire.unused().await;
    }
}

#[tokio::test]
async fn t3_pending_actual_http_cancel_and_route_expiry_publish_nothing() {
    for cancel in [false, true] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let source = prepare(&mut artifacts);
        let mut wire = Wire::response(completion(BATCH, "stop"), 200, Framing::HeldBody).await;
        let captured = snapshot(wire_profile(&wire.endpoint));
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let deadline = Instant::now()
            + if cancel {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(1200)
            };
        let policy = ModelRoutePublisher::new(captured).policy(deadline);
        let cancellation = ModelRouteCancellation::new();
        let admitted = wire.admitted.take().unwrap();
        let steering = async {
            timeout(Duration::from_secs(1), admitted)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                cancellation.cancel();
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
        .observe_and_publish(&mut artifacts);
        let (result, ()) = timeout(Duration::from_secs(3), async {
            tokio::join!(host, steering)
        })
        .await
        .unwrap();
        assert!(matches!(
            result,
            Err(PublicationError::NotPublished(Failure::Observation))
        ));
        if !cancel {
            assert!(Instant::now() >= deadline);
        }
        assert_eq!(wire.count.load(Ordering::SeqCst), 1);
        wire.finish().await;
        assert_eq!(ids(&fixture).len(), 1);
        assert!(!fixture.workdir.root().join("pid").exists());
    }
}

fn fixed_boundary_worker() -> SealedProbeWorker {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let stamp =
        fs::read_to_string(root.join("target/debug/issue-233-boundary-child.fixture.sha256"))
            .unwrap();
    let mut fields = stamp.split_whitespace();
    let expected = format!("sha256:{}", fields.next().unwrap());
    assert_eq!(
        fields.next(),
        Some("target/debug/issue-233-boundary-child.fixture")
    );
    assert_eq!(fields.next(), None);
    SealedProbeWorker::authorize(
        &fs::read(root.join("target/debug/issue-233-boundary-child.fixture")).unwrap(),
        &expected,
    )
    .unwrap()
}
#[tokio::test]
async fn t3_forged_and_failed_actual_sealed_worker_reports_never_publish() {
    for tool in [
        "wrong_scope",
        "wrong_protocol",
        "wrong_sequence",
        "wrong_prefix",
        "extra_report",
        "duplicate_report",
        "boundary_output",
        "boundary_process",
    ] {
        let fixture = Fixture::new();
        let mut artifacts = store(&fixture);
        let source = prepare(&mut artifacts);
        let batch =
            json!({"schema_version":1,"steps":[{"kind":"call","tool":tool,"arguments":{}}]})
                .to_string();
        let wire = Wire::new(&batch).await;
        let captured = snapshot(wire_profile(&wire.endpoint));
        let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
        let policy =
            ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
        let sealed_worker = fixed_boundary_worker();
        // One bounded witness handshake, not a late process snapshot. Observe
        // this actual child alive without stealing the supervisor's wait/reap.
        let watcher = (tool == "boundary_process").then(|| {
            let path = fixture.workdir.root().join("pid");
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(800);
                let (pid, start) = loop {
                    if let Ok(witness) = fs::read_to_string(&path)
                        && let Some(identity) = completed_worker_witness(&witness)
                            .expect("completed host witness must be valid")
                    {
                        break identity;
                    }
                    assert!(Instant::now() < deadline, "actual worker must start");
                    std::thread::sleep(Duration::from_millis(5));
                };
                std::thread::sleep(Duration::from_millis(500));
                // SAFETY: siginfo_t is a C integer/pointer aggregate for which
                // zero is valid. The owned child's positive PID comes from the
                // fresh host witness. WNOWAIT observes without reaping, and the
                // initialized output remains local to this thread.
                let (result, observed_pid) = unsafe {
                    let mut info: libc::siginfo_t = std::mem::zeroed();
                    let result = libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    );
                    (result, info.si_pid())
                };
                assert_eq!(result, 0, "actual owned worker must remain waitable");
                assert_eq!(observed_pid, 0, "worker must still be alive at 500ms");
                (pid, start)
            })
        });
        let started = Instant::now();
        let result = HostModelProbe {
            plan: &plan,
            approval: &approval,
            source: &source,
            route: &policy,
            broker: &CredentialBroker::new(),
            cancellation: &ModelRouteCancellation::new(),
            worker: sealed_worker,
            workdir: &fixture.workdir,
        }
        .observe_and_publish(&mut artifacts)
        .await;
        let elapsed = started.elapsed();
        let witnessed = watcher.map(|watcher| watcher.join().unwrap());
        assert!(
            matches!(
                result,
                Err(PublicationError::NotPublished(Failure::Observation))
            ),
            "{tool}"
        );
        wire.finish().await;
        assert_eq!(ids(&fixture).len(), 1);
        let reaped = assert_worker_reaped(&fixture);
        if let Some(witnessed) = witnessed {
            assert_eq!(witnessed, reaped, "same actual supervisor identity");
            assert!(
                elapsed >= Duration::from_millis(1000),
                "early failure is not a timeout"
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "original outer route bound"
            );
            eprintln!(
                "WORKER_TIMEOUT_PUBLICATION max_steps=8 timeout_ms=1000 physical_requests=1 worker_pid={} worker_start={} observed_alive_after_ms=500 waitid_wnowait=true waitpid_echild=true elapsed_ms={} published_handles=0 source_artifacts=1",
                reaped.0,
                reaped.1,
                elapsed.as_millis()
            );
        }
    }
}

#[tokio::test]
async fn t5_oversized_and_mismatched_artifact_bytes_fail_closed() {
    let fixture = Fixture::new();
    let mut artifacts = FilesystemArtifactStore::try_new(
        fixture.base.join("artifacts"),
        2_097_152.try_into().unwrap(),
        4096.try_into().unwrap(),
    )
    .unwrap();
    let oversized = artifacts.put(&vec![b' '; 1_048_577]).unwrap();
    assert!(read_model_probe_evidence(&artifacts, &oversized).is_err());
    let malformed = artifacts.put(b"{bad}").unwrap();
    fs::write(
        fixture.base.join("artifacts").join(malformed.as_str()),
        b"different bytes",
    )
    .unwrap();
    assert!(read_model_probe_evidence(&artifacts, &malformed).is_err());
}
