use super::*;
use adk_rust::session::{AppendEventRequest, DeleteRequest, GetRequest, ListRequest, Session};
use workflow_adk::model_profiles::{
    CredentialError, CredentialHandle, OpenAiCompatibleProfile, SecretProvider, SecretValue,
};
use workflow_adk::{ModelInvocationErrorKind, ModelRouteTerminalErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Load,
    User,
    Assistant,
}

enum Action {
    Normal,
    Fail(Stage),
    Pending(Stage),
    Cancel(Stage, ModelRouteCancellation),
    WrongIdentity(AdkIdentity),
    Delay(Duration),
}

struct Store {
    inner: InMemorySessionService,
    action: Action,
    calls: [AtomicUsize; 3],
    started: tokio::sync::Notify,
    dropped: AtomicUsize,
}

struct PendingGuard<'a>(&'a AtomicUsize);
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Store {
    fn new(action: Action) -> Self {
        Self {
            inner: InMemorySessionService::new(),
            action,
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            started: tokio::sync::Notify::new(),
            dropped: AtomicUsize::new(0),
        }
    }
    fn counts(&self) -> [usize; 3] {
        std::array::from_fn(|index| self.calls[index].load(Ordering::SeqCst))
    }
    async fn before(&self, stage: Stage) -> adk_rust::Result<()> {
        self.calls[match stage {
            Stage::Load => 0,
            Stage::User => 1,
            Stage::Assistant => 2,
        }]
        .fetch_add(1, Ordering::SeqCst);
        match &self.action {
            Action::Fail(at) if *at == stage => {
                Err(adk_rust::AdkError::session("private-store-error"))
            }
            Action::Pending(at) if *at == stage => {
                let _guard = PendingGuard(&self.dropped);
                self.started.notify_one();
                std::future::pending().await
            }
            Action::Cancel(at, cancellation) if *at == stage => {
                cancellation.cancel();
                Ok(())
            }
            Action::Delay(duration) => {
                tokio::time::sleep(*duration).await;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[adk_rust::async_trait]
impl SessionService for Store {
    async fn create(&self, req: CreateRequest) -> adk_rust::Result<Box<dyn Session>> {
        self.inner.create(req).await
    }
    async fn get(&self, req: GetRequest) -> adk_rust::Result<Box<dyn Session>> {
        self.inner.get(req).await
    }
    async fn list(&self, req: ListRequest) -> adk_rust::Result<Vec<Box<dyn Session>>> {
        self.inner.list(req).await
    }
    async fn delete(&self, req: DeleteRequest) -> adk_rust::Result<()> {
        self.inner.delete(req).await
    }
    async fn append_event(&self, _: &str, _: adk_rust::Event) -> adk_rust::Result<()> {
        panic!("bare session ID append is forbidden")
    }
    async fn get_for_identity(&self, id: &AdkIdentity) -> adk_rust::Result<Box<dyn Session>> {
        self.before(Stage::Load).await?;
        self.inner
            .get_for_identity(if let Action::WrongIdentity(other) = &self.action {
                other
            } else {
                id
            })
            .await
    }
    async fn append_event_for_identity(&self, req: AppendEventRequest) -> adk_rust::Result<()> {
        self.before(if req.event.author == "user" {
            Stage::User
        } else {
            Stage::Assistant
        })
        .await?;
        self.inner.append_event_for_identity(req).await
    }
}

struct Secrets(AtomicUsize);
impl SecretProvider for Secrets {
    fn resolve(&self, _: &str) -> Result<SecretValue, CredentialError> {
        panic!("route resolution must use the async contract")
    }

    fn resolve_for_route<'a>(
        &'a self,
        _: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SecretValue, CredentialError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(SecretValue::new("synthetic-only-token"))
        })
    }
}

fn authorized_policy(probe: Arc<Probe>, authorized: bool, deadline: Instant) -> ModelRoutePolicy {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "authorized-session", "1");
    let registry = ModelProfileRegistry::new()
        .with_worker(OpenAiCompatibleProfile::new(
            "authorized-session",
            "1",
            "session-model",
            "http://127.0.0.1:1/v1",
            CredentialHandle::secret_provider("synthetic-only-handle"),
        ))
        .unwrap();
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [candidate.clone()],
        ModelRouteAuthorization::new(authorized.then_some(candidate.clone())),
    )
    .unwrap()
    .with_test_llm(candidate, probe)
    .unwrap();
    ModelRoutePublisher::new(snapshot).policy(deadline)
}

fn deadline() -> Instant {
    (tokio::time::Instant::now() + Duration::from_secs(1)).into_std()
}

#[tokio::test]
async fn authorization_and_route_match_precede_every_session_or_credential_operation() {
    let store = Store::new(Action::Pending(Stage::Load));
    let id = identity("private-app", "private-user");
    let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
    let broker = CredentialBroker::new().with_secret_provider(secrets.clone());
    let probe = Probe::new(vec![]);
    let error = authorized_policy(probe.clone(), false, deadline())
        .invoke_in_session(
            &request("private-task", 0),
            &broker,
            &ModelRouteCancellation::new(),
            &store,
            &id,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ModelRouteTerminalErrorKind::AuthorizationDenied
    );
    let other_binding = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new("other", "1", "other", ["unused"]))
        .unwrap()
        .bind_worker(&broker)
        .unwrap();
    let direct = request("private-task", 0)
        .invoke_in_session(
            &other_binding,
            &store,
            &id,
            deadline(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(direct.kind(), ModelInvocationErrorKind::RouteMismatch);
    assert_eq!(store.counts(), [0, 0, 0]);
    assert_eq!(secrets.0.load(Ordering::SeqCst), 0);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn session_errors_fail_closed_before_later_io_and_do_not_expose_store_details() {
    for (action, expected, events, provider_calls) in [
        (Action::Fail(Stage::Load), [1, 0, 0], 0, 0),
        (Action::Fail(Stage::User), [1, 1, 0], 0, 0),
        (Action::Fail(Stage::Assistant), [1, 1, 1], 1, 1),
        (
            Action::WrongIdentity(identity("wrong-app", "wrong-user")),
            [1, 0, 0],
            0,
            0,
        ),
    ] {
        let store = Store::new(action);
        let id = identity("private-app", "private-user");
        create(&store, &id).await;
        if let Action::WrongIdentity(other) = &store.action {
            create(&store, other).await;
        }
        let probe = Probe::new(vec![Reply::Answer]);
        let secrets = Arc::new(Secrets(AtomicUsize::new(0)));
        let error = authorized_policy(probe.clone(), true, deadline())
            .invoke_in_session(
                &request("private-task", 0),
                &CredentialBroker::new().with_secret_provider(secrets.clone()),
                &ModelRouteCancellation::new(),
                &store,
                &id,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Session);
        assert_eq!(store.counts(), expected);
        assert_eq!(probe.calls.load(Ordering::SeqCst), provider_calls);
        assert_eq!(secrets.0.load(Ordering::SeqCst), provider_calls);
        assert_eq!(
            store
                .inner
                .get_for_identity(&id)
                .await
                .unwrap()
                .events()
                .all()
                .len(),
            events
        );
        let diagnostic = format!("{error:?} {error}");
        for private in [
            "private-app",
            "private-user",
            "private-task",
            "private-store-error",
        ] {
            assert!(!diagnostic.contains(private));
        }
    }
    let store = Store::new(Action::Normal);
    let probe = Probe::new(vec![]);
    let error = policy(std::slice::from_ref(&probe), true)
        .invoke_in_session(
            &request("missing", 0),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
            &store,
            &identity("missing", "missing"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Session);
    assert_eq!(store.counts(), [1, 0, 0]);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn direct_preexisting_stop_prevents_all_session_and_model_io() {
    for cancelled in [true, false] {
        let store = Store::new(Action::Pending(Stage::Load));
        let id = identity("direct-app", "user");
        let cancellation = ModelRouteCancellation::new();
        if cancelled {
            cancellation.cancel();
        }
        let probe = Probe::new(vec![]);
        let bind = binding(probe.clone());
        let error = spec(ProviderRouteIdentity::from_binding(&bind), "stopped", 0)
            .invoke_in_session(
                &bind,
                &store,
                &id,
                if cancelled {
                    deadline()
                } else {
                    Instant::now()
                },
                &cancellation,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if cancelled {
                ModelInvocationErrorKind::Cancelled
            } else {
                ModelInvocationErrorKind::DeadlineExceeded
            }
        );
        assert_eq!(store.counts(), [0, 0, 0]);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_and_absolute_deadline_drop_each_owned_store_future() {
    for stage in [Stage::Load, Stage::User, Stage::Assistant] {
        for cancel in [true, false] {
            let store = Store::new(Action::Pending(stage));
            let id = identity("timed-app", "user");
            create(&store, &id).await;
            let cancellation = ModelRouteCancellation::new();
            let probe = Probe::new(vec![Reply::Answer]);
            // Fake binding isolates store timing from credential resolution;
            // real async broker ordering is covered above.
            let route = policy_at(std::slice::from_ref(&probe), true, deadline());
            let broker = CredentialBroker::new();
            let spec = request("timed", 0);
            let invocation = route.invoke_in_session(&spec, &broker, &cancellation, &store, &id);
            tokio::pin!(invocation);
            tokio::select! {
                result = &mut invocation => panic!("{stage:?} stage not entered: {result:?}"),
                () = store.started.notified() => (),
            }
            if cancel {
                cancellation.cancel();
            } else {
                tokio::time::advance(Duration::from_secs(2)).await;
            }
            let result = invocation.await;
            assert_eq!(
                result.unwrap_err().kind(),
                if cancel {
                    ModelRouteTerminalErrorKind::Cancelled
                } else {
                    ModelRouteTerminalErrorKind::DeadlineExceeded
                }
            );
            assert_eq!(
                store.dropped.load(Ordering::SeqCst),
                1,
                "owned I/O future must be dropped, not detached"
            );
            assert_eq!(
                store.counts(),
                match stage {
                    Stage::Load => [1, 0, 0],
                    Stage::User => [1, 1, 0],
                    Stage::Assistant => [1, 1, 1],
                }
            );
            assert_eq!(
                store
                    .inner
                    .get_for_identity(&id)
                    .await
                    .unwrap()
                    .events()
                    .all()
                    .len(),
                usize::from(stage == Stage::Assistant)
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn store_stages_share_one_absolute_budget_without_resetting_it() {
    let store = Store::new(Action::Delay(Duration::from_millis(100)));
    let id = identity("deadline-app", "user");
    create(&store, &id).await;
    let start = tokio::time::Instant::now();
    let probe = Probe::new(vec![Reply::Answer]);
    let route = policy_at(
        &[probe],
        true,
        (start + Duration::from_millis(250)).into_std(),
    );
    let error = route
        .invoke_in_session(
            &request("timed", 0),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
            &store,
            &id,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ModelRouteTerminalErrorKind::DeadlineExceeded);
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_millis(250)
    );
    assert_eq!(store.counts(), [1, 1, 1]);
    assert_eq!(
        store
            .inner
            .get_for_identity(&id)
            .await
            .unwrap()
            .events()
            .all()
            .len(),
        1
    );
}

#[tokio::test]
async fn cancellation_observed_during_load_prevents_the_next_store_operation() {
    let cancellation = ModelRouteCancellation::new();
    let store = Store::new(Action::Cancel(Stage::Load, cancellation.clone()));
    let id = identity("cancel-app", "user");
    create(&store, &id).await;
    let probe = Probe::new(vec![]);
    let error = policy(std::slice::from_ref(&probe), true)
        .invoke_in_session(
            &request("cancel", 0),
            &CredentialBroker::new(),
            &cancellation,
            &store,
            &id,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Cancelled);
    assert_eq!(store.counts(), [1, 0, 0]);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_terminal_schema_and_domain_validation_never_append_an_assistant() {
    for reply in [
        Reply::Invalid,
        Reply::WrongSchema,
        Reply::Interrupted,
        Reply::Error,
        Reply::MissingStop,
        Reply::NonStop,
        Reply::Transport,
    ] {
        let store = Store::new(Action::Normal);
        let id = identity("invalid-app", "user");
        create(&store, &id).await;
        let probe = Probe::new(vec![reply; 2]);
        let route = policy(&[probe], true);
        assert!(
            route
                .invoke_in_session(
                    &request("invalid", 1),
                    &CredentialBroker::new(),
                    &ModelRouteCancellation::new(),
                    &store,
                    &id
                )
                .await
                .is_err()
        );
        assert_eq!(store.counts(), [1, 1, 0]);
        assert_eq!(
            store
                .inner
                .get_for_identity(&id)
                .await
                .unwrap()
                .events()
                .all()
                .len(),
            1
        );
    }
    for direct in [true, false] {
        let store = Store::new(Action::Normal);
        let id = identity("domain-app", "user");
        create(&store, &id).await;
        let probe = Probe::new(vec![Reply::Answer; 2]);
        let bind = binding(probe.clone());
        let spec = spec(ProviderRouteIdentity::from_binding(&bind), "domain", 1);
        let reject = |_: &[u8]| Err(workflow_runtime::StructuredOutputError::InvalidJson);
        if direct {
            assert!(
                spec.invoke_in_session_validated(
                    &bind,
                    &store,
                    &id,
                    deadline(),
                    &ModelRouteCancellation::new(),
                    reject
                )
                .await
                .is_err()
            );
        } else {
            assert!(
                policy(&[probe], true)
                    .invoke_in_session_validated(
                        &spec,
                        &CredentialBroker::new(),
                        &ModelRouteCancellation::new(),
                        &store,
                        &id,
                        reject
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(store.counts(), [1, 1, 0]);
        assert_eq!(
            store
                .inner
                .get_for_identity(&id)
                .await
                .unwrap()
                .events()
                .all()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn a_logical_call_loads_and_appends_once_across_validation_and_route_retries() {
    let store = Store::new(Action::Normal);
    let id = identity("counted-app", "user");
    create(&store, &id).await;
    let first = Probe::new(vec![Reply::Retryable]);
    let second = Probe::new(vec![Reply::Invalid, Reply::Answer]);
    let result = policy(&[first, second], true)
        .invoke_in_session(
            &request("retry", 1),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
            &store,
            &id,
        )
        .await
        .unwrap();
    assert_eq!(result.attempts(), 2);
    assert_eq!(store.counts(), [1, 1, 1]);
    assert_eq!(
        store
            .inner
            .get_for_identity(&id)
            .await
            .unwrap()
            .events()
            .all()
            .len(),
        2
    );
}
