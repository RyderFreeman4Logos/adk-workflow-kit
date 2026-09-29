use super::*;

#[test]
fn cas_rejection_after_absent_lookup_cannot_hide_prior_commit() {
    rejected_retry(true);
}

#[test]
fn rejection_and_fresh_absence_cannot_fence_a_pending_request() {
    rejected_retry(false);
}

fn rejected_retry(commit_first: bool) {
    let root = TestDir::new();
    let service = FakeService::start(&root.0, "before-remote-commit");
    let request = request();
    let mut executors = registry(service.address);
    let mut ledger = approved(&root, &request);
    assert_eq!(
        ledger.advance(&request, &mut executors, 10).unwrap(),
        EffectState::Started
    );
    assert_eq!(
        ledger.advance(&request, &mut executors, 10).unwrap(),
        EffectState::Indeterminate
    );
    let release = service.paused("before-remote-commit");
    let stats = service.stats();
    assert_eq!(stats["count"], 0);
    assert_eq!(stats["value"], 0);
    assert_eq!(stats["applies"], 1);
    drop(ledger);
    let mut ledger = root.ledger();
    call(
        service.address,
        json!({"op":"retry-mode","commit_first":commit_first}),
    );
    let rejected = if commit_first {
        let address = service.address;
        std::thread::scope(|scope| {
            let retry = scope.spawn(|| {
                ledger
                    .advance(&request, &mut registry(address), 10)
                    .unwrap()
            });
            let lookup = service.paused("after-absent");
            // A commits after B's truthful lookup snapshot but before B's CAS.
            release.send(()).unwrap();
            lookup.send(()).unwrap();
            retry.join().unwrap()
        })
    } else {
        ledger.advance(&request, &mut executors, 10).unwrap()
    };
    let stats = service.stats();
    assert_eq!(stats["rejections"], 1, "B really was rejected, not unknown");
    assert_eq!(stats["applies"], 2);
    assert_eq!(stats["count"], i64::from(commit_first));
    assert_eq!(stats["value"], i64::from(commit_first));
    assert_eq!(rejected, EffectState::Indeterminate);
    drop(ledger);
    let mut ledger = root.ledger();
    if !commit_first {
        // Even a fresh, independent exact-key lookup after B's rejection cannot
        // rule out A's future commit. Expiry must stop dispatch, not reconciliation.
        assert_eq!(
            call(
                service.address,
                json!({"op":"lookup","key":request.effect_key()})
            )["result"],
            "absent"
        );
        assert_eq!(
            ledger.advance(&request, &mut executors, 2000).unwrap(),
            EffectState::Indeterminate
        );
        assert_eq!(service.stats()["count"], 0);
        release.send(()).unwrap();
        call(service.address, json!({"op":"settle"}));
    }
    call(service.address, json!({"op":"disarm"}));
    assert_eq!(
        call(
            service.address,
            json!({"op":"lookup","key":request.effect_key()})
        )["result"],
        "committed"
    );
    assert_eq!(
        ledger.advance(&request, &mut executors, 2000).unwrap(),
        EffectState::Committed
    );
    assert_eq!(
        ledger.advance(&request, &mut executors, 2000).unwrap(),
        EffectState::Verified
    );
    assert_eq!(
        ledger.history(&request).unwrap(),
        vec![
            EffectState::Proposed,
            EffectState::Approved,
            EffectState::Started,
            EffectState::Indeterminate,
            EffectState::Committed,
            EffectState::Verified,
        ]
    );
    let stats = service.stats();
    assert_eq!(stats["count"], 1);
    assert_eq!(stats["value"], 1);
    assert_eq!(stats["applies"], 2);
    assert_eq!(stats["rejections"], 1);
    drop(ledger);
    assert_eq!(
        root.ledger()
            .advance(&request, &mut executors, 3000)
            .unwrap(),
        EffectState::Verified
    );
    assert_eq!(service.stats(), stats, "verified replay does no remote IO");
}
