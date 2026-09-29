use super::*;

#[test]
fn expired_pending_transaction_reconciles_after_snapshot_absence() {
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
    drop(ledger);
    let mut ledger = root.ledger();
    // The service's writer is alive with an uncommitted CAS transaction, while
    // independent authoritative reads still see no committed key/counter update.
    let stats = service.stats();
    assert_eq!(stats["count"], 0);
    assert_eq!(stats["value"], 0);
    assert_eq!(stats["applies"], 1);
    assert_eq!(
        ledger.advance(&request, &mut executors, 2000).unwrap(),
        EffectState::Indeterminate
    );
    assert_eq!(service.stats()["lookups"], 2);
    release.send(()).unwrap();
    call(service.address, json!({"op":"settle"}));
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
            EffectState::Verified
        ]
    );
    let stats = service.stats();
    assert_eq!(stats["count"], 1);
    assert_eq!(stats["value"], 1);
    assert_eq!(stats["applies"], 1);
    drop(ledger);
    assert_eq!(
        root.ledger()
            .advance(&request, &mut executors, 3000)
            .unwrap(),
        EffectState::Verified
    );
    assert_eq!(service.stats(), stats);
}

#[test]
fn expired_absence_without_a_final_fence_never_dispatches_or_terminalizes() {
    let root = TestDir::new();
    let service = FakeService::start(&root.0, "");
    let request = request();
    let mut executors = registry(service.address);
    let mut ledger = approved(&root, &request);
    assert_eq!(
        ledger.advance(&request, &mut executors, 10).unwrap(),
        EffectState::Started
    );
    drop(ledger);
    // Here there really is no remote request. Started alone cannot prove that:
    // it is also the durable state left by a client killed during dispatch.
    for now in [1000, 2000] {
        let mut ledger = root.ledger();
        assert_eq!(
            ledger.advance(&request, &mut executors, now).unwrap(),
            EffectState::Indeterminate
        );
    }
    let stats = service.stats();
    assert_eq!(stats["count"], 0);
    assert_eq!(stats["value"], 0);
    assert_eq!(stats["applies"], 0);
    assert_eq!(stats["lookups"], 2);
}
