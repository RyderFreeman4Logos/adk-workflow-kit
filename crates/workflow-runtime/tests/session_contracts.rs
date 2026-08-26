use std::collections::HashMap;

use workflow_runtime::{RunSessionIds, SessionId, SessionIdentityError, SessionRole};

#[test]
fn allocation_returns_distinct_role_ids() {
    let ids = RunSessionIds::allocate().expect("session identities must allocate");

    assert_ne!(ids.id(SessionRole::Producer), ids.id(SessionRole::Reviewer),);
}

#[test]
fn allocator_has_no_run_id_input_and_ids_are_path_safe() {
    let allocate: fn() -> Result<RunSessionIds, SessionIdentityError> = RunSessionIds::allocate;
    let ids = allocate().expect("session identities must allocate");

    for role in [SessionRole::Producer, SessionRole::Reviewer] {
        let id = ids.id(role).as_str();
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

/// This in-memory harness proves only that distinct identity keys partition histories.
#[test]
fn identity_keys_partition_in_memory_histories() {
    let allocation_a = RunSessionIds::allocate().expect("first session identities must allocate");
    let allocation_b = RunSessionIds::allocate().expect("second session identities must allocate");
    let producer_a = allocation_a.id(SessionRole::Producer).clone();
    let reviewer_a = allocation_a.id(SessionRole::Reviewer).clone();
    let producer_b = allocation_b.id(SessionRole::Producer).clone();
    let reviewer_b = allocation_b.id(SessionRole::Reviewer).clone();
    let event = String::from("producer-A event");
    let mut histories: HashMap<SessionId, Vec<String>> = HashMap::new();

    histories
        .entry(producer_a.clone())
        .or_default()
        .push(event.clone());

    assert_eq!(histories.get(&producer_a), Some(&vec![event.clone()]));
    for other in [&reviewer_a, &producer_b, &reviewer_b] {
        assert!(
            !histories
                .get(other)
                .is_some_and(|history| history.contains(&event))
        );
    }
}
