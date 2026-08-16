use std::{error::Error, num::NonZeroU64, time::SystemTime};

use workflow_runtime::{
    ArtifactErrorKind, ArtifactStore, InMemoryArtifactStore, PageRequest, RetentionPolicy,
};

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test limits must be positive")
}

fn new_store(max_content_bytes: u64, max_page_bytes: u64) -> InMemoryArtifactStore {
    InMemoryArtifactStore::new(nonzero(max_content_bytes), nonzero(max_page_bytes))
}

#[test]
fn content_ids_are_sha256_of_bytes_and_have_no_run_or_path_input() {
    let mut first_store = new_store(16, 8);
    let mut second_store = new_store(16, 8);

    let first_id = first_store
        .put(b"abc")
        .expect("small content must be accepted");
    let repeated_id = first_store
        .put(b"abc")
        .expect("identical content must deduplicate");
    let second_id = second_store
        .put(b"abc")
        .expect("the same content must work in another store");

    assert_eq!(
        first_id.as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(repeated_id, first_id);
    assert_eq!(second_id, first_id);
}

#[test]
fn pages_are_bounded_by_store_limit_and_repeatable() {
    let mut store = new_store(16, 3);
    let id = store.put(b"abcdef").expect("content must be accepted");
    let request = PageRequest::new(0, nonzero(8));

    let page = store
        .read_page(&id, request)
        .expect("stored content must be readable");
    assert_eq!(page.bytes(), b"abc");
    assert_eq!(page.next_offset(), Some(3));
    assert_eq!(
        store
            .read_page(&id, request)
            .expect("the same request must remain readable"),
        page
    );

    let short_page = store
        .read_page(&id, PageRequest::new(1, nonzero(1)))
        .expect("a smaller request limit must be honored");
    assert_eq!(short_page.bytes(), b"b");
    assert_eq!(short_page.next_offset(), Some(2));

    let terminal_page = store
        .read_page(&id, PageRequest::new(6, nonzero(8)))
        .expect("the terminal offset must be valid");
    assert_eq!(terminal_page.next_offset(), None);
    assert_eq!(terminal_page.into_bytes(), b"");
}

#[test]
fn retention_is_explicit_typed_metadata_not_an_implicit_sweeper() {
    let mut store = new_store(16, 8);
    let id = store.put(b"abc").expect("content must be accepted");

    assert_eq!(
        store
            .retention(&id)
            .expect("new content must have retention"),
        RetentionPolicy::Retain
    );

    let expired = RetentionPolicy::ExpiresAt(SystemTime::UNIX_EPOCH);
    store
        .set_retention(&id, expired)
        .expect("past expiration metadata must be accepted");
    assert_eq!(
        store
            .read_page(&id, PageRequest::new(0, nonzero(8)))
            .expect("expiration metadata must not delete or block reads")
            .bytes(),
        b"abc"
    );

    let repeated_id = store
        .put(b"abc")
        .expect("identical content must still deduplicate");
    assert_eq!(repeated_id, id);
    assert_eq!(
        store
            .retention(&id)
            .expect("deduplicated content must retain metadata"),
        expired
    );
}

#[test]
fn empty_and_oversized_content_fail_closed_with_stable_kinds() {
    let mut store = new_store(3, 3);

    let empty = store
        .put(b"")
        .expect_err("empty content must be rejected before hashing");
    let empty_error: &dyn Error = &empty;
    assert_eq!(empty.kind(), ArtifactErrorKind::EmptyContent);
    assert_eq!(
        empty_error.to_string(),
        "artifact content must not be empty"
    );

    let oversized = store
        .put(b"four")
        .expect_err("content above the configured limit must be rejected");
    let oversized_error: &dyn Error = &oversized;
    assert_eq!(oversized.kind(), ArtifactErrorKind::ContentTooLarge);
    assert_eq!(
        oversized_error.to_string(),
        "artifact content exceeds the configured limit"
    );
}

#[test]
fn hostile_bytes_remain_opaque_and_invalid_page_bounds_are_typed() {
    let mut store = new_store(16, 3);
    let id = store
        .put(b"../\0\xff")
        .expect("opaque bytes must be accepted without path interpretation");

    let first_page = store
        .read_page(&id, PageRequest::new(0, nonzero(8)))
        .expect("opaque bytes must be readable");
    assert_eq!(first_page.bytes(), b"../");
    assert_eq!(first_page.next_offset(), Some(3));
    let second_page = store
        .read_page(&id, PageRequest::new(3, nonzero(8)))
        .expect("opaque bytes must preserve NUL and invalid UTF-8");
    assert_eq!(second_page.bytes(), b"\0\xff");
    assert_eq!(second_page.next_offset(), None);

    let bounds_error = store
        .read_page(&id, PageRequest::new(6, nonzero(1)))
        .expect_err("offsets beyond content must fail closed");
    assert_eq!(bounds_error.kind(), ArtifactErrorKind::PageOutOfBounds);
    assert_eq!(
        bounds_error.to_string(),
        "artifact page offset is out of bounds"
    );

    let mut other_store = new_store(16, 3);
    let missing_id = other_store
        .put(b"other")
        .expect("the cross-store ID fixture must be valid");
    for error in [
        store
            .read_page(&missing_id, PageRequest::new(0, nonzero(1)))
            .expect_err("another store's ID must not be readable"),
        store
            .set_retention(&missing_id, RetentionPolicy::Retain)
            .expect_err("another store's ID must not receive metadata"),
        store
            .retention(&missing_id)
            .expect_err("another store's ID must not have metadata"),
    ] {
        assert_eq!(error.kind(), ArtifactErrorKind::NotFound);
        assert_eq!(error.to_string(), "artifact was not found");
    }
}
