use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_runtime::{
    ArtifactErrorKind, ArtifactStore, FilesystemArtifactStore, PageRequest, RetentionPolicy,
};

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        loop {
            let candidate = parent.join(format!(
                "workflow-runtime-fs-artifact-contracts-{}-{}",
                std::process::id(),
                NEXT_BASE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Self(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("test base must be created: {error}"),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestBase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test limits must be positive")
}

fn new_store(max_content_bytes: u64, max_page_bytes: u64) -> (TestBase, FilesystemArtifactStore) {
    let base = TestBase::new();
    let store = FilesystemArtifactStore::new(
        base.path(),
        nonzero(max_content_bytes),
        nonzero(max_page_bytes),
    );
    (base, store)
}

#[test]
fn content_ids_are_sha256_of_bytes_and_deduplicate_on_disk() {
    let (_base, mut store) = new_store(16, 8);

    let id = store.put(b"abc").expect("small content must be accepted");
    let repeated = store
        .put(b"abc")
        .expect("identical content must deduplicate");

    assert_eq!(
        id.as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(repeated, id);
}

#[test]
fn atomic_put_leaves_no_temp_file_on_success() {
    let (base, mut store) = new_store(16, 8);
    store.put(b"abc").expect("content must be accepted");

    let entries = fs::read_dir(base.path())
        .expect("store root must be readable")
        .map(|entry| entry.expect("entry must be readable").file_name())
        .collect::<Vec<_>>();

    assert_eq!(
        entries.len(),
        1,
        "a successful put must leave exactly one readable artifact file"
    );
    assert!(
        !entries
            .iter()
            .any(|name| name.to_string_lossy().starts_with('.')),
        "no temp file may remain after a successful put"
    );
}

#[test]
fn pages_are_bounded_by_store_limit_and_repeatable() {
    let (_base, mut store) = new_store(16, 3);
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

    let terminal_page = store
        .read_page(&id, PageRequest::new(6, nonzero(8)))
        .expect("the terminal offset must be valid");
    assert_eq!(terminal_page.next_offset(), None);
    assert_eq!(terminal_page.into_bytes(), b"");
}

#[test]
fn teardown_makes_later_reads_not_found() {
    let (base, mut store) = new_store(16, 8);
    let id = store.put(b"abc").expect("content must be accepted");

    // Explicit impl-local cleanup of the store directory.
    store.remove_all();
    drop(base);

    assert_eq!(
        store
            .read_page(&id, PageRequest::new(0, nonzero(8)))
            .expect_err("reads after teardown must fail")
            .kind(),
        ArtifactErrorKind::NotFound
    );
}

#[test]
fn empty_and_oversized_content_fail_closed_with_stable_kinds() {
    let (_base, mut store) = new_store(3, 3);

    let empty = store
        .put(b"")
        .expect_err("empty content must be rejected before hashing");
    assert_eq!(empty.kind(), ArtifactErrorKind::EmptyContent);

    let oversized = store
        .put(b"four")
        .expect_err("content above the configured limit must be rejected");
    assert_eq!(oversized.kind(), ArtifactErrorKind::ContentTooLarge);
}

#[test]
fn hostile_bytes_remain_opaque_and_missing_ids_are_not_found() {
    let (_base, mut store) = new_store(16, 8);
    let id = store
        .put(b"../\0\xff")
        .expect("opaque bytes must be accepted without path interpretation");

    assert_eq!(
        store
            .read_page(&id, PageRequest::new(0, nonzero(8)))
            .expect("opaque bytes must be readable")
            .bytes(),
        b"../\0\xff"
    );

    let (other_base, mut other_store) = new_store(16, 8);
    let missing = other_store.put(b"other").expect("fixture must be valid");
    assert_eq!(
        store
            .read_page(&missing, PageRequest::new(0, nonzero(8)))
            .expect_err("another store's ID must not be readable")
            .kind(),
        ArtifactErrorKind::NotFound
    );
    drop(other_base);
}

#[test]
fn retention_is_explicit_typed_metadata_not_an_implicit_sweeper() {
    let (_base, mut store) = new_store(16, 8);
    let id = store.put(b"abc").expect("content must be accepted");

    assert_eq!(
        store
            .retention(&id)
            .expect("new content must have retention"),
        RetentionPolicy::Retain
    );

    let expired = RetentionPolicy::ExpiresAt(std::time::SystemTime::UNIX_EPOCH);
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
    assert_eq!(
        store
            .retention(&id)
            .expect("retention metadata must be readable"),
        expired
    );
}
