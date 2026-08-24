use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_runtime::{
    ArtifactErrorKind, ArtifactStore, FilesystemArtifactStore, InMemoryArtifactStore, PageRequest,
    RetentionPolicy,
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
fn duplicate_stage_after_teardown_does_not_claim_unreadable_visibility() {
    let (_base, mut store) = new_store(16, 8);

    store.put(b"abc").expect("fixture content must publish");
    let staged = store
        .stage(b"abc")
        .expect("identical content must stage as a duplicate");
    store.remove_all();

    assert_eq!(
        store
            .commit(staged)
            .expect_err("a deleted duplicate must not commit as visible")
            .kind(),
        ArtifactErrorKind::NotFound
    );
}

#[test]
fn duplicate_stage_commits_to_readable_existing_artifact() {
    let (_base, mut store) = new_store(16, 8);

    store.put(b"abc").expect("fixture content must publish");
    let staged = store
        .stage(b"abc")
        .expect("identical content must stage as a duplicate");
    let id = store
        .commit(staged)
        .expect("an existing duplicate must remain readable after commit");

    assert_eq!(
        store
            .read_page(&id, PageRequest::new(0, nonzero(8)))
            .expect("a successful duplicate commit must be readable")
            .bytes(),
        b"abc"
    );
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
fn uncommitted_stage_removes_its_temp_and_leaves_nothing_visible() {
    let (base, mut store) = new_store(16, 8);

    let staged = store.stage(b"abc").expect("content must stage durably");

    let before_drop = fs::read_dir(base.path())
        .expect("store root must be readable")
        .map(|entry| entry.expect("entry must be readable").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        before_drop.len(),
        1,
        "staging must prepare exactly one non-visible temporary file"
    );
    assert!(
        before_drop
            .iter()
            .all(|name| name.to_string_lossy().starts_with('.')),
        "a staged artifact must not be visible under its final name"
    );

    drop(staged);

    assert_eq!(
        fs::read_dir(base.path())
            .expect("store root must be readable")
            .count(),
        0,
        "dropping an uncommitted staged artifact must remove its temporary file"
    );
}

#[test]
fn late_path_occupant_is_not_replaced_during_commit() {
    let (base, mut store) = new_store(16, 8);
    let staged = store.stage(b"abc").expect("content must stage durably");
    let final_path = base
        .path()
        .join("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::os::unix::fs::symlink(base.path().join("late-winner"), &final_path)
        .expect("fixture must occupy the final pathname");

    assert_eq!(
        store
            .commit(staged)
            .expect_err("a late pathname occupant must not be replaced")
            .kind(),
        ArtifactErrorKind::NotFound
    );
    assert!(fs::symlink_metadata(&final_path)
        .expect("the late pathname occupant must remain")
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_dir(base.path())
            .expect("store root must be readable")
            .count(),
        1,
        "a failed commit must remove its temporary file"
    );
}

#[test]
fn existing_different_bytes_are_not_replaced_during_commit() {
    let (base, mut store) = new_store(16, 8);
    let staged = store.stage(b"abc").expect("content must stage durably");
    let final_path = base
        .path()
        .join("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    fs::write(&final_path, b"late-winner").expect("fixture must publish winner bytes");

    assert_eq!(
        store
            .commit(staged)
            .expect_err("different winner bytes must reject the loser")
            .kind(),
        ArtifactErrorKind::ContentIdCollision
    );
    assert_eq!(
        fs::read(&final_path).expect("winner bytes must remain readable"),
        b"late-winner"
    );
    assert_eq!(
        fs::read_dir(base.path())
            .expect("store root must be readable")
            .count(),
        1,
        "a rejected commit must remove its temporary file"
    );
}

#[test]
fn commit_is_the_single_atomic_visibility_transition() {
    let (base, mut store) = new_store(16, 8);

    let staged = store.stage(b"abc").expect("content must stage durably");
    let id = store
        .commit(staged)
        .expect("commit must publish the staged content");

    let entries = fs::read_dir(base.path())
        .expect("store root must be readable")
        .map(|entry| entry.expect("entry must be readable").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        entries.len(),
        1,
        "commit must leave exactly one final artifact file"
    );
    assert!(
        !entries
            .iter()
            .any(|name| name.to_string_lossy().starts_with('.')),
        "no temporary file may remain after a successful commit"
    );
    assert_eq!(
        id.as_str(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        store
            .read_page(&id, PageRequest::new(0, nonzero(8)))
            .expect("committed content must be readable")
            .bytes(),
        b"abc"
    );
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

#[test]
fn stale_memory_stage_preserves_published_retention() {
    let limit = nonzero(16);
    let mut store = InMemoryArtifactStore::new(limit, limit);
    let staged = store.stage(b"abc").expect("content must stage");
    let id = store.put(b"abc").expect("same content must publish");
    let expires_at = RetentionPolicy::ExpiresAt(std::time::SystemTime::UNIX_EPOCH);
    store
        .set_retention(&id, expires_at)
        .expect("published content must accept explicit retention");

    assert_eq!(
        store
            .commit(staged)
            .expect("stale same-content stage must commit"),
        id
    );
    assert_eq!(
        store
            .retention(&id)
            .expect("published retention must remain readable"),
        expires_at
    );
}

#[test]
fn stale_filesystem_stage_preserves_published_retention() {
    let (_base, mut store) = new_store(16, 16);
    let staged = store.stage(b"abc").expect("content must stage");
    let id = store.put(b"abc").expect("same content must publish");
    let expires_at = RetentionPolicy::ExpiresAt(std::time::SystemTime::UNIX_EPOCH);
    store
        .set_retention(&id, expires_at)
        .expect("published content must accept explicit retention");

    assert_eq!(
        store
            .commit(staged)
            .expect("stale same-content stage must commit"),
        id
    );
    assert_eq!(
        store
            .retention(&id)
            .expect("published retention must remain readable"),
        expires_at
    );
}

#[test]
fn staged_artifact_debug_redacts_content_and_temporary_paths() {
    let limit = nonzero(64);
    let mut memory = InMemoryArtifactStore::new(limit, limit);
    let memory_debug = format!(
        "{:?}",
        memory
            .stage(b"memory-content-poison")
            .expect("memory content must stage")
    );
    assert!(!memory_debug.contains("memory-content-poison"));
    assert!(memory_debug.contains("memory"));
    assert!(memory_debug.contains("byte_len"));

    let base = TestBase::new();
    let root = base.path().join("temporary-path-poison");
    let mut filesystem = FilesystemArtifactStore::new(&root, limit, limit);
    let file_debug = format!(
        "{:?}",
        filesystem
            .stage(b"file-content-poison")
            .expect("file content must stage")
    );
    assert!(!file_debug.contains("file-content-poison"));
    assert!(!file_debug.contains("temporary-path-poison"));
    assert!(file_debug.contains("file"));
    assert!(file_debug.contains("byte_len"));
}

#[test]
fn foreign_staged_artifacts_are_rejected_before_visibility_or_cross_root_moves() {
    let limit = nonzero(16);
    let mut memory_a = InMemoryArtifactStore::new(limit, limit);
    let mut memory_b = InMemoryArtifactStore::new(nonzero(3), limit);
    let memory_token = memory_a.stage(b"four").expect("A must stage permissively");
    assert_eq!(
        memory_b
            .commit(memory_token)
            .expect_err("B must reject A's token")
            .kind(),
        ArtifactErrorKind::ForeignStagedArtifact
    );

    let file_a_base = TestBase::new();
    let file_b_base = TestBase::new();
    let mut file_a = FilesystemArtifactStore::new(file_a_base.path(), limit, limit);
    let mut file_b = FilesystemArtifactStore::new(file_b_base.path(), limit, limit);
    let file_token = file_a
        .stage(b"file-poison")
        .expect("A must stage a temp file");
    assert_eq!(fs::read_dir(file_a_base.path()).expect("A root").count(), 1);
    assert_eq!(fs::read_dir(file_b_base.path()).expect("B root").count(), 0);
    assert_eq!(
        file_b
            .commit(file_token)
            .expect_err("B must not rename A's temp file")
            .kind(),
        ArtifactErrorKind::ForeignStagedArtifact
    );
    assert_eq!(fs::read_dir(file_a_base.path()).expect("A root").count(), 0);
    assert_eq!(fs::read_dir(file_b_base.path()).expect("B root").count(), 0);

    let file_token = file_a.stage(b"restage").expect("A must stage");
    assert_eq!(
        memory_b
            .commit(file_token)
            .expect_err("memory must reject a file token without panicking")
            .kind(),
        ArtifactErrorKind::ForeignStagedArtifact
    );
    assert_eq!(fs::read_dir(file_a_base.path()).expect("A root").count(), 0);
    let restaged = file_a
        .stage(b"restage")
        .expect("drop must permit restaging");
    drop(restaged);

    let file_token = memory_a.stage(b"memory-poison").expect("A must stage");
    assert_eq!(
        file_b
            .commit(file_token)
            .expect_err("filesystem must not claim foreign memory visibility")
            .kind(),
        ArtifactErrorKind::ForeignStagedArtifact
    );
    assert_eq!(fs::read_dir(file_b_base.path()).expect("B root").count(), 0);

    let duplicate_id = memory_a.put(b"duplicate").expect("A must publish once");
    let duplicate = memory_a
        .stage(b"duplicate")
        .expect("A must mint a duplicate token");
    let mut memory_c = InMemoryArtifactStore::new(limit, limit);
    assert_eq!(
        memory_c
            .commit(duplicate)
            .expect_err("foreign duplicate must not claim visibility")
            .kind(),
        ArtifactErrorKind::ForeignStagedArtifact
    );
    assert_eq!(
        memory_c
            .read_page(&duplicate_id, PageRequest::new(0, nonzero(16)))
            .expect_err("foreign duplicate must remain absent")
            .kind(),
        ArtifactErrorKind::NotFound
    );

    let staged = memory_a.stage(b"same-instance").expect("A must stage");
    let id = memory_a
        .commit(staged)
        .expect("owner must commit its token");
    assert_eq!(
        memory_a
            .read_page(&id, PageRequest::new(0, nonzero(16)))
            .expect("owner content must remain readable")
            .bytes(),
        b"same-instance"
    );
}
