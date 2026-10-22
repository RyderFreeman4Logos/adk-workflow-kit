use super::*;
use std::{
    os::unix::fs::symlink,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(super) struct TestRoot(pub(super) PathBuf);
impl TestRoot {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bounded-artifact-{}-{}",
            std::process::id(),
            next_capability()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limit(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

fn store(root: &Path, cap: u64) -> FilesystemArtifactStore {
    FilesystemArtifactStore::new(root, limit(cap), limit(cap))
}

fn temporary(staged: &StagedArtifact) -> PathBuf {
    match staged.state.as_ref().unwrap() {
        StagedState::File { temporary } => temporary.clone(),
        _ => panic!("filesystem token"),
    }
}

#[test]
fn existing_files_obey_content_cap_at_every_read_boundary() {
    let root = TestRoot::new();
    let mut store = store(&root.0, 4);
    let bytes = b"1234";
    let id = ArtifactId(encode_hex(&Sha256::digest(bytes)));
    let path = store.path_for(&id);
    let oversized_id = ArtifactId(encode_hex(&Sha256::digest(b"12345")));
    fs::write(store.path_for(&oversized_id), b"12345").unwrap();
    let read = store
        .read_page(&oversized_id, PageRequest::new(0, limit(1)))
        .err()
        .map(|error| error.kind());
    fs::write(&path, b"12345").unwrap();
    let stage = store.stage(bytes).err().map(|error| error.kind());
    assert_eq!(fs::read(&path).unwrap(), b"12345");
    fs::remove_file(&path).unwrap();
    let staged = store.stage(bytes).unwrap();
    let temp = temporary(&staged);
    fs::write(&path, b"12345").unwrap();
    let collision_final = store.commit(staged).err().map(|error| error.kind());
    assert!(!temp.exists(), "failed token cleans up its temporary file");
    assert_eq!(fs::read(&path).unwrap(), b"12345");
    fs::remove_file(&path).unwrap();
    let staged = store.stage(bytes).unwrap();
    let temp = temporary(&staged);
    fs::write(&temp, b"12345").unwrap();
    fs::write(&path, bytes).unwrap();
    let collision_temp = store.commit(staged).err().map(|error| error.kind());
    assert!(!temp.exists());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        [read, stage, collision_final, collision_temp],
        [Some(ArtifactErrorKind::ContentTooLarge); 4],
        "read_page, stage, collision final, collision temporary"
    );
}

#[test]
fn exact_limits_unbounded_configuration_and_symlinks_preserve_content() {
    let root = TestRoot::new();
    let real = root.0.join("real");
    fs::create_dir(&real).unwrap();
    let alias = root.0.join("alias");
    symlink(&real, &alias).unwrap();
    let mut store = store(&alias, 4);
    let id = store.put(b"1234").unwrap();
    let staged = store.stage(b"1234").unwrap();
    assert_eq!(store.commit(staged).unwrap(), id);
    let target = root.0.join("content");
    fs::rename(store.path_for(&id), &target).unwrap();
    symlink(&target, store.path_for(&id)).unwrap();
    let staged = store.stage(b"1234").unwrap();
    assert_eq!(store.commit(staged).unwrap(), id);
    assert_eq!(
        store.read_page(&id, PageRequest::new(1, limit(2))).unwrap(),
        ArtifactPage {
            bytes: b"23".to_vec(),
            next_offset: Some(3)
        }
    );
    let huge = FilesystemArtifactStore::new(&alias, limit(u64::MAX), limit(u64::MAX));
    assert_eq!(
        huge.read_page(&id, PageRequest::new(0, limit(u64::MAX)))
            .unwrap()
            .bytes(),
        b"1234"
    );
    fs::remove_file(&target).unwrap();
    assert_eq!(
        huge.read_page(&id, PageRequest::new(0, limit(1)))
            .unwrap_err()
            .kind(),
        ArtifactErrorKind::NotFound
    );
    assert!(
        store.stage(b"1234").is_ok(),
        "dangling symlink still reads as NotFound during staging"
    );
}

// The parent owns and reaps each bounded child even when the old reader blocks
// opening a FIFO. No writer is ever opened to make a blocked read succeed.
struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            child.wait().unwrap();
        }
    }
}

fn nonregular_read(root: &Path, case: &str, fifo: bool) {
    let mut store = store(root, 4);
    let id = ArtifactId(encode_hex(&Sha256::digest(b"1234")));
    let mut staged = None;
    let path = if case == "collision_temporary" {
        let token = store.stage(b"1234").unwrap();
        fs::write(store.path_for(&id), b"1234").unwrap();
        let path = temporary(&token);
        fs::remove_file(&path).unwrap();
        staged = Some(token);
        path
    } else {
        if case == "collision_final" {
            staged = Some(store.stage(b"1234").unwrap());
        }
        store.path_for(&id)
    };
    if fifo {
        assert!(
            Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
    } else {
        fs::create_dir(&path).unwrap();
    }
    let kind = match case {
        "read" => store
            .read_page(&id, PageRequest::new(0, limit(1)))
            .unwrap_err()
            .kind(),
        "stage" => store.stage(b"1234").unwrap_err().kind(),
        _ => store.commit(staged.unwrap()).unwrap_err().kind(),
    };
    assert_eq!(kind, ArtifactErrorKind::Io);
    if case != "collision_temporary" {
        assert!(path.exists(), "rejected final occupant is preserved");
    } else if fifo {
        assert!(!path.exists(), "failed token cleans up its FIFO temporary");
    }
}

#[test]
fn nonregular_files_fail_without_waiting_for_a_writer() {
    const CASE: &str = "WORKFLOW_ARTIFACT_FIFO_CASE";
    const ROOT: &str = "WORKFLOW_ARTIFACT_FIFO_ROOT";
    if let Ok(case) = std::env::var(CASE) {
        nonregular_read(Path::new(&std::env::var(ROOT).unwrap()), &case, true);
        return;
    }
    let mut outcomes = Vec::new();
    for case in ["read", "stage", "collision_final", "collision_temporary"] {
        let directory_root = TestRoot::new();
        nonregular_read(&directory_root.0, case, false);
        let root = TestRoot::new();
        let mut child = OwnedChild(Some(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "artifact::bounded_read_tests::nonregular_files_fail_without_waiting_for_a_writer", "--nocapture"])
            .env(CASE, case).env(ROOT, &root.0)
            .stdin(Stdio::null()).stdout(Stdio::null()).spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(2);
        let success = loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                child.0.take();
                break status.success();
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        drop(child); // kill + actual wait on the RED path, before root cleanup
        outcomes.push((case, success));
    }
    assert!(
        outcomes.iter().all(|(_, success)| *success),
        "FIFO outcomes: {outcomes:?}"
    );
}
