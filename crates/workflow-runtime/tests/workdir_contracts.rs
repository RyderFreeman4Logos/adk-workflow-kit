use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

use workflow_runtime::{CleanupOutcome, Materialization, RunId, WorkdirErrorKind, WorkdirManager};

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        loop {
            let candidate = parent.join(format!(
                "workflow-runtime-workdir-contracts-{}-{}",
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

#[test]
fn concurrent_allocations_isolate_the_same_relative_path() {
    let base = TestBase::new();
    let manager = Arc::new(WorkdirManager::new(base.path()).expect("test base must be trusted"));
    let barrier = Arc::new(Barrier::new(2));

    let spawn = |run_id: &str, byte: u8| {
        let manager = Arc::clone(&manager);
        let barrier = Arc::clone(&barrier);
        let run_id = RunId::new(run_id.to_owned()).expect("fixture run ID must be valid");
        thread::spawn(move || {
            let workdir = manager.allocate(&run_id).expect("allocation must succeed");
            let file = workdir.work_dir().join("same-name");
            barrier.wait();
            fs::write(&file, [byte]).expect("isolated file must be writable");
            barrier.wait();
            (
                workdir.id().as_str().to_owned(),
                workdir.root().to_owned(),
                fs::read(file).expect("isolated file must be readable"),
            )
        })
    };

    let first = spawn("run-a", b'a');
    let second = spawn("run-b", b'b');
    let first = first.join().expect("first allocation thread must finish");
    let second = second.join().expect("second allocation thread must finish");

    assert_ne!(first.0, second.0);
    assert_ne!(first.1, second.1);
    assert_eq!(first.2, b"a");
    assert_eq!(second.2, b"b");
}

#[test]
fn base_must_be_an_unchanged_real_directory() {
    use std::os::unix::fs::symlink;

    let fixture = TestBase::new();
    let real_base = fixture.path().join("real-base");
    let linked_base = fixture.path().join("linked-base");
    let file_base = fixture.path().join("file-base");
    fs::create_dir(&real_base).expect("real base must be created");
    symlink(&real_base, &linked_base).expect("base symlink must be created");
    fs::write(&file_base, b"not a directory").expect("base file must be created");

    let linked_error = match WorkdirManager::new(&linked_base) {
        Ok(_) => panic!("a final-component symlink must be rejected"),
        Err(error) => error,
    };
    assert_eq!(linked_error.kind(), WorkdirErrorKind::BaseSymlink);
    let file_error = match WorkdirManager::new(&file_base) {
        Ok(_) => panic!("a regular file must be rejected"),
        Err(error) => error,
    };
    assert_eq!(file_error.kind(), WorkdirErrorKind::BaseNotDirectory);

    let manager = WorkdirManager::new(&real_base).expect("real base must be trusted");
    let original_base = fixture.path().join("original-base");
    fs::rename(&real_base, &original_base).expect("original base must be moved aside");
    fs::create_dir(&real_base).expect("replacement base must be created");
    let run_id = RunId::new(String::from("base-change")).expect("fixture run ID must be valid");
    let changed_error = match manager.allocate(&run_id) {
        Ok(_) => panic!("a replaced base must be rejected"),
        Err(error) => error,
    };
    assert_eq!(changed_error.kind(), WorkdirErrorKind::BaseChanged);
}

#[test]
fn successful_allocation_has_the_exact_private_layout() {
    use std::os::unix::fs::PermissionsExt;

    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id = RunId::new(String::from("layout")).expect("fixture run ID must be valid");
    let workdir = manager.allocate(&run_id).expect("allocation must succeed");
    let id = workdir.id().as_str();

    assert_eq!(id.len(), 32);
    assert!(
        id.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(workdir.root(), base.path().join(id));
    assert_eq!(
        workdir.manifest_path(),
        workdir.root().join("manifest.json")
    );
    assert_eq!(workdir.work_dir(), workdir.root().join("work"));
    assert_eq!(workdir.out_dir(), workdir.root().join("out"));
    assert_eq!(workdir.tmp_dir(), workdir.root().join("tmp"));
    assert_eq!(workdir.input_dir(), workdir.root().join("input"));
    assert_eq!(workdir.package_dir(), workdir.root().join("package"));
    assert_eq!(workdir.skills_dir(), workdir.root().join("skills"));
    assert_eq!(workdir.refs_dir(), workdir.root().join("refs"));

    let mut entries = fs::read_dir(workdir.root())
        .expect("root must be readable")
        .map(|entry| {
            entry
                .expect("root entry must be readable")
                .file_name()
                .into_string()
                .expect("layout names must be UTF-8")
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    assert_eq!(
        entries,
        [
            "input",
            "manifest.json",
            "out",
            "package",
            "refs",
            "skills",
            "tmp",
            "work"
        ]
    );

    for directory in [
        workdir.root().to_owned(),
        workdir.work_dir(),
        workdir.out_dir(),
        workdir.tmp_dir(),
    ] {
        let mode = fs::metadata(directory)
            .expect("layout directory metadata must be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
    for directory in [
        workdir.input_dir(),
        workdir.package_dir(),
        workdir.skills_dir(),
        workdir.refs_dir(),
    ] {
        let mode = fs::metadata(&directory)
            .expect("immutable layout directory metadata must be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o555);
        assert!(
            !directory.join("content.bin").exists(),
            "empty allocation must not materialize content"
        );
    }
    let manifest_mode = fs::metadata(workdir.manifest_path())
        .expect("manifest metadata must be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(manifest_mode, 0o600);

    let expected = format!(
        "{{\"schema_version\":1,\"workdir_id\":\"{id}\",\"paths\":{{\"work\":\"work\",\"out\":\"out\",\"tmp\":\"tmp\",\"input\":\"input\",\"package\":\"package\",\"skills\":\"skills\",\"refs\":\"refs\"}},\"hashes\":{{}}}}"
    );
    assert_eq!(
        fs::read(workdir.manifest_path()).expect("manifest must be readable"),
        expected.as_bytes()
    );
    assert!(!workdir.root().join(".manifest.json.tmp").exists());
}

#[test]
fn materialization_records_immutable_hashes_and_blocks_writes() {
    use std::os::unix::fs::PermissionsExt;

    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id = RunId::new(String::from("materialize")).expect("fixture run ID must be valid");
    let fixture = b"fixture bytes";
    let materialization = Materialization {
        input: Some(fixture.to_vec()),
        package: Some(b"package".to_vec()),
        skills: None,
        refs: None,
    };
    let workdir = manager
        .materialize(&run_id, &materialization)
        .expect("materialization must succeed");

    // Accessors exist beside work_dir().
    assert_eq!(workdir.input_dir(), workdir.root().join("input"));
    assert_eq!(workdir.package_dir(), workdir.root().join("package"));
    assert_eq!(workdir.skills_dir(), workdir.root().join("skills"));
    assert_eq!(workdir.refs_dir(), workdir.root().join("refs"));

    // Immutable dirs are created at 0o555.
    for directory in [
        workdir.input_dir(),
        workdir.package_dir(),
        workdir.skills_dir(),
        workdir.refs_dir(),
    ] {
        let mode = fs::metadata(&directory)
            .expect("immutable directory metadata must be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o555);
    }

    // A write into an immutable directory fails.
    assert!(
        fs::write(workdir.input_dir().join("tamper"), b"x").is_err(),
        "a write into a read-only immutable directory must fail"
    );

    // Materialized bytes are recorded on the manifest as SHA-256.
    let manifest = fs::read(workdir.manifest_path()).expect("manifest must be readable");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest).expect("manifest must be valid JSON");
    assert_eq!(
        manifest["paths"]["input"], "input",
        "manifest paths must record the immutable input directory"
    );
    let recorded = manifest["hashes"]["input"]
        .as_str()
        .expect("input hash must be recorded");
    let expected = sha256_hex(fixture);
    assert_eq!(
        recorded, expected,
        "recorded hash must match materialized bytes"
    );

    // Recomputing over mutated bytes diverges from the recorded hash.
    let tampered = sha256_hex(b"mutated bytes");
    assert_ne!(
        tampered, recorded,
        "a later hash check must fail on mutation"
    );
}

#[test]
fn cleanup_removes_a_materialized_tree_with_content() {
    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id =
        RunId::new(String::from("materialize-cleanup")).expect("fixture run ID must be valid");
    let materialization = Materialization {
        input: Some(b"input blob".to_vec()),
        package: Some(b"package blob".to_vec()),
        skills: Some(b"skills blob".to_vec()),
        refs: Some(b"refs blob".to_vec()),
    };
    let mut workdir = manager
        .materialize(&run_id, &materialization)
        .expect("materialization must succeed");
    let root = workdir.root().to_owned();

    assert_eq!(
        workdir
            .cleanup()
            .expect("materialized cleanup must succeed"),
        CleanupOutcome::Removed,
        "cleanup must remove a materialized tree so it does not leak at 0o555"
    );
    assert!(
        !root.exists(),
        "the materialized root must be fully removed on cleanup"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[test]
fn hostile_run_id_is_owned_but_never_used_for_filesystem_identity() {
    let fixture = TestBase::new();
    let base = fixture.path().join("base");
    fs::create_dir(&base).expect("base must be created");
    let manager = WorkdirManager::new(&base).expect("test base must be trusted");
    let hostile = String::from("../ run\t\n\0雪🚀");
    let run_id = RunId::new(hostile.clone()).expect("hostile non-empty run ID must be valid");
    let workdir = manager.allocate(&run_id).expect("allocation must succeed");

    assert_eq!(workdir.run_id().as_str(), hostile);
    for generated_path in [
        workdir.root().to_owned(),
        workdir.manifest_path(),
        workdir.work_dir(),
        workdir.out_dir(),
        workdir.tmp_dir(),
    ] {
        assert!(!generated_path.to_string_lossy().contains(&hostile));
    }
    let manifest = fs::read(workdir.manifest_path()).expect("manifest must be readable");
    assert!(
        !manifest
            .windows(hostile.len())
            .any(|window| window == hostile.as_bytes())
    );

    let original_base = fixture.path().join("original-base");
    fs::rename(&base, &original_base).expect("base must be moved aside");
    fs::create_dir(&base).expect("replacement base must be created");
    let error = match manager.allocate(&run_id) {
        Ok(_) => panic!("a replaced base must be rejected"),
        Err(error) => error,
    };
    let display = error.to_string();
    assert!(!display.contains(&hostile));
    assert!(!display.contains(&base.to_string_lossy().into_owned()));

    drop(workdir);
    fs::remove_dir_all(original_base).expect("moved test base must be removed");
}

#[test]
fn cleanup_never_reuses_an_inactive_handle() {
    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id = RunId::new(String::from("cleanup")).expect("fixture run ID must be valid");
    let mut workdir = manager.allocate(&run_id).expect("allocation must succeed");
    let root = workdir.root().to_owned();

    assert_eq!(
        workdir.cleanup().expect("first cleanup must succeed"),
        CleanupOutcome::Removed
    );
    assert!(!root.exists());

    fs::create_dir(&root).expect("replacement root must be created");
    fs::write(root.join("sentinel"), b"replacement").expect("replacement sentinel must be written");
    assert_eq!(
        workdir.cleanup().expect("repeat cleanup must be inactive"),
        CleanupOutcome::AlreadyAbsent
    );
    assert_eq!(
        fs::read(root.join("sentinel")).expect("replacement sentinel must survive"),
        b"replacement"
    );
}

#[test]
fn cleanup_confirms_external_absence_before_becoming_inactive() {
    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id =
        RunId::new(String::from("external-cleanup")).expect("fixture run ID must be valid");
    let mut workdir = manager.allocate(&run_id).expect("allocation must succeed");
    let root = workdir.root().to_owned();
    fs::remove_dir_all(&root).expect("external cleanup must remove the root");

    assert_eq!(
        workdir
            .cleanup()
            .expect("confirmed external absence must succeed"),
        CleanupOutcome::AlreadyAbsent
    );
    fs::create_dir(&root).expect("replacement root must be created");
    fs::write(root.join("sentinel"), b"replacement").expect("replacement sentinel must be written");
    assert_eq!(
        workdir.cleanup().expect("inactive cleanup must be inert"),
        CleanupOutcome::AlreadyAbsent
    );
    assert_eq!(
        fs::read(root.join("sentinel")).expect("replacement sentinel must survive"),
        b"replacement"
    );
}

#[test]
fn cleanup_rejects_a_replaced_directory_or_symlink() {
    use std::os::unix::fs::symlink;

    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");

    let directory_run =
        RunId::new(String::from("directory-swap")).expect("fixture run ID must be valid");
    let mut directory_workdir = manager
        .allocate(&directory_run)
        .expect("directory-swap allocation must succeed");
    let directory_root = directory_workdir.root().to_owned();
    let displaced_directory = base.path().join("displaced-directory-root");
    fs::rename(&directory_root, &displaced_directory).expect("root must be displaced");
    fs::create_dir(&directory_root).expect("replacement directory must be created");
    fs::write(directory_root.join("sentinel"), b"replacement")
        .expect("replacement sentinel must be written");
    let error = directory_workdir
        .cleanup()
        .expect_err("replacement directory must be rejected");
    assert_eq!(error.kind(), WorkdirErrorKind::RootChanged);
    assert!(displaced_directory.exists());
    assert_eq!(
        fs::read(directory_root.join("sentinel")).expect("replacement sentinel must survive"),
        b"replacement"
    );

    let symlink_run =
        RunId::new(String::from("symlink-swap")).expect("fixture run ID must be valid");
    let mut symlink_workdir = manager
        .allocate(&symlink_run)
        .expect("symlink-swap allocation must succeed");
    let symlink_root = symlink_workdir.root().to_owned();
    let displaced_symlink = base.path().join("displaced-symlink-root");
    let outside = base.path().join("outside-directory");
    fs::rename(&symlink_root, &displaced_symlink).expect("root must be displaced");
    fs::create_dir(&outside).expect("outside directory must be created");
    fs::write(outside.join("sentinel"), b"outside").expect("outside sentinel must be written");
    symlink(&outside, &symlink_root).expect("replacement symlink must be created");
    let error = symlink_workdir
        .cleanup()
        .expect_err("replacement symlink must be rejected");
    assert_eq!(error.kind(), WorkdirErrorKind::RootChanged);
    assert!(displaced_symlink.exists());
    assert_eq!(
        fs::read(outside.join("sentinel")).expect("outside sentinel must survive"),
        b"outside"
    );
    assert!(
        fs::symlink_metadata(symlink_root)
            .expect("replacement symlink must survive")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn cleanup_unlinks_inside_symlinks_and_preserves_other_allocations() {
    use std::os::unix::fs::symlink;

    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let first_run = RunId::new(String::from("first")).expect("fixture run ID must be valid");
    let second_run = RunId::new(String::from("second")).expect("fixture run ID must be valid");
    let mut first = manager
        .allocate(&first_run)
        .expect("first allocation must succeed");
    let mut second = manager
        .allocate(&second_run)
        .expect("second allocation must succeed");
    let outside = base.path().join("outside-sentinel");
    fs::write(&outside, b"outside").expect("outside sentinel must be written");
    symlink(&outside, first.work_dir().join("outside-link"))
        .expect("inside symlink must be created");
    fs::write(second.work_dir().join("sentinel"), b"second")
        .expect("second allocation sentinel must be written");

    assert_eq!(
        first.cleanup().expect("first cleanup must succeed"),
        CleanupOutcome::Removed
    );
    assert_eq!(
        fs::read(&outside).expect("outside sentinel must survive"),
        b"outside"
    );
    assert_eq!(
        fs::read(second.work_dir().join("sentinel"))
            .expect("second allocation sentinel must survive"),
        b"second"
    );
    assert!(second.root().exists());
    assert_eq!(
        second.cleanup().expect("second cleanup must succeed"),
        CleanupOutcome::Removed
    );
}

#[test]
fn dropping_a_handle_never_removes_its_root() {
    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id = RunId::new(String::from("drop")).expect("fixture run ID must be valid");
    let workdir = manager.allocate(&run_id).expect("allocation must succeed");
    let root = workdir.root().to_owned();

    drop(workdir);

    assert!(root.exists());
}

#[test]
fn cleanup_permission_failure_stays_active_and_maps_to_cleanup() {
    use std::os::unix::fs::PermissionsExt;

    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let run_id = RunId::new(String::from("cleanup-failure")).expect("fixture run ID must be valid");
    let mut workdir = manager.allocate(&run_id).expect("allocation must succeed");
    fs::write(workdir.work_dir().join("sentinel"), b"keep").expect("work sentinel must be written");
    fs::set_permissions(workdir.work_dir(), fs::Permissions::from_mode(0o000))
        .expect("work permissions must be restricted");

    let error = workdir
        .cleanup()
        .expect_err("unreadable non-empty work directory must fail cleanup");
    assert_eq!(error.kind(), WorkdirErrorKind::Cleanup);
    assert!(workdir.root().exists());

    fs::set_permissions(workdir.work_dir(), fs::Permissions::from_mode(0o700))
        .expect("work permissions must be restored");
    assert_eq!(
        workdir.cleanup().expect("retry cleanup must succeed"),
        CleanupOutcome::Removed
    );
}

#[test]
fn cleanup_rejects_a_replaced_base() {
    let fixture = TestBase::new();
    let base = fixture.path().join("base");
    fs::create_dir(&base).expect("base must be created");
    let manager = WorkdirManager::new(&base).expect("test base must be trusted");
    let run_id = RunId::new(String::from("base-cleanup")).expect("fixture run ID must be valid");
    let mut workdir = manager.allocate(&run_id).expect("allocation must succeed");
    let original_base = fixture.path().join("original-base");
    fs::rename(&base, &original_base).expect("original base must be moved aside");
    fs::create_dir(&base).expect("replacement base must be created");
    fs::write(base.join("sentinel"), b"replacement").expect("replacement sentinel must be written");

    let error = workdir
        .cleanup()
        .expect_err("a replaced base must be rejected");

    assert_eq!(error.kind(), WorkdirErrorKind::BaseChanged);
    assert!(original_base.join(workdir.id().as_str()).exists());
    assert_eq!(
        fs::read(base.join("sentinel")).expect("replacement sentinel must survive"),
        b"replacement"
    );
}
