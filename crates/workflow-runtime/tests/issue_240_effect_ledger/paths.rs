use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::Path,
    time::{Duration, Instant},
};

#[test]
fn lease_release_is_not_delayed_by_a_forked_pre_exec_child() {
    let root = TestDir::new();
    let path = root.0.join("ledger.db");
    let ledger = EffectLedger::open(&path).unwrap();
    let mut ready = [0; 2];
    let mut release = [0; 2];
    unsafe {
        assert_eq!(libc::pipe(ready.as_mut_ptr()), 0);
        assert_eq!(libc::pipe(release.as_mut_ptr()), 0);
    }
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(release[1]);
            libc::write(ready[1], b"ready".as_ptr().cast(), 5);
            let mut byte = [0; 1];
            libc::read(release[0], byte.as_mut_ptr().cast(), 1);
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(release[0]);
    }
    let mut child = ForkChild(pid);
    let mut readiness = libc::pollfd {
        fd: ready[0],
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut readiness, 1, 20_000) }, 1);
    let mut byte = [0; 5];
    assert_eq!(
        unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 5) },
        5
    );
    drop(ledger);
    let reopened = EffectLedger::open(&path).unwrap();
    drop(reopened);
    assert_eq!(
        unsafe { libc::write(release[1], b"x".as_ptr().cast(), 1) },
        1
    );
    unsafe {
        libc::close(ready[0]);
    }
    unsafe {
        libc::close(release[1]);
    }
    child.wait();
}

struct ForkChild(libc::pid_t);
impl ForkChild {
    fn wait(&mut self) {
        unsafe {
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}
impl Drop for ForkChild {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}

#[test]
#[ignore = "subprocess entry point, invoked only by path admission test"]
fn path_child() {
    let path = std::env::var("ISSUE_240_LEDGER").unwrap();
    assert!(
        matches!(EffectLedger::open(&path), Err(LedgerError::InvalidInput)),
        "hard-linked database must be rejected at admission, not by SQLite"
    );
}

#[test]
fn hard_linked_database_is_rejected_in_two_processes_before_sqlite_mutation() {
    let root = TestDir::new();
    let request = request();
    drop(approved(&root, &request));
    let original = root.0.join("ledger.db");
    let alias = root.0.join("alias.db");
    fs::hard_link(&original, &alias).unwrap();
    assert_eq!(
        fs::metadata(&original).unwrap().ino(),
        fs::metadata(&alias).unwrap().ino()
    );
    assert_eq!(fs::metadata(&original).unwrap().nlink(), 2);
    let before = fs::read(&original).unwrap();
    // All links are stable before either child starts; no replacement race.
    let mut children = [&original, &alias].map(|path| {
        Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "paths::path_child", "--ignored", "--nocapture"])
                .env("ISSUE_240_LEDGER", path)
                .spawn()
                .unwrap(),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let results = children.each_mut().map(|child| {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "bounded admission child");
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    assert!(results.iter().all(|status| status.success()), "{results:?}");
    assert_eq!(fs::read(&original).unwrap(), before);
    for name in ["ledger.db", "alias.db"] {
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(
                !root.0.join(format!("{name}{suffix}")).exists(),
                "no SQLite sidecar: {name}{suffix}"
            );
        }
    }
}

#[test]
fn hard_linked_lease_and_each_sidecar_are_rejected_without_mutation() {
    for name in [
        "ledger.effect-lock",
        "ledger.db-wal",
        "ledger.db-shm",
        "ledger.db-journal",
    ] {
        let root = TestDir::new();
        drop(root.ledger());
        let database = fs::read(root.0.join("ledger.db")).unwrap();
        let path = root.0.join(name);
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let alias = root.0.join("linked-file");
        fs::hard_link(&path, &alias).unwrap();
        let bytes = fs::read(&alias).unwrap();
        assert!(
            matches!(
                EffectLedger::open(root.0.join("ledger.db")),
                Err(LedgerError::InvalidInput)
            ),
            "{name}"
        );
        assert_eq!(fs::read(&alias).unwrap(), bytes, "{name}");
        assert_eq!(
            fs::read(root.0.join("ledger.db")).unwrap(),
            database,
            "{name}"
        );
    }
}

#[test]
fn configured_directory_symlink_preserves_shared_ownership_and_history() {
    let root = TestDir::new();
    let target = root.0.join("private");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let configured = root.0.join("configured");
    symlink("private", &configured).unwrap();
    let request = request();
    let mut ledger = EffectLedger::open(configured.join("ledger.db")).unwrap();
    ledger.propose(&request).unwrap();
    assert!(matches!(
        EffectLedger::open(target.join("ledger.db")),
        Err(LedgerError::Busy)
    ));
    drop(ledger);
    let mut ledger = EffectLedger::open(target.join("ledger.db")).unwrap();
    ledger
        .approve(&request, request.approval_digest(), "operator", 10)
        .unwrap();
    assert!(matches!(
        EffectLedger::open(configured.join("ledger.db")),
        Err(LedgerError::Busy)
    ));
    drop(ledger);
    let reopened = EffectLedger::open(configured.join("ledger.db")).unwrap();
    assert_eq!(
        reopened.history(&request).unwrap(),
        vec![EffectState::Proposed, EffectState::Approved]
    );
    assert_eq!(fs::read_link(&configured).unwrap(), Path::new("private"));
    assert_eq!(
        fs::metadata(&target).unwrap().dev(),
        fs::metadata(configured.join("ledger.db")).unwrap().dev()
    );
}

#[test]
fn unsafe_target_or_ancestor_is_rejected_through_both_directory_spellings() {
    for unsafe_part in ["target", "ancestor"] {
        let root = TestDir::new();
        let ancestor = root.0.join("ancestor");
        let target = ancestor.join("private");
        fs::create_dir(&ancestor).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let configured = root.0.join("configured");
        symlink(&target, &configured).unwrap();
        let unsafe_path = if unsafe_part == "target" {
            &target
        } else {
            &ancestor
        };
        fs::set_permissions(unsafe_path, fs::Permissions::from_mode(0o770)).unwrap();
        for parent in [&configured, &target] {
            assert!(
                matches!(
                    EffectLedger::open(parent.join("ledger.db")),
                    Err(LedgerError::InvalidInput)
                ),
                "{unsafe_part}: {parent:?}"
            );
        }
        assert!(!target.join("ledger.db").exists());
        assert_eq!(fs::read_link(&configured).unwrap(), target);
    }
}

#[test]
fn file_and_sidecar_symlinks_stay_rejected_under_a_directory_alias() {
    for name in [
        "ledger.db",
        "ledger.effect-lock",
        "ledger.db-wal",
        "ledger.db-shm",
        "ledger.db-journal",
    ] {
        for dangling in [false, true] {
            let root = TestDir::new();
            let target = root.0.join("private");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            let configured = root.0.join("configured");
            symlink(&target, &configured).unwrap();
            let victim = root.0.join("victim");
            if !dangling {
                fs::write(&victim, b"unchanged").unwrap();
                fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            }
            symlink(&victim, target.join(name)).unwrap();
            for parent in [&configured, &target] {
                assert!(
                    matches!(
                        EffectLedger::open(parent.join("ledger.db")),
                        Err(LedgerError::InvalidInput)
                    ),
                    "{name}"
                );
            }
            if dangling {
                assert!(!victim.exists());
            } else {
                assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
            }
        }
    }
}
