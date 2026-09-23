//! Public-path schedules for prefix acquisition. All fixtures run as one UID;
//! the foreign-UID cases override only descriptor metadata, not OS permissions.
use super::*;
use std::cell::{Cell, RefCell};
use std::os::unix::fs::symlink;

thread_local! {
    static SCHEDULE: RefCell<Option<Schedule>> = const { RefCell::new(None) };
    static OWNER_CHECKS: Cell<usize> = const { Cell::new(0) };
}

struct Schedule {
    staging: PathBuf,
    private: PathBuf,
    planted: bool,
    swapped: bool,
}

pub(super) fn record_owner_check() {
    OWNER_CHECKS.with(|hits| hits.set(hits.get() + 1));
}

fn plant_prefix() {
    SCHEDULE.with_borrow_mut(|slot| {
        let schedule = slot.as_mut().expect("armed schedule");
        assert!(!schedule.planted);
        fs::create_dir_all(schedule.staging.join("next/deep")).expect("late ordinary prefix");
        schedule.planted = true;
    });
    CREATE_BARRIER.with(|slot| slot.set(None));
}

// Frozen implementation: after scanning, before reopening the longest prefix.
// Fixed implementation: after opening that same child through the held parent.
// This is synchronous and bounded: no scheduler timing, sleeps, or child Cargo.
pub(super) fn prefix_acquired(path: &Path) {
    SCHEDULE.with_borrow_mut(|slot| {
        let Some(schedule) = slot else { return };
        if path != schedule.staging.join("next/deep") || schedule.swapped {
            return;
        }
        fs::rename(
            schedule.staging.join("next"),
            schedule.staging.join("saved"),
        )
        .expect("replace intermediate name after prefix acquisition");
        symlink(&schedule.private, schedule.staging.join("next")).expect("next -> Q, not Q/deep");
        schedule.swapped = true;
    });
}

fn prefix_race(manual: bool, foreign: bool) {
    use super::issue_229_creation::{Source, request, smoke, ssd_root};
    let root = ssd_root(&format!("prefix-{manual}-{foreign}"));
    let parent = root.join("P");
    fs::DirBuilder::new()
        .mode(0o1703)
        .create(&parent)
        .expect("sticky P");
    let private = root.join("Q");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .expect("private Q");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(private.join("deep"))
        .expect("Q/deep");
    let staging = parent.join("staging");
    let cache = staging.join("next/deep/cache-A");
    let input = root.join("manual-input");
    fs::write(&input, issue_229_creation::SMOKE).expect("manual input");
    assert!(
        !staging.exists(),
        "initial public validation must see a missing suffix"
    );
    SCHEDULE.with_borrow_mut(|slot| {
        *slot = Some(Schedule {
            staging: staging.clone(),
            private: private.clone(),
            planted: false,
            swapped: false,
        })
    });
    OWNER_CHECKS.with(|hits| hits.set(0));
    CREATE_BARRIER.with(|slot| slot.set(Some(plant_prefix)));
    if foreign {
        let uid = fs::metadata("/proc/self").expect("uid").uid();
        set_foreign_owner_component(Some("staging"), uid.checked_add(1).expect("foreign UID"));
    }
    let mut manifest = smoke();
    if manual {
        manifest.datasets[0].distribution = DatasetDistribution::Manual;
    }
    let source = Source;
    let result = prepare_dataset(
        &manifest,
        "smoke-fixture",
        &PrepareRequest {
            manual_path: manual.then_some(input.as_path()),
            ..request(&cache, &source)
        },
    );
    let schedule = SCHEDULE.with_borrow_mut(|slot| slot.take().expect("schedule"));
    let checks = OWNER_CHECKS.with(Cell::get);
    let private_children: Vec<_> = fs::read_dir(private.join("deep"))
        .expect("Q/deep")
        .map(|entry| entry.expect("child").file_name())
        .collect();
    let staging_children: Vec<_> = fs::read_dir(&staging)
        .expect("foreign prefix preserved")
        .map(|entry| entry.expect("child").file_name())
        .collect();
    clear_create_barrier();
    set_foreign_owner_component(None, 0);
    fs::remove_dir_all(root).expect("cleanup");
    assert!(
        schedule.planted,
        "must enter public creator after lexical prechecks"
    );
    assert!(
        private_children.is_empty(),
        "prefix reopen created children inside Q/deep: {private_children:?}"
    );
    assert_eq!(
        result.expect_err("raced prefix").kind(),
        DatasetErrorKind::Io
    );
    if foreign {
        assert_eq!(
            checks, 1,
            "reject the first simulated foreign descriptor before descent"
        );
        assert!(
            !schedule.swapped,
            "foreign prefix must be refused before reaching deep"
        );
        assert_eq!(
            staging_children,
            [std::ffi::OsString::from("next")],
            "no mutation beneath refused prefix"
        );
    } else {
        assert!(
            schedule.swapped,
            "must exercise actual scan/reopen takeover decision, not early symlink rejection"
        );
        assert_eq!(checks, 0);
    }
}

#[test]
fn prefix_reacquisition_fetch() {
    prefix_race(false, false);
}

#[test]
fn prefix_reacquisition_manual() {
    prefix_race(true, false);
}

#[test]
fn simulated_foreign_prefix_fetch() {
    prefix_race(false, true);
}

#[test]
fn simulated_foreign_prefix_manual() {
    prefix_race(true, true);
}
