use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_runtime::{
    ProductionProfile, ProductionProfileErrorKind, ProductionProfileRegistry, RunId,
    SandboxCapability,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn run_id() -> RunId {
    RunId::new(String::from("production-profile-82")).expect("valid test run ID")
}

fn root() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "workflow-runtime-production-profile-82-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("unique test root");
    let workdirs = root.join("workdirs");
    fs::create_dir(&workdirs).expect("workdir base");
    (root, workdirs)
}

#[test]
fn canary_prod_profile_82_binds_production_workdir_without_dev_fallback() {
    const CANARY_PROD_PROFILE_82: &str = "CANARY_PROD_PROFILE_82";
    let (_root, workdirs) = root();
    let profile = ProductionProfile::new(&workdirs).expect("production profile");
    let binding = profile.bind(&run_id()).expect(CANARY_PROD_PROFILE_82);
    assert_eq!(binding.profile_name(), "production");
    assert!(
        binding
            .requested()
            .contains(SandboxCapability::FilesystemRead)
    );
    assert!(
        binding
            .requested()
            .contains(SandboxCapability::FilesystemWrite)
    );
    binding
        .validate_workdir_path(binding.workdir().out_dir())
        .expect(CANARY_PROD_PROFILE_82);
}

#[test]
fn source_truth_validation_rejects_relative_and_noncanonical_paths() {
    let (root, workdirs) = root();
    let source = root.join("source");
    fs::create_dir(&source).expect("source root");
    let binding = ProductionProfile::new(&workdirs)
        .expect("production profile")
        .bind_with_source(&run_id(), &source)
        .expect("binding");

    for path in [
        std::path::PathBuf::from("../source/truth.txt"),
        source.join(".").join("truth.txt"),
    ] {
        assert_eq!(
            binding.validate_source_path(path).unwrap_err().kind(),
            ProductionProfileErrorKind::SourceTruthViolation
        );
    }
}

#[test]
fn binding_rejects_workdir_base_inside_source_before_allocation() {
    let (root, _workdirs) = root();
    let source = root.join("source");
    fs::create_dir(&source).expect("source root");
    let equal_profile = ProductionProfile::new(&source).expect("production profile");
    assert_eq!(
        match equal_profile.bind_with_source(&run_id(), &source) {
            Ok(_) => panic!("source tree must not receive production artifacts"),
            Err(error) => error,
        }
        .kind(),
        ProductionProfileErrorKind::SourceTruthViolation
    );
    let nested_workdirs = source.join("workdirs");
    fs::create_dir(&nested_workdirs).expect("nested workdir base");
    let profile = ProductionProfile::new(&nested_workdirs).expect("production profile");

    let error = match profile.bind_with_source(&run_id(), &source) {
        Ok(_) => panic!("source tree must not receive production artifacts"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        ProductionProfileErrorKind::SourceTruthViolation
    );
    assert_eq!(
        fs::read_dir(&nested_workdirs)
            .expect("nested workdir base remains readable")
            .count(),
        0
    );
}

#[test]
fn canary_acl_intact_82_rejects_source_truth_crossing_with_typed_error() {
    const CANARY_ACL_INTACT_82: &str = "CANARY_ACL_INTACT_82";
    let (root, workdirs) = root();
    let source = root.join("source");
    fs::create_dir(&source).expect("source root");
    let binding = ProductionProfile::new(&workdirs)
        .expect("production profile")
        .bind_with_source(&run_id(), &source)
        .expect(CANARY_ACL_INTACT_82);
    let error = binding
        .validate_source_path(source.join("truth.txt"))
        .expect_err(CANARY_ACL_INTACT_82);
    assert_eq!(
        error.kind(),
        ProductionProfileErrorKind::SourceTruthViolation
    );
}

#[test]
fn canary_workdir_isolate_82_rejects_host_tree_write_as_source_truth() {
    const CANARY_WORKDIR_ISOLATE_82: &str = "CANARY_WORKDIR_ISOLATE_82";
    let (root, workdirs) = root();
    let source = root.join("source");
    fs::create_dir(&source).expect("source root");
    let binding = ProductionProfile::new(&workdirs)
        .expect("production profile")
        .bind_with_source(&run_id(), &source)
        .expect(CANARY_WORKDIR_ISOLATE_82);
    let error = binding
        .validate_workdir_path(source.join("host-write"))
        .expect_err(CANARY_WORKDIR_ISOLATE_82);
    assert_eq!(
        error.kind(),
        ProductionProfileErrorKind::WorkdirIsolationBreach
    );
}

#[test]
fn workdir_validation_rejects_lexical_and_symlink_escape() {
    let (root, workdirs) = root();
    let outside = root.join("outside");
    fs::create_dir(&outside).expect("outside directory");
    let binding = ProductionProfile::new(&workdirs)
        .expect("production profile")
        .bind(&run_id())
        .expect("binding");
    std::os::unix::fs::symlink(&outside, binding.workdir().root().join("escape"))
        .expect("escape symlink");

    for path in [
        binding
            .workdir()
            .root()
            .join("..")
            .join("outside")
            .join("file"),
        binding.workdir().root().join("escape").join("file"),
    ] {
        assert_eq!(
            binding.validate_workdir_path(path).unwrap_err().kind(),
            ProductionProfileErrorKind::WorkdirIsolationBreach
        );
    }
}

#[test]
fn missing_production_profile_is_typed_and_never_falls_back() {
    let error = match ProductionProfileRegistry::default().select("production") {
        Ok(_) => panic!("missing production profile must fail closed"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        ProductionProfileErrorKind::MissingProductionProfile
    );
    assert!(!format!("{error:?}").contains("production-profile-82"));
}

#[test]
fn diagnostics_do_not_render_paths_or_payloads() {
    let (root, workdirs) = root();
    let source = root.join("SECRET_SOURCE_PATH");
    fs::create_dir(&source).expect("source root");
    let binding = ProductionProfile::new(&workdirs)
        .expect("production profile")
        .bind_with_source(&run_id(), &source)
        .expect("binding");
    let error = binding
        .validate_source_path(&source)
        .expect_err("source truth must be rejected");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("SECRET_SOURCE_PATH"));
    assert!(rendered.contains("<redacted>"));
}
