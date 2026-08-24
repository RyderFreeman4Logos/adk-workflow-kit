use workflow_review::{
    validate_package, PackageArchiveEntry, PackageFile, PackageManifest, PackageValidationError,
};

const CANARY_PATH_56: &str = "../CANARY_PATH_56";
const CANARY_HASH_56: &[u8] = b"CANARY_HASH_56";
const CANARY_SECRET_56: &[u8] = b"token = \"CANARY_SECRET_56\"";
const WRONG_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn manifest(path: &str) -> PackageManifest {
    PackageManifest::new(vec![PackageFile::new(path.into(), WRONG_DIGEST.into())])
}

fn entry<'a>(path: &'a str, bytes: &'a [u8]) -> PackageArchiveEntry<'a> {
    PackageArchiveEntry::new(path, bytes, false)
}

fn assert_secret_redacted(error: &PackageValidationError) {
    for rendered in [
        error.to_string(),
        format!("{error:?}"),
        serde_json::to_string(error).unwrap(),
    ] {
        assert!(
            !rendered.contains("CANARY_SECRET_56"),
            "leaked diagnostic: {rendered}"
        );
    }
}

#[test]
fn escaped_archive_path_is_rejected_with_typed_error() {
    let error = validate_package(
        &manifest(CANARY_PATH_56),
        &[entry(CANARY_PATH_56, b"workflow")],
    )
    .expect_err("escaped archive paths must fail closed");

    assert_eq!(error, PackageValidationError::PathEscape);
}

#[test]
fn content_hash_mismatch_is_rejected_with_typed_error() {
    let error = validate_package(
        &manifest("workflow.toml"),
        &[entry("workflow.toml", CANARY_HASH_56)],
    )
    .expect_err("content hash mismatches must fail closed");

    assert_eq!(error, PackageValidationError::HashMismatch);
}

#[test]
fn secret_scan_rejects_and_redacts_the_secret_canary() {
    let error = validate_package(
        &manifest("config.toml"),
        &[entry("config.toml", CANARY_SECRET_56)],
    )
    .expect_err("credential-shaped values must fail closed");

    assert_eq!(error, PackageValidationError::SecretDetected);
    assert_secret_redacted(&error);
}
