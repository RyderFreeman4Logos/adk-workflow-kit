use super::{NEXT_PRODUCTION_ROOT, Ordering, remove_production_root};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

#[path = "../../../workflowctl/tests/support/owned_tree.rs"]
mod owned_tree;

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).expect("fixture identity");
    (metadata.dev(), metadata.ino())
}

struct Fixture {
    path: PathBuf,
    identity: (u64, u64),
}

impl Fixture {
    fn new(label: &str) -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
            .join("tmp")
            .join(format!(
                "issue-317-cleanup-{label}-{}-{}",
                std::process::id(),
                NEXT_PRODUCTION_ROOT.fetch_add(1, Ordering::Relaxed),
            ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("exclusive owned fixture");
        let identity = identity(&path);
        Self { path, identity }
    }

    fn finish(self) {
        assert_eq!(identity(&self.path), self.identity);
        owned_tree::remove_dir_all(&self.path).expect("owned fixture cleanup");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        // Recover only our exclusive container, never a replacement or symlink target.
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != self.identity {
            return;
        }
        if std::thread::panicking() {
            eprintln!("cleanup fixture recovery follows the recorded test failure");
        }
        if owned_tree::remove_dir_all(&self.path).is_err() {
            eprintln!("owned cleanup fixture recovery failed");
        }
    }
}

#[test]
fn production_root_cleanup_restores_directory_access_before_descent() {
    let fixture = Fixture::new("permissions");
    let root = fixture.path.join("root");
    let nested = root.join("nested");
    fs::create_dir_all(&nested).expect("nested fixture directory");
    let root_identity = identity(&root);
    let file = nested.join("read-only");
    fs::write(&file, b"owned content").expect("owned fixture content");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("read-only file");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o000))
        .expect("non-searchable directory");
    assert_eq!(
        fs::read_dir(&nested)
            .expect_err("fixture must deny traversal")
            .kind(),
        std::io::ErrorKind::PermissionDenied,
    );
    assert_eq!(identity(&root), root_identity);

    remove_production_root(&root);

    assert!(!root.try_exists().expect("root absence"));
    assert_eq!(identity(&fixture.path), fixture.identity);
    fixture.finish();
}

#[test]
fn production_root_cleanup_preserves_external_symlink_targets() {
    let fixture = Fixture::new("symlinks");
    let root = fixture.path.join("root");
    let outside = fixture.path.join("outside");
    fs::create_dir(&root).expect("owned cleanup root");
    fs::create_dir(&outside).expect("separately owned outside root");
    let root_identity = identity(&root);
    let file = outside.join("file");
    let directory = outside.join("directory");
    fs::create_dir(&directory).expect("outside directory");
    fs::write(&file, b"outside file").expect("outside file content");
    fs::write(directory.join("content"), b"outside directory").expect("outside content");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("outside file mode");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
        .expect("outside directory mode");
    let file_identity = identity(&file);
    let directory_identity = identity(&directory);
    symlink(&file, root.join("file-link")).expect("outside file symlink");
    symlink(&directory, root.join("directory-link")).expect("outside directory symlink");
    assert_eq!(identity(&root), root_identity);

    remove_production_root(&root);

    assert!(!root.try_exists().expect("root absence"));
    assert_eq!(identity(&fixture.path), fixture.identity);
    assert_eq!(identity(&file), file_identity);
    assert_eq!(identity(&directory), directory_identity);
    let file_mode = fs::metadata(&file).expect("outside file metadata").mode() & 0o777;
    let directory_mode = fs::metadata(&directory)
        .expect("outside directory metadata")
        .mode()
        & 0o777;
    assert_eq!((file_mode, directory_mode), (0o400, 0o500));
    assert_eq!(
        fs::read(&file).expect("outside file remains"),
        b"outside file"
    );
    assert_eq!(
        fs::read(directory.join("content")).expect("outside directory content remains"),
        b"outside directory",
    );
    fixture.finish();
}
