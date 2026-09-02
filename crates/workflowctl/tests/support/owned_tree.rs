use std::{fs, path::Path};

pub fn remove_dir_all(path: &Path) -> std::io::Result<()> {
    make_owner_writable(path);
    fs::remove_dir_all(path)
}

fn make_owner_writable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | if metadata.is_dir() { 0o700 } else { 0o200 });
        if fs::set_permissions(path, permissions).is_err() || !metadata.is_dir() {
            return;
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        make_owner_writable(&entry.path());
    }
}
