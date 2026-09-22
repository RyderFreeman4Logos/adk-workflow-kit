use std::{fs, os::unix::fs::MetadataExt, path::Path};

use super::{DatasetError, DatasetErrorKind};

pub(super) fn validate_cache_entry_ancestors(
    cache_dir: &Path,
    dest: &Path,
) -> Result<(), DatasetError> {
    let uid = fs::metadata("/proc/self")
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?
        .uid();
    let root = match fs::symlink_metadata(cache_dir) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return validate_creation_ancestry(cache_dir, uid);
        }
        Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
    };
    if root.file_type().is_symlink() {
        if root.uid() != uid {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
        if let Some(parent) = cache_dir.parent() {
            validate_sticky_ancestry(parent, uid)?;
        }
    }
    let canonical_root =
        fs::canonicalize(cache_dir).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    validate_sticky_ancestry(&canonical_root, uid)?;
    let parent = dest
        .parent()
        .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
    let relative = parent
        .strip_prefix(cache_dir)
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
    let mut current = cache_dir.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
        };
        let mode = metadata.mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != uid
            || mode & 0o020 != 0
            || (mode & 0o002 != 0 && mode & 0o1000 == 0)
        {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
    }
    Ok(())
}

// Validate the existing path before recursive directory creation can touch it.
fn validate_creation_ancestry(path: &Path, uid: u32) -> Result<(), DatasetError> {
    let mut existing = path;
    let metadata = loop {
        match fs::symlink_metadata(existing) {
            Ok(metadata) => break metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing
                    .parent()
                    .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
            }
            Err(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DatasetError::new(DatasetErrorKind::Io));
    }
    validate_sticky_ancestry(existing, uid)?;
    let mut child = existing.to_owned();
    while let Some(parent) = child.parent() {
        let child_metadata =
            fs::metadata(&child).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let mode = child_metadata.mode();
        if mode & 0o020 != 0 || (mode & 0o002 != 0 && mode & 0o1000 == 0) {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
        child = parent.to_owned();
    }
    Ok(())
}

// Sticky shared parents cannot replace entries owned by another user.
fn validate_sticky_ancestry(path: &Path, uid: u32) -> Result<(), DatasetError> {
    let mut child = path.to_owned();
    while let Some(parent) = child.parent() {
        let child_metadata =
            fs::metadata(&child).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let parent_metadata =
            fs::metadata(parent).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let parent_mode = parent_metadata.mode();
        if parent_mode & 0o1002 == 0o1002 && child_metadata.uid() != uid {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
        child = parent.to_owned();
    }
    Ok(())
}
