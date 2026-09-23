use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use super::{DatasetError, DatasetErrorKind, safe_directory_metadata};

pub(super) fn validate_root_link_chain(path: &Path) -> Result<(), DatasetError> {
    let uid = fs::metadata("/proc/self")
        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?
        .uid();
    validate_root_link_chain_with_owner(path, uid, &|_, metadata: &fs::Metadata| metadata.uid())
}

fn validate_root_link_chain_with_owner(
    path: &Path,
    uid: u32,
    owner: &impl Fn(&Path, &fs::Metadata) -> u32,
) -> Result<(), DatasetError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?
            .join(path)
    };
    let mut pending = absolute;
    for _ in 0..40 {
        let mut current = PathBuf::new();
        let mut redirected = None;
        let mut components = pending.components();
        while let Some(component) = components.next() {
            match component {
                Component::RootDir => current.push(Path::new("/")),
                Component::CurDir => {}
                Component::ParentDir => {
                    current.pop();
                }
                Component::Normal(name) => {
                    current.push(name);
                    let parent = current
                        .parent()
                        .ok_or(DatasetError::new(DatasetErrorKind::Io))?;
                    let parent_meta = fs::metadata(parent)
                        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
                    let meta = fs::symlink_metadata(&current)
                        .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
                    let child_uid = owner(&current, &meta);
                    if ![uid, 0].contains(&child_uid)
                        || ![uid, 0].contains(&owner(parent, &parent_meta))
                        || (parent_meta.mode() & 0o1002 == 0o1002 && child_uid != uid)
                        || (!meta.file_type().is_symlink() && !safe_directory_metadata(&meta))
                    {
                        return Err(DatasetError::new(DatasetErrorKind::Io));
                    }
                    if meta.file_type().is_symlink() {
                        let target = fs::read_link(&current)
                            .map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
                        let target = if target.is_absolute() {
                            target
                        } else {
                            parent.join(target)
                        };
                        redirected = Some(target.join(components.as_path()));
                        break;
                    }
                }
                Component::Prefix(_) => return Err(DatasetError::new(DatasetErrorKind::Io)),
            }
        }
        if let Some(next) = redirected {
            pending = next;
        } else {
            return Ok(());
        }
    }
    Err(DatasetError::new(DatasetErrorKind::Io))
}

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
    if let Some(parent) = cache_dir.parent() {
        validate_sticky_ancestry(parent, uid)?;
    }
    if root.file_type().is_symlink() && root.uid() != uid {
        return Err(DatasetError::new(DatasetErrorKind::Io));
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

// Only our UID or root may control a pathname ancestor; retain sticky-child checks.
fn validate_sticky_ancestry(path: &Path, uid: u32) -> Result<(), DatasetError> {
    let mut child = path.to_owned();
    while let Some(parent) = child.parent() {
        let child_metadata =
            fs::metadata(&child).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let parent_metadata =
            fs::metadata(parent).map_err(|_| DatasetError::new(DatasetErrorKind::Io))?;
        let parent_mode = parent_metadata.mode();
        if ![uid, 0].contains(&child_metadata.uid())
            || ![uid, 0].contains(&parent_metadata.uid())
            || (parent_mode & 0o1002 == 0o1002 && child_metadata.uid() != uid)
        {
            return Err(DatasetError::new(DatasetErrorKind::Io));
        }
        child = parent.to_owned();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn foreign_owned_hidden_root_link_hop_is_rejected() {
        let uid = fs::metadata("/proc/self").expect("current uid").uid();
        let root =
            fs::canonicalize(Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"))
                .expect("SSD root")
                .join(format!("issue-229-uid-hop-{}", std::process::id()));
        let parent = root.join("foreign-hop-parent");
        let safe = root.join("safe");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&parent).expect("hop parent");
        fs::create_dir(&safe).expect("safe cache");
        symlink(&safe, parent.join("hop")).expect("nested symlink");
        let configured = root.join("configured");
        symlink(parent.join("hop"), &configured).expect("configured symlink");
        let owner = |path: &Path, metadata: &fs::Metadata| {
            if path == parent {
                uid + 1
            } else {
                metadata.uid()
            }
        };
        assert_eq!(
            validate_root_link_chain_with_owner(&configured, uid, &owner)
                .expect_err("simulated foreign UID owns hidden ordinary hop")
                .kind(),
            DatasetErrorKind::Io
        );
        validate_root_link_chain_with_owner(&configured, uid, &|_, metadata: &fs::Metadata| {
            metadata.uid()
        })
        .expect("trusted nested symlinks remain supported");
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn ordinary_foreign_owned_ancestor_cannot_control_cache_namespace() {
        let current_uid = fs::metadata("/proc/self").expect("current uid").uid();
        let root =
            fs::canonicalize(Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"))
                .expect("SSD test root");
        assert_eq!(fs::metadata(&root).expect("root").uid(), current_uid);
        let sticky = Path::new("/run/lock");
        assert_eq!(
            fs::metadata(sticky)
                .expect("root-owned sticky directory")
                .uid(),
            0
        );
        assert_eq!(
            fs::metadata(sticky).expect("sticky directory").mode() & 0o1002,
            0o1002
        );
        validate_sticky_ancestry(sticky, current_uid).expect("root-owned sticky ancestor");
        assert_eq!(fs::metadata(&root).expect("root").mode() & 0o777, 0o700);
        validate_sticky_ancestry(&root, current_uid).expect("own and root-owned ancestors");
        let foreign_uid = current_uid.checked_add(1).expect("non-root fixture uid");
        assert_eq!(
            validate_sticky_ancestry(&root, foreign_uid)
                .expect_err("foreign-owned ordinary ancestor must be rejected")
                .kind(),
            DatasetErrorKind::Io
        );
    }
}
