use std::path::Path;

const MAX_SKILL_FILE_BYTES: usize = 65_536;

#[derive(Clone, Copy)]
pub(crate) enum SkillValidationFailure {
    Manifest,
    Script,
}

#[cfg(target_os = "linux")]
pub(crate) fn read_skill_file(
    root: &Path,
    relative_path: &str,
    failure: SkillValidationFailure,
) -> Result<Vec<u8>, SkillValidationFailure> {
    use std::{
        ffi::{CString, c_char},
        fs::{File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
        path::Component,
    };

    const O_CLOEXEC: i32 = 0o2_000_000;
    const O_DIRECTORY: i32 = 0o200_000;
    const O_NOFOLLOW: i32 = 0o400_000;
    const O_NONBLOCK: i32 = 0o4_000;

    unsafe extern "C" {
        fn openat(dirfd: i32, pathname: *const c_char, flags: i32, mode: u32) -> i32;
    }

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
        .open(root)
        .map_err(|_| failure)?;
    let mut directory = OwnedFd::from(root);
    let mut components = Path::new(relative_path).components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(failure);
        };
        let name = CString::new(name.as_bytes()).map_err(|_| failure)?;
        let final_component = components.peek().is_none();
        let flags =
            O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | if final_component { 0 } else { O_DIRECTORY };
        let fd = unsafe { openat(directory.as_raw_fd(), name.as_ptr(), flags, 0) };
        if fd < 0 {
            return Err(failure);
        }
        let opened = unsafe { OwnedFd::from_raw_fd(fd) };
        if !final_component {
            directory = opened;
            continue;
        }

        let file = File::from(opened);
        let metadata = file.metadata().map_err(|_| failure)?;
        if !metadata.is_file() {
            return Err(failure);
        }
        let mut bytes = Vec::new();
        file.take((MAX_SKILL_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| failure)?;
        if bytes.len() > MAX_SKILL_FILE_BYTES {
            return Err(failure);
        }
        return Ok(bytes);
    }

    Err(failure)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_skill_file(
    _root: &Path,
    _relative_path: &str,
    failure: SkillValidationFailure,
) -> Result<Vec<u8>, SkillValidationFailure> {
    Err(failure)
}
