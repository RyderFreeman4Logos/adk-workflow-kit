//! One immutable anonymous inode, shared by sandbox scripts and embedded assets.
use std::{
    fs::File,
    io::{self, Seek, Write},
    os::fd::{AsRawFd, FromRawFd},
};

pub(crate) fn sealed_memfd(bytes: &[u8]) -> io::Result<File> {
    const MFD_CLOEXEC: i32 = 0x0001;
    const MFD_ALLOW_SEALING: i32 = 0x0002;
    const F_ADD_SEALS: i32 = 1033;
    const F_SEAL_SEAL: i32 = 0x0001;
    const F_SEAL_SHRINK: i32 = 0x0002;
    const F_SEAL_GROW: i32 = 0x0004;
    const F_SEAL_WRITE: i32 = 0x0008;

    unsafe extern "C" {
        fn memfd_create(name: *const std::ffi::c_char, flags: i32) -> i32;
        fn fcntl(fd: i32, operation: i32, ...) -> i32;
    }

    // SAFETY: the name is NUL-terminated and the flags are valid for Linux memfd_create.
    let fd = unsafe { memfd_create(c"workflow-script".as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a fresh owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(io::SeekFrom::Start(0))?;
    // SAFETY: the descriptor is owned by `file`; these seals make its bytes immutable.
    if unsafe {
        fcntl(
            file.as_raw_fd(),
            F_ADD_SEALS,
            F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
