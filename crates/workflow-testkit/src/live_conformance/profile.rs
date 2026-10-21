use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    path::Path,
    process::Command,
    time::Duration,
};

use workflow_adk::execution::ExecutionProfileV1;
use workflow_spec::{SourcePath, read_bounded_regular_file};

// Offline canonical fake run: pre/post 77.932ms ×4, rounded up to a whole second.
// This admission allowance is calibrated headroom, not a host scheduling guarantee.
const OVERHEAD: Duration = Duration::from_secs(1);

pub(super) fn budget(bytes: &[u8]) -> Option<Duration> {
    ExecutionProfileV1::parse(bytes)
        .ok()?
        .wall_time_limit()
        .checked_add(OVERHEAD)
}

/// A sealed, inherited regular file binds admission to the bytes read by the CLI.
pub(super) struct Snapshot(File);

impl Snapshot {
    pub(super) fn new(path: &Path, admitted: Duration) -> io::Result<Self> {
        let bytes = read_bounded_regular_file(&SourcePath::from(path), 64 * 1024)
            .map_err(|_| io::Error::other("live profile read failed"))?;
        let required = budget(&bytes).ok_or_else(|| io::Error::other("invalid live profile"))?;
        if admitted < required {
            return Err(io::Error::other(
                "live command budget does not admit profile wall time",
            ));
        }
        // SAFETY: the fixed name is NUL-terminated; memfd is anonymous and initially CLOEXEC.
        let fd = unsafe {
            libc::memfd_create(
                c"workflow-live-profile".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful memfd_create transferred this fresh descriptor to us.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&bytes)?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: this owned descriptor is sealable and has no shared writable mappings.
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }

    pub(super) fn bind(&self, command: &mut Command) -> String {
        let fd = self.0.as_raw_fd();
        // SAFETY: the descriptor stays owned through spawn. Only the child clears
        // CLOEXEC; fcntl is async-signal-safe and no allocation or lock is used.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        format!("/proc/self/fd/{fd}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn sealed_snapshot_survives_source_replacement_and_child_exec() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/01-code-investigation/profiles/fake.json");
        let bytes = std::fs::read(example).expect("checked-in profile");
        let path = std::env::temp_dir().join(format!("issue-337-seal-{}", std::process::id()));
        let mut original = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("exclusive profile");
        original.write_all(&bytes).expect("profile");
        let snapshot = Snapshot::new(&path, Duration::from_secs(61)).expect("snapshot");
        std::fs::write(&path, b"replaced after admission").expect("replace source");
        let fd = snapshot.0.as_raw_fd();
        // SAFETY: these calls query our owned descriptor without changing it.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        // SAFETY: F_GET_SEALS only queries this valid sealable descriptor.
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        assert_eq!(
            seals,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL
        );
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut command = Command::new("/usr/bin/python3");
        let bound = snapshot.bind(&mut command);
        command.args(["-c", "import fcntl,os,sys; p=sys.argv[1]; f=os.open(p,os.O_RDWR); assert fcntl.fcntl(f,fcntl.F_GET_SEALS)==15; sys.stdout.buffer.write(os.pread(f,65536,0));\nfor op in [lambda:os.pwrite(f,b'x',0),lambda:os.ftruncate(f,0),lambda:os.ftruncate(f,1000000)]:\n try: op(); raise AssertionError('seal missing')\n except PermissionError: pass", &bound]);
        let output = super::super::child::output(&mut command, Duration::from_secs(2))
            .expect("bounded child");
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, bytes);
        // SAFETY: read-only query proves the parent never cleared CLOEXEC.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, flags);
        let mut readback = Vec::new();
        File::open(bound)
            .expect("regular snapshot path")
            .read_to_end(&mut readback)
            .expect("snapshot bytes");
        assert_eq!(readback, bytes);
        std::fs::remove_file(path).expect("remove owned fixture");
    }
}
