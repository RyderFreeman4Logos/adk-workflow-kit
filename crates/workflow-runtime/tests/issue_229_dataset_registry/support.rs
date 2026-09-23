use std::{
    fs,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use workflow_runtime::{ByteSource, DatasetError, DatasetErrorKind, DatasetSourceIdentity};

pub const SMOKE_BYTES: &[u8] = b"issue-229-smoke-fixture\n";
pub const SMOKE_SHA256: &str =
    "sha256:e543862e31a042f932ef3d2f34daa869537e5da06ad9ded1cbbd10885bd46959";
pub static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub struct TestRoot(pub PathBuf);

impl TestRoot {
    pub fn new(label: &str) -> Self {
        let temp_root = fs::canonicalize(
            std::path::Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"),
        )
        .expect("resolved HOME/tmp");
        let root = temp_root.join(format!(
            "issue-229-{}-{}-{}",
            label,
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("cache root");
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct ScriptedSource {
    pub bytes: Vec<u8>,
    max_bytes: usize,
    identity: DatasetSourceIdentity,
    interrupt_after: Option<u64>,
    zero_after: Option<u64>,
    pub served: Mutex<Vec<u64>>,
}

impl ScriptedSource {
    pub fn new(bytes: &[u8], max_bytes: usize) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            identity: DatasetSourceIdentity::local_fixture("memory://smoke-fixture", SMOKE_SHA256),
            interrupt_after: None,
            zero_after: None,
            served: Mutex::new(Vec::new()),
        }
    }

    pub fn with_identity(mut self, identity: DatasetSourceIdentity) -> Self {
        self.identity = identity;
        self
    }

    pub fn interrupt_after(bytes: &[u8], max_bytes: usize, offset: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            identity: DatasetSourceIdentity::local_fixture("memory://smoke-fixture", SMOKE_SHA256),
            interrupt_after: Some(offset),
            zero_after: None,
            served: Mutex::new(Vec::new()),
        }
    }

    pub fn short_eof_after(bytes: &[u8], max_bytes: usize, offset: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            max_bytes,
            identity: DatasetSourceIdentity::local_fixture("memory://smoke-fixture", SMOKE_SHA256),
            interrupt_after: None,
            zero_after: Some(offset),
            served: Mutex::new(Vec::new()),
        }
    }
}

impl ByteSource for ScriptedSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(self.identity.clone())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        if self.interrupt_after.is_some_and(|limit| offset >= limit) {
            return Err(DatasetError::from(DatasetErrorKind::Interrupted));
        }
        if self.zero_after.is_some_and(|limit| offset >= limit) {
            return Ok(0);
        }
        let start = usize::try_from(offset).expect("fixture offset");
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let available = self.bytes.len() - start;
        let take = available.min(buf.len()).min(self.max_bytes);
        buf[..take].copy_from_slice(&self.bytes[start..start + take]);
        self.served.lock().expect("served").push(offset);
        Ok(take)
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(u64::try_from(self.bytes.len()).expect("fixture len"))
    }
}
