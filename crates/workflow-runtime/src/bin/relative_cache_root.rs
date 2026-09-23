//! Isolated cwd probe for a missing bare relative cache root.
use std::{env, path::Path};
use workflow_runtime::{
    ByteSource, DatasetError, DatasetManifest, DatasetSourceIdentity, EvalSuite, PrepareRequest,
    prepare_dataset,
};

const SHA: &str = "sha256:e543862e31a042f932ef3d2f34daa869537e5da06ad9ded1cbbd10885bd46959";
const BYTES: &[u8] = b"issue-229-smoke-fixture\n";

struct Source;

impl ByteSource for Source {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(DatasetSourceIdentity::local_fixture(
            "memory://smoke-fixture",
            SHA,
        ))
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(BYTES.len() as u64)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        let start = offset as usize;
        if start >= BYTES.len() {
            return Ok(0);
        }
        let count = (BYTES.len() - start).min(buf.len());
        buf[..count].copy_from_slice(&BYTES[start..start + count]);
        Ok(count)
    }
}

fn main() {
    let offline = env::args().nth(1).as_deref() == Some("offline");
    let manifest = DatasetManifest::parse_str(&format!(
        r#"schema_version = 1
[[datasets]]
id = "smoke-fixture"
family = "synthetic"
language = "en"
revision = "1.0.0"
url = "memory://smoke-fixture"
sha256 = "{SHA}"
license = "Apache-2.0"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["smoke"]
"#
    ))
    .expect("manifest");
    prepare_dataset(
        &manifest,
        "smoke-fixture",
        &PrepareRequest {
            cache_dir: Path::new("cache"),
            source: &Source,
            suite: EvalSuite::Smoke,
            offline,
            license_accepted: false,
            manual_path: None,
        },
    )
    .expect("relative cache root");
}
