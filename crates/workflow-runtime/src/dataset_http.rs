//! HTTPS byte source for immutable dataset objects.
use super::{
    ByteSource, DatasetError, DatasetErrorKind, DatasetSourceIdentity, digest_bytes, is_sha256,
};
use std::{io::Read, sync::OnceLock, time::Duration};

const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// A pinned remote object read through the dataset preparation boundary.
pub struct HttpByteSource {
    url: String,
    revision: String,
    sha256: String,
    max_bytes: usize,
    local: bool,
    bytes: OnceLock<Result<Vec<u8>, DatasetError>>,
}

impl HttpByteSource {
    /// Validates a pinned HTTPS object; fetch occurs only after preparation's gates.
    pub fn new(
        url: &str,
        revision: &str,
        sha256: &str,
        max_bytes: usize,
    ) -> Result<Self, DatasetError> {
        Self::configure(url, revision, sha256, max_bytes, false)
    }

    #[cfg(test)]
    fn local_fixture(
        url: &str,
        revision: &str,
        sha256: &str,
        max_bytes: usize,
    ) -> Result<Self, DatasetError> {
        Self::configure(url, revision, sha256, max_bytes, true)
    }

    fn configure(
        url: &str,
        revision: &str,
        sha256: &str,
        max_bytes: usize,
        local: bool,
    ) -> Result<Self, DatasetError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|_| DatasetErrorKind::SourceIdentityMismatch)?;
        let valid_origin = if local {
            parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1")
        } else {
            parsed.scheme() == "https"
                && parsed.host_str() == Some("huggingface.co")
                && parsed.port().is_none()
        };
        let segments: Vec<_> = parsed
            .path_segments()
            .ok_or(DatasetErrorKind::SourceIdentityMismatch)?
            .collect();
        if !valid_origin
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(revision.len(), 40 | 64)
            || !revision.bytes().all(|b| b.is_ascii_hexdigit())
            || !is_sha256(sha256)
            || !segments
                .windows(2)
                .any(|pair| pair == ["resolve", revision])
            || max_bytes == 0
            || max_bytes > MAX_OBJECT_BYTES
        {
            return Err(DatasetErrorKind::SourceIdentityMismatch.into());
        }
        Ok(Self {
            url: url.to_owned(),
            revision: revision.to_owned(),
            sha256: sha256.to_owned(),
            max_bytes,
            local,
            bytes: OnceLock::new(),
        })
    }

    fn bytes(&self) -> Result<&[u8], DatasetError> {
        self.bytes
            .get_or_init(|| self.fetch())
            .as_ref()
            .map(Vec::as_slice)
            .map_err(|error| *error)
    }

    fn fetch(&self) -> Result<Vec<u8>, DatasetError> {
        let mut builder = reqwest::blocking::Client::builder();
        if self.local {
            builder = builder.no_proxy();
        }
        let client = builder
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                let next = attempt.url();
                let host = next.host_str().unwrap_or_default();
                if attempt.previous().len() < 5
                    && next.scheme() == "https"
                    && (host == "huggingface.co"
                        || host.ends_with(".xethub.hf.co")
                        || host.ends_with(".hf.co"))
                    && next.port().is_none()
                {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|_| DatasetErrorKind::Io)?;
        let response = client
            .get(&self.url)
            .send()
            .map_err(|_| DatasetErrorKind::Io)?;
        if !response.status().is_success() {
            return Err(DatasetErrorKind::Io.into());
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(DatasetErrorKind::Io.into());
        }
        let mut bytes = Vec::new();
        response
            .take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DatasetErrorKind::Interrupted)?;
        if bytes.len() > self.max_bytes {
            return Err(DatasetErrorKind::Io.into());
        }
        if digest_bytes(&bytes) != self.sha256 {
            return Err(DatasetErrorKind::ChecksumMismatch.into());
        }
        Ok(bytes)
    }
}

impl ByteSource for HttpByteSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(DatasetSourceIdentity::upstream(&self.url, &self.revision))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        let start = usize::try_from(offset).map_err(|_| DatasetErrorKind::Io)?;
        let Some(remaining) = self.bytes()?.get(start..) else {
            return Ok(0);
        };
        let count = remaining.len().min(buf.len());
        buf[..count].copy_from_slice(&remaining[..count]);
        Ok(count)
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(self.bytes()?.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatasetManifest, EvalSuite, PrepareRequest, prepare_dataset};
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };

    const REV: &str = "c7d5e59960087f360bc32a5006bb994324b38c35";
    const SHA: &str = "sha256:e543862e31a042f932ef3d2f34daa869537e5da06ad9ded1cbbd10885bd46959";
    const BYTES: &[u8] = b"issue-229-smoke-fixture\n";

    #[test]
    fn pinned_http_source_prepares_verified_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let url = format!(
            "http://127.0.0.1:{}/resolve/{REV}/artifact",
            listener.local_addr().expect("addr").port()
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("deadline");
            let mut request = [0; 1024];
            let read = stream.read(&mut request).expect("request");
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /resolve/"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        BYTES.len()
                    )
                    .as_bytes(),
                )
                .expect("headers");
            stream.write_all(BYTES).expect("body");
        });
        let source = HttpByteSource::local_fixture(&url, REV, SHA, 128).expect("source");
        let root = fs::canonicalize(
            std::path::Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"),
        )
        .expect("temp")
        .join(format!("issue-229-http-{}", std::process::id()));
        fs::create_dir(&root).expect("cache");
        let manifest = DatasetManifest::parse_str(&format!(
            r#"schema_version = 1
[[datasets]]
id = "http-fixture"
family = "synthetic"
language = "en"
revision = "{REV}"
url = "{url}"
sha256 = "{SHA}"
license = "Apache-2.0"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["regression"]
"#
        ))
        .expect("manifest");
        let prepared = prepare_dataset(
            &manifest,
            "http-fixture",
            &PrepareRequest {
                cache_dir: &root,
                source: &source,
                suite: EvalSuite::Regression,
                offline: false,
                license_accepted: true,
                manual_path: None,
            },
        )
        .expect("prepared");
        assert_eq!(
            fs::read(root.join("http-fixture").join(REV).join("artifact")).expect("artifact"),
            BYTES
        );
        assert_eq!(prepared.source_identity().source_revision(), REV);
        server.join().expect("server");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn pinned_http_source_rejects_wrong_bytes_and_revision() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!(
            "http://127.0.0.1:{}/resolve/{REV}/artifact",
            listener.local_addr().expect("addr").port()
        );
        let other = "0000000000000000000000000000000000000000";
        assert!(matches!(
            HttpByteSource::new(&url, REV, SHA, 128),
            Err(error) if error.kind() == DatasetErrorKind::SourceIdentityMismatch
        ));
        assert!(matches!(
            HttpByteSource::local_fixture(&url, other, SHA, 128),
            Err(error) if error.kind() == DatasetErrorKind::SourceIdentityMismatch
        ));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("deadline");
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).expect("request");
            let changed = b"issue-229-smoke-fixturE\n";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        changed.len()
                    )
                    .as_bytes(),
                )
                .expect("headers");
            stream.write_all(changed).expect("body");
        });
        assert!(matches!(
            HttpByteSource::local_fixture(&url, REV, SHA, 128).and_then(|source| source.len()),
            Err(error) if error.kind() == DatasetErrorKind::ChecksumMismatch
        ));
        server.join().expect("server");
    }

    #[test]
    fn license_gate_precedes_http_get() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!(
            "http://127.0.0.1:{}/resolve/{REV}/artifact",
            listener.local_addr().expect("addr").port()
        );
        listener.set_nonblocking(true).expect("nonblocking");
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0; 1024];
                        let _ = stream.read(&mut request);
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", BYTES.len()).as_bytes()).expect("header");
                        stream.write_all(BYTES).expect("body");
                        return true;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
                    Err(error) => panic!("accept: {error}"),
                }
            }
        });
        let source = HttpByteSource::local_fixture(&url, REV, SHA, 128).expect("source");
        let root = fs::canonicalize(
            std::path::Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"),
        )
        .expect("temp")
        .join(format!("issue-229-gate-{}", std::process::id()));
        fs::create_dir(&root).expect("cache");
        let manifest = DatasetManifest::parse_str(&format!(
            r#"schema_version = 1
[[datasets]]
id = "gate"
family = "synthetic"
language = "en"
revision = "{REV}"
url = "{url}"
sha256 = "{SHA}"
license = "CC-BY-4.0"
license_acceptance_required = true
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["regression"]
"#
        ))
        .expect("manifest");
        assert!(
            matches!(prepare_dataset(&manifest, "gate", &PrepareRequest {
            cache_dir: &root, source: &source, suite: EvalSuite::Regression,
            offline: false, license_accepted: false, manual_path: None,
        }), Err(error) if error.kind() == DatasetErrorKind::LicenseRequired)
        );
        assert!(
            !server.join().expect("server"),
            "license gate must prevent GET"
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    // FutureHouse (2025), ether0-benchmark, CC BY 4.0:
    // https://creativecommons.org/licenses/by/4.0/
    #[test]
    #[ignore = "requires a public HTTPS connection; invoke via just issue-229-live"]
    fn futurehouse_pinned_product_fetch() {
        const URL: &str = "https://huggingface.co/datasets/futurehouse/ether0-benchmark/resolve/c7d5e59960087f360bc32a5006bb994324b38c35/data/test-00000-of-00001.parquet";
        const EXPECTED: &str =
            "sha256:c53213a37ef319aa7f733751b93748db960cce33355c1d44124108e7f15c5bbc";
        let root = fs::canonicalize(
            std::path::Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"),
        )
        .expect("temp")
        .join(format!("issue-229-live-{}", std::process::id()));
        fs::create_dir(&root).expect("cache");
        let manifest = DatasetManifest::parse_str(&format!(
            r#"schema_version = 1
[[datasets]]
id = "ether0"
family = "futurehouse"
language = "en"
revision = "{REV}"
url = "{URL}"
sha256 = "{EXPECTED}"
license = "CC-BY-4.0"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["regression"]
"#
        ))
        .expect("manifest");
        let source = HttpByteSource::new(URL, REV, EXPECTED, 100_000).expect("HTTPS source");
        let prepared = prepare_dataset(
            &manifest,
            "ether0",
            &PrepareRequest {
                cache_dir: &root,
                source: &source,
                suite: EvalSuite::Regression,
                offline: false,
                license_accepted: true,
                manual_path: None,
            },
        )
        .expect("prepared");
        assert_eq!(prepared.source_identity().source_revision(), REV);
        let bytes = fs::read(root.join("ether0").join(REV).join("artifact")).expect("artifact");
        assert_eq!(bytes.len(), 80_281);
        assert_eq!(digest_bytes(&bytes), EXPECTED);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
