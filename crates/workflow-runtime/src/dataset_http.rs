//! HTTPS byte source for immutable dataset objects.
#[cfg(test)]
use super::digest_bytes;
use super::{ByteSource, DatasetError, DatasetErrorKind, DatasetSourceIdentity, is_sha256};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_RANGE, ETAG, IF_RANGE, RANGE};
use std::{io::Read, sync::OnceLock, time::Duration};

const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// A pinned remote object read through the dataset preparation boundary.
pub struct HttpByteSource {
    url: String,
    revision: String,
    sha256: String,
    max_bytes: usize,
    local: bool,
    metadata: OnceLock<Result<(u64, Option<String>), DatasetError>>,
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
            metadata: OnceLock::new(),
        })
    }

    fn metadata(&self) -> Result<&(u64, Option<String>), DatasetError> {
        self.metadata
            .get_or_init(|| {
                let (mut response, total, etag) = self.range(0, 0, None)?;
                let mut byte = [0];
                response
                    .read_exact(&mut byte)
                    .map_err(|_| DatasetErrorKind::Interrupted)?;
                Ok((total, etag))
            })
            .as_ref()
            .map_err(|error| *error)
    }

    fn range(
        &self,
        start: u64,
        end: u64,
        expected: Option<&(u64, Option<String>)>,
    ) -> Result<(reqwest::blocking::Response, u64, Option<String>), DatasetError> {
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
        let mut request = client
            .get(&self.url)
            .header(RANGE, format!("bytes={start}-{end}"))
            .header(ACCEPT_ENCODING, "identity");
        if let Some(etag) = expected
            .and_then(|(_, tag)| tag.as_deref())
            .filter(|tag| !tag.starts_with("W/"))
        {
            request = request.header(IF_RANGE, etag);
        }
        let response = request.send().map_err(|_| DatasetErrorKind::Interrupted)?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(DatasetErrorKind::Io.into());
        }
        let range = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("bytes "))
            .ok_or(DatasetErrorKind::Io)?;
        let (bounds, total) = range.split_once('/').ok_or(DatasetErrorKind::Io)?;
        let (actual_start, actual_end) = bounds.split_once('-').ok_or(DatasetErrorKind::Io)?;
        let total = total.parse::<u64>().map_err(|_| DatasetErrorKind::Io)?;
        let etag = response
            .headers()
            .get(ETAG)
            .map(|value| {
                value
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| DatasetErrorKind::Io)
            })
            .transpose()?;
        if total == 0
            || total > self.max_bytes as u64
            || actual_start.parse::<u64>() != Ok(start)
            || actual_end.parse::<u64>() != Ok(end)
            || end >= total
            || response.content_length() != Some(end - start + 1)
            || expected
                .is_some_and(|(length, tag)| *length != total || tag.as_ref() != etag.as_ref())
        {
            return Err(DatasetErrorKind::Io.into());
        }
        Ok((response, total, etag))
    }
}

impl ByteSource for HttpByteSource {
    fn identity(&self) -> Result<DatasetSourceIdentity, DatasetError> {
        Ok(DatasetSourceIdentity::upstream(&self.url, &self.revision))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DatasetError> {
        let metadata = self.metadata()?;
        if offset >= metadata.0 || buf.is_empty() {
            return Ok(0);
        }
        let count = (metadata.0 - offset).min(buf.len() as u64) as usize;
        let end = offset + count as u64 - 1;
        let (mut response, _, _) = self.range(offset, end, Some(metadata))?;
        response
            .read(&mut buf[..count])
            .map_err(|_| DatasetErrorKind::Interrupted.into())
    }

    fn len(&self) -> Result<u64, DatasetError> {
        Ok(self.metadata()?.0)
    }

    fn expected_sha256(&self) -> Option<&str> {
        Some(&self.sha256)
    }
}

#[cfg(test)]
#[path = "dataset_http_resume_tests.rs"]
mod resume_tests;

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
            for (start, end) in [(0, 0), (0, BYTES.len() - 1)] {
                let (mut stream, _) = listener.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut request = [0; 1024];
                let read = stream.read(&mut request).expect("request");
                let text = String::from_utf8_lossy(&request[..read]);
                assert!(text.starts_with("GET /resolve/"));
                assert!(text.contains(&format!("range: bytes={start}-{end}")));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            BYTES.len(), end - start + 1
                        )
                        .as_bytes(),
                    )
                    .expect("headers");
                stream.write_all(&BYTES[start..=end]).expect("body");
            }
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
            for (start, end) in [(0, 0), (0, BYTES.len() - 1)] {
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
                            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            changed.len(), end - start + 1
                        )
                        .as_bytes(),
                    )
                    .expect("headers");
                stream.write_all(&changed[start..=end]).expect("body");
            }
        });
        let source = HttpByteSource::local_fixture(&url, REV, SHA, 128).expect("source");
        assert_eq!(source.len().expect("probe"), BYTES.len() as u64);
        let mut fetched = [0; 128];
        let count = source.read_at(0, &mut fetched).expect("range");
        assert_ne!(digest_bytes(&fetched[..count]), SHA);
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
    fn futurehouse_pinned_product_source_to_cases() {
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
        let cases = super::super::decode_parquet_cases(&prepared, &bytes, 3).expect("cases");
        assert_eq!(cases.len(), 3);
        assert_eq!(
            cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            [
                "00c8bc2d-0bb3-53c2-8bdf-cd19616d4536",
                "066b28c7-c991-5095-8045-a5da176c150a",
                "5c555f14-4a93-552c-bc9f-1d45ae1f6c29"
            ]
        );
        for case in &cases {
            assert!(!case.id.is_empty());
            assert!(!case.problem.is_empty());
            assert!(!case.solution.is_empty());
            assert!(!case.ideal.is_empty());
            assert!(!case.problem_type.is_empty());
            assert!(!case.unformatted.is_empty());
        }

        fs::remove_dir_all(root).expect("cleanup");
    }
}
