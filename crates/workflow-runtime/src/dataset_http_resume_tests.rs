use super::*;
use crate::{DatasetManifest, EvalSuite, PrepareRequest, prepare_dataset};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const REV: &str = "c7d5e59960087f360bc32a5006bb994324b38c35";
const BYTES: &[u8] = b"issue-229-smoke-fixture\n";

#[test]
fn socket_interruption_persists_attributed_partial_and_resumes_exact_range() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!(
        "http://127.0.0.1:{}/resolve/{REV}/artifact",
        listener.local_addr().expect("address").port()
    );
    let sha = digest_bytes(BYTES);
    let manifest = DatasetManifest::parse_str(&format!(
        r#"schema_version = 1
[[datasets]]
id = "http-fixture"
family = "synthetic"
language = "en"
revision = "{REV}"
url = "{url}"
sha256 = "{sha}"
license = "Apache-2.0"
license_acceptance_required = false
distribution = "fetch"
adapter_version = "1"
derivation = "identity"
suites = ["regression"]
"#
    ))
    .expect("manifest");
    let root = fs::canonicalize(
        std::path::Path::new(&std::env::var_os("HOME").expect("HOME")).join("tmp"),
    )
    .expect("temp")
    .join(format!("issue-229-range-{}", std::process::id()));
    fs::create_dir(&root).expect("cache");
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = Arc::clone(&requests);
    listener.set_nonblocking(true).expect("nonblocking");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("deadline");
            let mut request = [0; 2048];
            let count = stream.read(&mut request).expect("request");
            let request = String::from_utf8_lossy(&request[..count]).into_owned();
            let range = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("range: "))
                .expect("actual HTTP Range request")
                .to_owned();
            let index = {
                let mut values = observed.lock().expect("requests");
                values.push(range.clone());
                values.len()
            };
            let (start, end, body): (usize, usize, &[u8]) = match index {
                1 | 4 => (0, 0, &BYTES[..1]),
                2 => (0, BYTES.len() - 1, &BYTES[..8]),
                3 => continue, // interrupted follow-up read leaves the already persisted prefix
                5 => (8, BYTES.len() - 1, &BYTES[8..]),
                _ => panic!("unexpected request {index}"),
            };
            let header = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\nETag: \"immutable-fixture\"\r\nConnection: close\r\n\r\n",
                BYTES.len(),
                end - start + 1
            );
            stream.write_all(header.as_bytes()).expect("headers");
            stream.write_all(body).expect("body");
            if index == 5 {
                return;
            }
        }
    });
    let partial = root.join("http-fixture").join(REV).join("artifact.partial");
    let wrong_pin = HttpByteSource::local_fixture(
        &url,
        REV,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        128,
    )
    .expect("wrong pin source");
    assert!(
        matches!(prepare_dataset(&manifest, "http-fixture", &PrepareRequest {
        cache_dir: &root, source: &wrong_pin, suite: EvalSuite::Regression,
        offline: false, license_accepted: true, manual_path: None,
    }), Err(error) if error.kind() == DatasetErrorKind::ChecksumMismatch)
    );
    assert!(
        requests.lock().expect("requests").is_empty(),
        "pin gate precedes egress"
    );
    let run = || {
        let source = HttpByteSource::local_fixture(&url, REV, &sha, 128).expect("source");
        prepare_dataset(
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
    };
    assert!(matches!(run(), Err(error) if error.kind() == DatasetErrorKind::Interrupted));
    assert_eq!(fs::read(&partial).expect("admitted partial"), &BYTES[..8]);
    assert_eq!(
        fs::read(
            root.join("http-fixture")
                .join(REV)
                .join("artifact.partial.identity")
        )
        .expect("partial identity"),
        DatasetSourceIdentity::upstream(&url, REV)
            .cache_bytes()
            .as_bytes()
    );
    let prepared = run().expect("resumed");
    assert_eq!(prepared.source_identity().source_revision(), REV);
    assert_eq!(
        fs::read(root.join("http-fixture").join(REV).join("artifact")).expect("complete"),
        BYTES
    );
    server.join().expect("server");
    assert_eq!(
        *requests.lock().expect("requests"),
        [
            "range: bytes=0-0",
            "range: bytes=0-23",
            "range: bytes=8-23",
            "range: bytes=0-0",
            "range: bytes=8-23"
        ]
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn range_rejects_ignored_offset_invalid_bounds_lengths_etag_and_redirect() {
    let total = BYTES.len();
    let cases = [
        ("ignored-200", "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n"),
        (
            "wrong-start",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-23/24\r\nContent-Length: 16\r\n",
        ),
        (
            "wrong-total",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 8-23/25\r\nContent-Length: 16\r\n",
        ),
        (
            "short-length",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 8-23/24\r\nContent-Length: 15\r\n",
        ),
        (
            "long-length",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 8-23/24\r\nContent-Length: 17\r\n",
        ),
        (
            "changed-etag",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 8-23/24\r\nContent-Length: 16\r\nETag: \"changed\"\r\n",
        ),
        (
            "forbidden-redirect",
            "HTTP/1.1 302 Found\r\nLocation: https://unapproved.invalid/object\r\nContent-Length: 0\r\n",
        ),
    ];
    assert_eq!(total, 24);
    for (name, headers) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!(
            "http://127.0.0.1:{}/resolve/{REV}/artifact",
            listener.local_addr().expect("address").port()
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("deadline");
            let mut request = [0; 2048];
            let count = stream.read(&mut request).expect("request");
            let text = String::from_utf8_lossy(&request[..count]);
            assert!(text.contains("range: bytes=8-23"), "{name}: {text}");
            stream
                .write_all(format!("{headers}Connection: close\r\n\r\n").as_bytes())
                .expect("response");
        });
        let source =
            HttpByteSource::local_fixture(&url, REV, &digest_bytes(BYTES), 128).expect("source");
        let meta = (total as u64, Some("\"immutable-fixture\"".to_owned()));
        assert!(
            matches!(source.range(8, 23, Some(&meta)), Err(error) if error.kind() == DatasetErrorKind::Io),
            "{name}"
        );
        server.join().expect("server");
    }
}
