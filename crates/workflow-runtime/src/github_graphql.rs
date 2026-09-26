use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER, USER_AGENT},
    redirect::Policy,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
#[cfg(test)]
use std::net::SocketAddr;

use crate::{
    GitHubIntakeError, GitHubIssueMetadata, GitHubIssueState, GitHubMetadataPage,
    GitHubMetadataPageRequest, GitHubMetadataSource, GitHubRateLimit,
};

const GRAPHQL_ENDPOINT: &str = "https://api.github.com/graphql";
const GRAPHQL_QUERY: &str = "query MetadataOnlyIssues($owner: String!, $name: String!, $first: Int!) { repository(owner: $owner, name: $name) { issues(first: $first) { nodes { id number author { login } authorAssociation state updatedAt } pageInfo { hasNextPage } } } }";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Metadata-only GitHub GraphQL intake. The response identity is deliberately
/// labeled as one-page response provenance, not an immutable repository snapshot.
pub struct GitHubGraphqlMetadataSource {
    client: Client,
    endpoint: String,
    credential: String,
}

impl GitHubGraphqlMetadataSource {
    /// Construct the live source with an opaque caller-supplied credential.
    /// Credentials are never read from process configuration or included in errors.
    pub fn new(credential: impl Into<String>) -> Result<Self, GitHubIntakeError> {
        Self::with_endpoint(GRAPHQL_ENDPOINT.to_owned(), credential)
    }

    #[cfg(test)]
    fn local_fixture(
        address: SocketAddr,
        credential: impl Into<String>,
    ) -> Result<Self, GitHubIntakeError> {
        if !address.ip().is_loopback() {
            return Err(GitHubIntakeError::invalid_request());
        }
        Self::with_endpoint(format!("http://{address}/graphql"), credential)
    }

    fn with_endpoint(
        endpoint: String,
        credential: impl Into<String>,
    ) -> Result<Self, GitHubIntakeError> {
        let credential = credential.into();
        if credential.is_empty() {
            return Err(GitHubIntakeError::invalid_request());
        }
        let client = Client::builder()
            .redirect(Policy::none())
            // The endpoint is pinned; never route its bearer through ambient proxies.
            .no_proxy()
            .build()
            .map_err(|_| GitHubIntakeError::source_unavailable())?;
        Ok(Self {
            client,
            endpoint,
            credential,
        })
    }

    fn request_page(
        &self,
        request: &GitHubMetadataPageRequest,
    ) -> Result<GitHubMetadataPage, GitHubIntakeError> {
        if request.page() != 1 || request.snapshot().is_some() || request.per_page() == 0 {
            return Err(GitHubIntakeError::invalid_request());
        }
        let mut repository = request.repository().split('/');
        let Some(owner) = repository.next().filter(|value| !value.is_empty()) else {
            return Err(GitHubIntakeError::invalid_request());
        };
        let Some(name) = repository.next().filter(|value| !value.is_empty()) else {
            return Err(GitHubIntakeError::invalid_request());
        };
        if repository.next().is_some() {
            return Err(GitHubIntakeError::invalid_request());
        }
        let body = serde_json::to_vec(&json!({
            "query": GRAPHQL_QUERY,
            "variables": {
                "owner": owner,
                "name": name,
                "first": request.per_page(),
            },
        }))
        .map_err(|_| GitHubIntakeError::source_unavailable())?;
        let response = self
            .client
            .post(&self.endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT, "adk-workflow-kit")
            .bearer_auth(&self.credential)
            .body(body)
            .send()
            .map_err(|_| GitHubIntakeError::source_unavailable())?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_u64_header);
        let remaining_header = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(parse_u64_header);
        let remaining = remaining_header
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let reset = response
            .headers()
            .get("x-ratelimit-reset")
            .and_then(parse_u64_header);
        let bytes = read_response_body(response)?;
        let envelope = serde_json::from_slice::<GraphqlResponse>(&bytes).ok();
        if should_classify_rate_limit(status, remaining_header, retry_after, envelope.as_ref()) {
            return Err(GitHubIntakeError::rate_limited(retry_after));
        }
        if !status.is_success() {
            return Err(GitHubIntakeError::source_unavailable());
        }
        let envelope = envelope.ok_or_else(GitHubIntakeError::source_unavailable)?;
        if envelope.errors.is_some() {
            return Err(GitHubIntakeError::source_unavailable());
        }
        let issues = envelope
            .data
            .and_then(|data| data.repository)
            .map(|repository| repository.issues)
            .ok_or_else(GitHubIntakeError::source_unavailable)?;
        // Repository.issues is the issue connection; pull requests are not selected.
        // See https://docs.github.com/en/graphql/reference/objects#repository.
        if issues.page_info.has_next_page {
            return Err(GitHubIntakeError::source_unavailable());
        }
        let mut metadata = Vec::with_capacity(issues.nodes.len());
        for node in issues.nodes {
            if !valid_graphql_id(&node.id) || !valid_graphql_datetime(&node.updated_at) {
                return Err(GitHubIntakeError::source_unavailable());
            }
            let author = node
                .author
                .ok_or_else(GitHubIntakeError::source_unavailable)?;
            let number =
                u64::try_from(node.number).map_err(|_| GitHubIntakeError::source_unavailable())?;
            let state = match node.state {
                GraphqlIssueState::Open => GitHubIssueState::Open,
                GraphqlIssueState::Closed => GitHubIssueState::Closed,
            };
            let issue = GitHubIssueMetadata::new(
                number,
                author.login,
                node.author_association.as_str().to_owned(),
                state,
                node.updated_at,
                false,
            )
            .map_err(|_| GitHubIntakeError::source_unavailable())?;
            metadata.push(issue);
        }
        let digest = Sha256::digest(&bytes);
        let snapshot = format!("github-graphql-one-page-response:{digest:x}");
        GitHubMetadataPage::new(
            snapshot,
            metadata,
            false,
            GitHubRateLimit::new(remaining, reset),
        )
    }
}

impl GitHubMetadataSource for GitHubGraphqlMetadataSource {
    fn list_page(
        &mut self,
        request: &GitHubMetadataPageRequest,
    ) -> Result<GitHubMetadataPage, GitHubIntakeError> {
        self.request_page(request)
    }
}

fn parse_u64_header(value: &reqwest::header::HeaderValue) -> Option<u64> {
    value.to_str().ok()?.parse().ok()
}

fn read_response_body(mut response: Response) -> Result<Vec<u8>, GitHubIntakeError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(GitHubIntakeError::source_unavailable());
    }
    let mut bytes = Vec::with_capacity(MAX_RESPONSE_BYTES.min(8 * 1024));
    response
        .by_ref()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| GitHubIntakeError::source_unavailable())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(GitHubIntakeError::source_unavailable());
    }
    Ok(bytes)
}

fn should_classify_rate_limit(
    status: StatusCode,
    remaining: Option<u64>,
    retry_after: Option<u64>,
    envelope: Option<&GraphqlResponse>,
) -> bool {
    let structured_rate_error = envelope.is_some_and(|envelope| {
        envelope
            .errors
            .as_ref()
            .is_some_and(|errors| errors.iter().any(GraphqlError::is_rate_limited))
    });
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (structured_rate_error || remaining == Some(0) || retry_after.is_some()))
        || (status.is_success() && structured_rate_error)
}

fn valid_graphql_id(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| !character.is_control())
}

fn parse_fixed_component(value: &str, width: usize) -> Option<u32> {
    (value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn valid_graphql_datetime(value: &str) -> bool {
    let Some((date, time_with_zone)) = value.split_once('T') else {
        return false;
    };
    let mut date_parts = date.split('-');
    let (Some(year), Some(month), Some(day)) = (
        date_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 4)),
        date_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 2)),
        date_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 2)),
    ) else {
        return false;
    };
    if date_parts.next().is_some() || !(1..=12).contains(&month) {
        return false;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return false;
    }
    let Some(time) = time_with_zone.strip_suffix('Z') else {
        return false;
    };
    let (clock, fraction) = time
        .split_once('.')
        .map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    if fraction.is_some_and(|fraction| {
        fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return false;
    }
    let mut clock_parts = clock.split(':');
    let (Some(hour), Some(minute), Some(second)) = (
        clock_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 2)),
        clock_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 2)),
        clock_parts
            .next()
            .and_then(|part| parse_fixed_component(part, 2)),
    ) else {
        return false;
    };
    clock_parts.next().is_none() && hour < 24 && minute < 60 && second < 60
}

#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Deserialize)]
struct GraphqlError {
    #[serde(rename = "type")]
    error_type: Option<String>,
    extensions: Option<GraphqlErrorExtensions>,
}

impl GraphqlError {
    fn is_rate_limited(&self) -> bool {
        self.error_type.as_deref() == Some("RATE_LIMITED")
            || self.extensions.as_ref().is_some_and(|extensions| {
                extensions.error_type.as_deref() == Some("RATE_LIMITED")
                    || extensions.code.as_deref() == Some("RATE_LIMITED")
            })
    }
}

#[derive(Deserialize)]
struct GraphqlErrorExtensions {
    code: Option<String>,
    #[serde(rename = "type")]
    error_type: Option<String>,
}

#[derive(Deserialize)]
struct GraphqlData {
    repository: Option<GraphqlRepository>,
}

#[derive(Deserialize)]
struct GraphqlRepository {
    issues: GraphqlIssues,
}

#[derive(Deserialize)]
struct GraphqlIssues {
    nodes: Vec<GraphqlNode>,
    #[serde(rename = "pageInfo")]
    page_info: GraphqlPageInfo,
}

#[derive(Deserialize)]
struct GraphqlPageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
}

#[derive(Deserialize)]
struct GraphqlNode {
    id: String,
    number: i32,
    author: Option<GraphqlAuthor>,
    #[serde(rename = "authorAssociation")]
    author_association: GraphqlAuthorAssociation,
    state: GraphqlIssueState,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GraphqlAuthorAssociation {
    Collaborator,
    Contributor,
    FirstTimer,
    FirstTimeContributor,
    Mannequin,
    Member,
    None,
    Owner,
}

impl GraphqlAuthorAssociation {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Collaborator => "COLLABORATOR",
            Self::Contributor => "CONTRIBUTOR",
            Self::FirstTimer => "FIRST_TIMER",
            Self::FirstTimeContributor => "FIRST_TIME_CONTRIBUTOR",
            Self::Mannequin => "MANNEQUIN",
            Self::Member => "MEMBER",
            Self::None => "NONE",
            Self::Owner => "OWNER",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GraphqlIssueState {
    Open,
    Closed,
}

#[derive(Deserialize)]
struct GraphqlAuthor {
    login: String,
}

#[cfg(test)]
mod tests {
    use super::{GitHubGraphqlMetadataSource, MAX_RESPONSE_BYTES};
    use crate::{
        GitHubIntakeError, GitHubIntakeErrorKind, GitHubIntakeLimits, GitHubMetadataSnapshot,
        collect_github_metadata,
    };
    use std::{
        io::{self, Read, Write},
        net::{TcpListener, TcpStream},
        process::Command,
        sync::mpsc::{self, Receiver},
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };

    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(2);
    const MAX_REQUEST_BYTES: usize = 64 * 1024;

    fn graphql_page(has_next_page: bool) -> String {
        format!(
            r#"{{
                "data": {{
                    "repository": {{
                        "issues": {{
                            "nodes": [{{
                                "id": "I_kwDOfixture",
                                "number": 7,
                                "author": {{"login": "trusted"}},
                                "authorAssociation": "MEMBER",
                                "state": "OPEN",
                                "updatedAt": "2026-09-26T00:00:00Z"
                            }}],
                            "pageInfo": {{"hasNextPage": {has_next_page}}}
                        }}
                    }}
                }}
            }}"#
        )
    }

    fn spawn_fixture(
        listener: TcpListener,
        status: &str,
        headers: &[(&str, &str)],
        payload: String,
        chunked: bool,
    ) -> (Receiver<Result<String, String>>, JoinHandle<()>) {
        let status = status.to_owned();
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        let (sender, receiver) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let result = (|| -> io::Result<String> {
                listener.set_nonblocking(true)?;
                let mut stream = accept_fixture(&listener)?;
                stream.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
                stream.set_write_timeout(Some(FIXTURE_TIMEOUT))?;
                let request = read_request(&mut stream)?;
                match write_response(&mut stream, &status, &headers, &payload, chunked) {
                    Err(error)
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        return Err(error);
                    }
                    _ => {}
                }
                Ok(request)
            })()
            .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        (receiver, handle)
    }

    fn finish_fixture(
        receiver: Receiver<Result<String, String>>,
        handle: JoinHandle<()>,
    ) -> String {
        let request = receiver
            .recv_timeout(FIXTURE_TIMEOUT)
            .expect("fixture thread timed out")
            .expect("fixture failed");
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        while !handle.is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(handle.is_finished(), "fixture join timed out");
        handle.join().expect("fixture thread panicked");
        request
    }

    fn accept_fixture(listener: &TcpListener) -> io::Result<TcpStream> {
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "fixture accept"));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn write_response(
        stream: &mut TcpStream,
        status: &str,
        headers: &[(String, String)],
        payload: &str,
        chunked: bool,
    ) -> io::Result<()> {
        let mut response = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        if chunked {
            response.push_str("Transfer-Encoding: chunked\r\n");
        } else {
            response.push_str(&format!("Content-Length: {}\r\n", payload.len()));
        }
        for (name, value) in headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
        response.push_str("\r\n");
        stream.write_all(response.as_bytes())?;
        if chunked {
            for chunk in payload.as_bytes().chunks(8192) {
                write!(stream, "{:x}\r\n", chunk.len())?;
                stream.write_all(chunk)?;
                stream.write_all(b"\r\n")?;
            }
            stream.write_all(b"0\r\n\r\n")?;
        } else {
            stream.write_all(payload.as_bytes())?;
        }
        Ok(())
    }

    fn read_request(stream: &mut TcpStream) -> io::Result<String> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fixture request closed before headers",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fixture request too large",
                ));
            }
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length").then_some(value)
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fixture content length"))?;
        let body_end = header_end
            .checked_add(content_length)
            .filter(|length| *length <= MAX_REQUEST_BYTES)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "fixture request too large")
            })?;
        while bytes.len() < body_end {
            let remaining = body_end - bytes.len();
            let read_limit = remaining.min(chunk.len());
            let count = stream.read(&mut chunk[..read_limit])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fixture request closed before payload",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fixture request is UTF-8"))
    }

    fn collect_fixture(
        status: &str,
        headers: &[(&str, &str)],
        payload: String,
        chunked: bool,
    ) -> Result<GitHubMetadataSnapshot, GitHubIntakeError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let (receiver, handle) = spawn_fixture(listener, status, headers, payload, chunked);
        let mut source =
            GitHubGraphqlMetadataSource::local_fixture(address, "opaque-fixture-credential")
                .expect("fixture source");
        let result = collect_github_metadata(
            "acme/widget",
            &mut source,
            GitHubIntakeLimits::new(1, 10, 10).expect("limits"),
        );
        let _request = finish_fixture(receiver, handle);
        result
    }

    fn assert_wire_schema_refused(
        label: &str,
        result: Result<GitHubMetadataSnapshot, GitHubIntakeError>,
    ) {
        assert!(
            result.is_err(),
            "{label}: an invalid GraphQL wire value must not become metadata"
        );
    }

    fn graphql_error_page(error_type: &str) -> String {
        format!(
            r#"{{"data":null,"errors":[{{"type":"{error_type}","message":"secret upstream message"}}]}}"#
        )
    }

    fn padded_graphql_page(size: usize) -> String {
        let page = graphql_page(false);
        let prefix = &page[..page.len() - 1];
        let field_prefix = ",\"padding\":\"";
        let field_suffix = "\"}";
        let padding_length = size
            .checked_sub(prefix.len() + field_prefix.len() + field_suffix.len())
            .expect("padded page size");
        let payload = format!(
            "{prefix}{field_prefix}{}{field_suffix}",
            "x".repeat(padding_length)
        );
        assert_eq!(payload.len(), size);
        payload
    }

    #[test]
    fn graphql_source_accepts_a_response_at_the_byte_limit() {
        let result = collect_fixture(
            "200 OK",
            &[],
            padded_graphql_page(MAX_RESPONSE_BYTES),
            false,
        );
        let snapshot = result.expect("the exact response limit is valid");
        assert_eq!(snapshot.issues()[0].number(), 7);
    }

    #[test]
    fn graphql_source_rejects_unknown_length_responses_over_the_byte_limit() {
        let result = collect_fixture(
            "200 OK",
            &[],
            padded_graphql_page(MAX_RESPONSE_BYTES + 1),
            true,
        );
        assert_eq!(
            result
                .expect_err("an unknown-length oversized response must be refused")
                .kind(),
            GitHubIntakeErrorKind::SourceUnavailable
        );
    }

    #[test]
    fn graphql_source_maps_primary_graphql_rate_errors_and_retry_hints() {
        let result = collect_fixture(
            "200 OK",
            &[("x-ratelimit-remaining", "0"), ("retry-after", "30")],
            graphql_error_page("RATE_LIMITED"),
            false,
        );
        let error = result.expect_err("primary rate exhaustion must be typed");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::RateLimited);
        assert_eq!(error.retry_after_seconds(), Some(30));
    }

    #[test]
    fn graphql_source_maps_secondary_graphql_rate_errors_without_remaining_zero() {
        let result = collect_fixture(
            "200 OK",
            &[("x-ratelimit-remaining", "17"), ("retry-after", "45")],
            graphql_error_page("RATE_LIMITED"),
            false,
        );
        let error = result.expect_err("secondary rate exhaustion must be typed");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::RateLimited);
        assert_eq!(error.retry_after_seconds(), Some(45));
    }

    #[test]
    fn graphql_source_keeps_ordinary_graphql_errors_opaque() {
        let result = collect_fixture("200 OK", &[], graphql_error_page("FORBIDDEN"), false);
        let error = result.expect_err("ordinary GraphQL errors must fail closed");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::SourceUnavailable);
        assert_eq!(error.retry_after_seconds(), None);
        assert!(!format!("{error:?}").contains("secret upstream message"));
    }

    #[test]
    fn graphql_source_does_not_classify_permission_403_as_rate_limited() {
        let result = collect_fixture(
            "403 Forbidden",
            &[("x-ratelimit-remaining", "17")],
            graphql_error_page("FORBIDDEN"),
            false,
        );
        let error = result.expect_err("permission failures are not throttling evidence");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::SourceUnavailable);
        assert_eq!(error.retry_after_seconds(), None);
    }

    #[test]
    fn graphql_source_classifies_429_as_rate_limited() {
        let result = collect_fixture(
            "429 Too Many Requests",
            &[("retry-after", "12")],
            graphql_error_page("FORBIDDEN"),
            false,
        );
        let error = result.expect_err("429 must be typed throttling");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::RateLimited);
        assert_eq!(error.retry_after_seconds(), Some(12));
    }

    #[test]
    fn graphql_source_accepts_a_complete_page_with_zero_remaining() {
        let result = collect_fixture(
            "200 OK",
            &[("x-ratelimit-remaining", "0")],
            graphql_page(false),
            false,
        );
        assert!(result.is_ok(), "a complete page is valid at remaining zero");
    }

    #[test]
    fn graphql_source_ignores_ambient_proxy_for_loopback_fixture() {
        if std::env::var_os("ISSUE_249_POISONED_PROXY_CHILD").is_none() {
            let output = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "graphql_source_ignores_ambient_proxy_for_loopback_fixture",
                    "--exact",
                    "--nocapture",
                ])
                .env("ISSUE_249_POISONED_PROXY_CHILD", "1")
                .env("HTTP_PROXY", "http://127.0.0.1:1")
                .env("HTTPS_PROXY", "http://127.0.0.1:1")
                .env("ALL_PROXY", "http://127.0.0.1:1")
                .env("http_proxy", "http://127.0.0.1:1")
                .env("https_proxy", "http://127.0.0.1:1")
                .env("all_proxy", "http://127.0.0.1:1")
                .env_remove("NO_PROXY")
                .env_remove("no_proxy")
                .output()
                .expect("poisoned-proxy child");
            assert!(
                output.status.success(),
                "poisoned-proxy child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let result = collect_fixture("200 OK", &[], graphql_page(false), false);
        assert!(
            result.is_ok(),
            "the loopback fixture must bypass ambient proxies"
        );
    }

    #[test]
    fn graphql_source_enforces_documented_wire_enums_and_scalars() {
        let valid_cases = vec![
            ("documented values", graphql_page(false), 7),
            (
                "alternate association",
                graphql_page(false).replace("MEMBER", "FIRST_TIMER"),
                7,
            ),
            (
                "fractional UTC datetime",
                graphql_page(false).replace("2026-09-26T00:00:00Z", "2026-09-26T00:00:00.123Z"),
                7,
            ),
            (
                "maximum GraphQL Int",
                graphql_page(false).replace("\"number\": 7", "\"number\": 2147483647"),
                2_147_483_647,
            ),
        ];
        for (label, payload, expected_number) in valid_cases {
            let snapshot = collect_fixture("200 OK", &[], payload, false)
                .unwrap_or_else(|error| panic!("{label} should be accepted: {error:?}"));
            assert_eq!(snapshot.issues()[0].number(), expected_number, "{label}");
        }

        let invalid_cases = vec![
            (
                "unknown author association",
                graphql_page(false).replace("MEMBER", "ALIEN"),
            ),
            (
                "non-UTC datetime",
                graphql_page(false).replace("2026-09-26T00:00:00Z", "2026-09-26 00:00:00Z"),
            ),
            (
                "GraphQL Int overflow",
                graphql_page(false).replace("\"number\": 7", "\"number\": 2147483648"),
            ),
            (
                "empty GraphQL ID",
                graphql_page(false).replace("I_kwDOfixture", ""),
            ),
        ];
        for (label, payload) in invalid_cases {
            assert_wire_schema_refused(label, collect_fixture("200 OK", &[], payload, false));
        }
    }

    #[test]
    fn graphql_source_requests_only_metadata_and_returns_one_page_provenance() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let (receiver, handle) = spawn_fixture(
            listener,
            "200 OK",
            &[
                ("x-ratelimit-remaining", "17"),
                ("x-ratelimit-reset", "1800000000"),
            ],
            graphql_page(false),
            false,
        );
        let mut source =
            GitHubGraphqlMetadataSource::local_fixture(address, "opaque-fixture-credential")
                .expect("fixture source");

        let snapshot = collect_github_metadata(
            "acme/widget",
            &mut source,
            GitHubIntakeLimits::new(1, 10, 10).expect("limits"),
        )
        .expect("metadata snapshot");
        let request = finish_fixture(receiver, handle);
        let request_lower = request.to_ascii_lowercase();
        let payload = request.split_once("\r\n\r\n").expect("request payload").1;

        assert!(request.starts_with("POST /graphql HTTP/1.1\r\n"));
        assert!(request_lower.contains("authorization: bearer "));
        assert!(payload.contains("\"owner\":\"acme\""));
        assert!(payload.contains("\"name\":\"widget\""));
        assert!(payload.contains("\"first\":10"));
        for field in [
            "number",
            "author",
            "authorAssociation",
            "state",
            "updatedAt",
            "id",
        ] {
            assert!(payload.contains(field), "missing requested field {field}");
        }
        for field in ["title", "comments", "body", "pullRequest"] {
            assert!(!payload.contains(field), "unexpected field {field}");
        }
        assert_eq!(snapshot.pages(), 1);
        assert_eq!(snapshot.issues()[0].number(), 7);
        assert_eq!(snapshot.issues()[0].author(), "trusted");
        assert!(
            snapshot
                .snapshot()
                .starts_with("github-graphql-one-page-response:")
        );
    }

    #[test]
    fn graphql_source_rejects_a_required_second_page() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let (receiver, handle) = spawn_fixture(listener, "200 OK", &[], graphql_page(true), false);
        let mut source = GitHubGraphqlMetadataSource::local_fixture(address, "opaque-credential")
            .expect("fixture source");

        let error = collect_github_metadata(
            "acme/widget",
            &mut source,
            GitHubIntakeLimits::new(3, 10, 10).expect("limits"),
        )
        .expect_err("a second page cannot be called a stable snapshot");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::SourceUnavailable);
        let _request = finish_fixture(receiver, handle);
    }
}
