use reqwest::{
    StatusCode,
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER, USER_AGENT},
    redirect::Policy,
};
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::json;
use sha2::{Digest, Sha256};
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
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_u64_header);
        if matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        ) {
            return Err(GitHubIntakeError::rate_limited(retry_after));
        }
        if !response.status().is_success() {
            return Err(GitHubIntakeError::source_unavailable());
        }
        let remaining = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(parse_u64_header)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let reset = response
            .headers()
            .get("x-ratelimit-reset")
            .and_then(parse_u64_header);
        let bytes = response
            .bytes()
            .map_err(|_| GitHubIntakeError::source_unavailable())?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(GitHubIntakeError::source_unavailable());
        }
        let envelope: GraphqlResponse =
            serde_json::from_slice(&bytes).map_err(|_| GitHubIntakeError::source_unavailable())?;
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
            let author = node
                .author
                .ok_or_else(GitHubIntakeError::source_unavailable)?;
            let state = match node.state.as_str() {
                "OPEN" => GitHubIssueState::Open,
                "CLOSED" => GitHubIssueState::Closed,
                _ => return Err(GitHubIntakeError::source_unavailable()),
            };
            let issue = GitHubIssueMetadata::new(
                node.number,
                author.login,
                node.author_association,
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

#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    errors: Option<IgnoredAny>,
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
    #[allow(dead_code)]
    id: String,
    number: u64,
    author: Option<GraphqlAuthor>,
    #[serde(rename = "authorAssociation")]
    author_association: String,
    state: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Deserialize)]
struct GraphqlAuthor {
    login: String,
}

#[cfg(test)]
mod tests {
    use super::GitHubGraphqlMetadataSource;
    use crate::{GitHubIntakeErrorKind, GitHubIntakeLimits, collect_github_metadata};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
    };

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
    ) -> JoinHandle<String> {
        let status = status.to_owned();
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fixture request");
            let request = read_request(&mut stream);
            let mut response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                payload.len()
            );
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            response.push_str(&payload);
            stream
                .write_all(response.as_bytes())
                .expect("fixture response");
            request
        })
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk).expect("fixture request bytes");
            assert!(count > 0, "fixture request closed before headers");
            bytes.extend_from_slice(&chunk[..count]);
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
            .expect("fixture content length");
        while bytes.len() < header_end + content_length {
            let count = stream.read(&mut chunk).expect("fixture request body");
            assert!(count > 0, "fixture request closed before payload");
            bytes.extend_from_slice(&chunk[..count]);
        }
        String::from_utf8(bytes).expect("fixture request is UTF-8")
    }

    #[test]
    fn graphql_source_requests_only_metadata_and_returns_one_page_provenance() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let handle = spawn_fixture(
            listener,
            "200 OK",
            &[
                ("x-ratelimit-remaining", "17"),
                ("x-ratelimit-reset", "1800000000"),
            ],
            graphql_page(false),
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
        let request = handle.join().expect("fixture thread");
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
        let handle = spawn_fixture(listener, "200 OK", &[], graphql_page(true));
        let mut source = GitHubGraphqlMetadataSource::local_fixture(address, "opaque-credential")
            .expect("fixture source");

        let error = collect_github_metadata(
            "acme/widget",
            &mut source,
            GitHubIntakeLimits::new(3, 10, 10).expect("limits"),
        )
        .expect_err("a second page cannot be called a stable snapshot");
        assert_eq!(error.kind(), GitHubIntakeErrorKind::SourceUnavailable);
        let _ = handle.join().expect("fixture thread");
    }
}
