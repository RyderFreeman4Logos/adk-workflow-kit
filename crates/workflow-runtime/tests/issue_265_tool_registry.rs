use std::{fs, num::NonZeroU64, sync::Arc, time::Duration};

use serde_json::{Value, json};
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, InMemoryArtifactStore, PageRequest, ReadSourceRangeTool,
    RunContext, RunId, RunLimits, RunSandbox, SandboxCapability, SearchCodeTool, ToolBridge,
    ToolCall, ToolCallContext, ToolEnvelope, ToolHandler, ToolImplementationRegistry,
    ToolImplementationRegistryError, ToolProvenance, WorkdirManager,
};

struct EchoTool;

impl ToolHandler for EchoTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
        Ok(ToolEnvelope::success(
            arguments.clone(),
            ToolProvenance::new("echo", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        "echo:1".to_owned()
    }
}

struct EmptyIdentityTool;

impl ToolHandler for EmptyIdentityTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
        Ok(ToolEnvelope::success(
            arguments.clone(),
            ToolProvenance::new("echo", "1"),
        ))
    }
}

fn sandbox() -> RunSandbox {
    let root =
        std::env::temp_dir().join(format!("workflow-runtime-issue-265-{}", std::process::id()));
    fs::create_dir_all(&root).expect("fixture root");
    let context = RunContext::new(
        RunId::new("issue-265".to_owned()).expect("fixture run ID"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(4_096).expect("positive"),
        ),
    );
    let workdir = WorkdirManager::new(&root)
        .expect("fixture root trusted")
        .allocate(context.run_id())
        .expect("fixture workdir");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead]).expect("fixture sandbox")
}

fn repo() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-repo-{}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("src")).expect("repo");
    fs::write(
        root.join("src/retry.rs"),
        "pub fn default_retry() -> u8 { 3 }\n",
    )
    .expect("retry");
    fs::write(
        root.join("src/lib.rs"),
        "pub fn run() -> u8 { default_retry() }\n",
    )
    .expect("lib");
    root
}

fn authority() -> CapabilityIntersection {
    CapabilityIntersection::new(
        [SandboxCapability::FilesystemRead],
        ["search_code"],
        ["search_code"],
        std::iter::empty::<String>(),
        ["search_code"],
        ["search_code"],
        [SandboxCapability::FilesystemRead],
    )
}

#[test]
fn register_resolves_exact_id_and_version() {
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("echo", "1", Arc::new(EchoTool))
        .expect("register");
    assert!(registry.resolve("echo", "1").is_ok());
    assert!(registry.resolve("echo", "2").is_err());
    assert!(registry.resolve("search_code", "1").is_err());
}

#[test]
fn register_rejects_empty_implementation_identity() {
    let mut registry = ToolImplementationRegistry::new();
    assert_eq!(
        registry
            .register("echo", "1", Arc::new(EmptyIdentityTool))
            .expect_err("empty identity must fail closed"),
        ToolImplementationRegistryError::InvalidIdentity
    );

    let mut first = ToolImplementationRegistry::new();
    first
        .register(
            "echo",
            "1",
            Arc::from(
                |_: &ChildSandbox<'_>, _: &ToolCallContext, arguments: &Value| {
                    Ok(ToolEnvelope::success(
                        arguments.clone(),
                        ToolProvenance::new("echo", "1"),
                    ))
                },
            ),
        )
        .expect_err("default closure identity must fail closed");
    assert_eq!(
        registry
            .register("echo", "2", Arc::new(NulIdentityTool))
            .expect_err("NUL in identity must fail closed"),
        ToolImplementationRegistryError::InvalidIdentity
    );
}

struct NulIdentityTool;

impl ToolHandler for NulIdentityTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
        Ok(ToolEnvelope::success(
            arguments.clone(),
            ToolProvenance::new("echo", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        "echo\0v1".to_owned()
    }
}

#[test]
fn registry_identity_does_not_collide_across_nul_field_boundaries() {
    let mut left = ToolImplementationRegistry::new();
    let left_ok = left.register("a\0b", "c", Arc::new(EchoTool));
    let mut right = ToolImplementationRegistry::new();
    let right_ok = right.register("a", "b\0c", Arc::new(EchoTool));
    assert!(
        left_ok.is_err() || right_ok.is_err() || left.identity() != right.identity(),
        "id/version NUL must not collapse distinct registry entries into one identity"
    );
}

#[test]
fn search_code_returns_argument_dependent_repo_hits() {
    let repo = repo();
    let tool = SearchCodeTool::new(&repo);
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(tool.clone()))
        .expect("register search_code");
    let mut other = ToolImplementationRegistry::new();
    other
        .register(
            "search_code",
            "1",
            Arc::new(SearchCodeTool::new(repo.join("src"))),
        )
        .expect("register other root");
    assert_ne!(
        registry.identity(),
        other.identity(),
        "implementation config participates in resume identity"
    );

    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(
            tool.registration(),
            registry.resolve("search_code", "1").expect("resolve"),
        )
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );

    let retry = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "retry",
                "actor",
                json!({"query": "default_retry", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("retry search");
    let run = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "run",
                "actor",
                json!({"query": "pub fn run", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("run search");
    assert_ne!(
        retry, run,
        "valid arguments must not share a fabricated result"
    );
    match retry {
        ToolEnvelope::Success { payload, .. } => {
            assert!(payload.to_string().contains("retry.rs"), "{payload}");
        }
        other => panic!("expected hits, got {other:?}"),
    }

    let denied = bridge.invoke(
        ToolCall::new(
            "search_code",
            "escape",
            "actor",
            json!({"query": "retry", "path": "../secrets"}),
        ),
        &authority(),
        None,
        Duration::ZERO,
        &mut artifacts,
    );
    assert!(denied.is_err() || matches!(denied, Ok(ToolEnvelope::Failure { .. })));
}

#[test]
fn search_code_over_inline_ceiling_returns_artifact_page() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-page-{}",
        std::process::id()
    ));
    fs::create_dir_all(repo.join("src")).expect("repo");
    let snippet = "needle ".repeat(80);
    let mut source = String::new();
    for index in 0..400 {
        source.push_str(&format!("hit {index} {snippet}\n"));
    }
    fs::write(repo.join("src/lib.rs"), source).expect("large search corpus");

    let tool = SearchCodeTool::new(&repo);
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(tool.clone()))
        .expect("register search_code");
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(
            tool.registration(),
            registry.resolve("search_code", "1").expect("resolve"),
        )
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(2 * 1024 * 1024).expect("positive"),
        NonZeroU64::new(4_096).expect("positive"),
    );
    let result = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "page",
                "actor",
                json!({"query": "needle", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("over-ceiling search must page, not fail");
    let handle = result
        .artifact_id()
        .expect("over-ceiling search must return an artifact handle");
    assert!(result.next_offset().is_some());
    let page = bridge
        .read_artifact_page(
            &artifacts,
            handle,
            PageRequest::new(0, NonZeroU64::new(1_024).expect("positive")),
        )
        .expect("paged search artifact must be readable");
    assert!(!page.bytes().is_empty());
}

fn search_payload(result: &workflow_runtime::ToolEnvelope<Value>) -> Value {
    match result {
        workflow_runtime::ToolEnvelope::Success { payload, .. } => payload.clone(),
        other => panic!("expected success, got {other:?}"),
    }
}

#[test]
fn search_code_skips_nested_denied_dirs_without_omitted_path() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-deny-{}",
        std::process::id()
    ));
    fs::create_dir_all(repo.join("src")).expect("src");
    fs::create_dir_all(repo.join("secrets")).expect("denied dir");
    fs::create_dir_all(repo.join("src/secrets")).expect("nested denied dir");
    fs::write(repo.join("src/lib.rs"), "pub fn canary_source() {}\n").expect("source");
    fs::write(repo.join("secrets/token.txt"), "canary_secret_token\n").expect("denied canary");
    fs::write(
        repo.join("src/secrets/nested.txt"),
        "canary_nested_secret\n",
    )
    .expect("nested denied canary");

    let tool = SearchCodeTool::new(&repo);
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(tool.registration(), tool)
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );

    let omitted = bridge
        .invoke(
            ToolCall::new("search_code", "omit", "actor", json!({"query": "canary"})),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("omitted path must search");
    let omitted = search_payload(&omitted).to_string();
    assert!(omitted.contains("lib.rs"), "{omitted}");
    assert!(
        !omitted.contains("canary_secret_token")
            && !omitted.contains("canary_nested_secret")
            && !omitted.contains("secrets/"),
        "{omitted}"
    );

    let ancestor = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "ancestor",
                "actor",
                json!({"query": "canary", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("safe ancestor must search");
    let ancestor = search_payload(&ancestor).to_string();
    assert!(ancestor.contains("lib.rs"), "{ancestor}");
    assert!(
        !ancestor.contains("canary_secret_token") && !ancestor.contains("canary_nested_secret"),
        "{ancestor}"
    );
}

#[test]
fn search_code_hard_caps_matches_and_line_bytes() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-bounds-{}",
        std::process::id()
    ));
    for index in 0..12 {
        let dir = repo.join(format!("src{index}"));
        fs::create_dir_all(&dir).expect("wide tree");
        let mut source = String::new();
        for line in 0..200 {
            source.push_str(&format!("needle {index}-{line}\n"));
        }
        fs::write(dir.join("lib.rs"), source).expect("hits");
    }
    fs::create_dir_all(repo.join("long")).expect("long dir");
    let mut overlong = "x".repeat(8_192);
    overlong.push_str("needle-overlong\n");
    fs::write(repo.join("long/line.rs"), overlong).expect("overlong");

    let tool = SearchCodeTool::new(&repo);
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(tool.registration(), tool)
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(2 * 1024 * 1024).expect("positive"),
        NonZeroU64::new(4_096).expect("positive"),
    );

    let wide = bridge
        .invoke(
            ToolCall::new("search_code", "wide", "actor", json!({"query": "needle"})),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("wide search");
    let payload = search_payload(&wide);
    let matches = payload["matches"]
        .as_array()
        .unwrap_or_else(|| panic!("matches array, {payload}"));
    assert_eq!(
        matches.len(),
        1_024,
        "MAX_SEARCH_MATCHES must be a hard cap, got {}",
        matches.len()
    );
    assert!(
        matches.iter().all(|hit| {
            hit["snippet"].as_str().is_some_and(|snippet| {
                snippet.len() <= 4_096 && !snippet.contains("needle-overlong")
            })
        }),
        "{payload}"
    );
}

fn invoke_search(
    tool: SearchCodeTool,
    query: &str,
    path: Option<&str>,
) -> Result<workflow_runtime::ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(tool.registration(), tool)
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );
    let mut args = json!({"query": query});
    if let Some(path) = path {
        args["path"] = json!(path);
    }
    bridge.invoke(
        ToolCall::new("search_code", "search", "actor", args),
        &authority(),
        None,
        Duration::ZERO,
        &mut artifacts,
    )
}

fn invoke_read(
    tool: ReadSourceRangeTool,
    path: &str,
    start_line: usize,
    end_line: usize,
) -> Result<workflow_runtime::ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
    let authority = CapabilityIntersection::new(
        [SandboxCapability::FilesystemRead],
        ["read_source_range"],
        ["read_source_range"],
        std::iter::empty::<String>(),
        ["read_source_range"],
        ["read_source_range"],
        [SandboxCapability::FilesystemRead],
    );
    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(tool.registration(), tool)
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );
    bridge.invoke(
        ToolCall::new(
            "read_source_range",
            "read",
            "actor",
            json!({"path": path, "start_line": start_line, "end_line": end_line}),
        ),
        &authority,
        None,
        Duration::ZERO,
        &mut artifacts,
    )
}

#[test]
fn repo_tools_deny_safe_named_symlink_aliases() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-symlink-{}",
        std::process::id()
    ));
    fs::create_dir_all(repo.join("src")).expect("src");
    fs::write(repo.join("src/lib.rs"), "pub fn canary_source() {}\n").expect("source");
    fs::write(repo.join(".env"), "canary_secret_token=1\n").expect("denied file");
    fs::create_dir_all(repo.join("secrets")).expect("denied dir");
    fs::write(repo.join("secrets/token.txt"), "canary_nested_secret\n").expect("denied nested");
    std::os::unix::fs::symlink(repo.join(".env"), repo.join("src/notes.rs")).expect("file alias");
    std::os::unix::fs::symlink(repo.join("secrets"), repo.join("docs")).expect("dir alias");

    let search = invoke_search(SearchCodeTool::new(&repo), "canary", Some("docs"));
    assert!(
        search.is_err() || matches!(search, Ok(workflow_runtime::ToolEnvelope::Failure { .. })),
        "search alias must fail closed, got {search:?}"
    );
    let read = invoke_read(ReadSourceRangeTool::new(&repo), "src/notes.rs", 1, 1);
    assert!(
        read.is_err() || matches!(read, Ok(workflow_runtime::ToolEnvelope::Failure { .. })),
        "read alias must fail closed, got {read:?}"
    );
}

#[test]
fn read_source_range_bounds_before_whole_file() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-range-{}",
        std::process::id()
    ));
    fs::create_dir_all(repo.join("src")).expect("src");
    let oversized = repo.join("src/huge.rs");
    let mut file = fs::File::create(&oversized).expect("create oversized");
    use std::io::Write;
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..80 {
        file.write_all(&chunk).expect("write chunk");
    }
    file.write_all(b"\ncanary_last_line\n").expect("tail");
    drop(file);

    let before = fs::read_to_string("/proc/self/io").ok().and_then(|text| {
        text.lines()
            .find_map(|line| line.strip_prefix("rchar: "))
            .and_then(|value| value.parse::<u64>().ok())
    });
    let result = invoke_read(ReadSourceRangeTool::new(&repo), "src/huge.rs", 1, 1);
    assert!(
        result.is_err() || matches!(result, Ok(workflow_runtime::ToolEnvelope::Failure { .. })),
        "oversized file must fail closed, got {result:?}"
    );
    if let Some(before) = before {
        let after = fs::read_to_string("/proc/self/io")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("rchar: "))
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .expect("rchar after");
        assert!(
            after.saturating_sub(before) < 2 * 1024 * 1024,
            "range reader must not ingest the whole oversized file, read {}",
            after.saturating_sub(before)
        );
    }
}

#[test]
fn search_code_stops_miss_heavy_traversal_within_budget() {
    let repo = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-budget-{}",
        std::process::id()
    ));
    for dir in 0..40 {
        let nested = repo.join(format!("wide{dir}"));
        fs::create_dir_all(&nested).expect("wide dir");
        for file in 0..40 {
            fs::write(
                nested.join(format!("f{file}.rs")),
                "pub fn miss() {}\n".repeat(80),
            )
            .expect("miss file");
        }
    }
    let result = invoke_search(SearchCodeTool::new(&repo), "no-such-canary-token", None);
    assert!(
        result.is_err() || matches!(result, Ok(workflow_runtime::ToolEnvelope::Failure { .. })),
        "miss-heavy walk must fail closed instead of unbounded scanning, got {result:?}"
    );
}
