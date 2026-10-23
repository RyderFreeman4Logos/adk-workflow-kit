//! Real OpenAI-compatible SSE exercised through the official agent and public observer.

use super::*;
use adk_rust::agent::LlmAgentBuilder;
use adk_rust::model::{OpenAICompatible, OpenAICompatibleConfig, RetryConfig};
use std::{io, num::NonZeroU64, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Instant, timeout_at},
};

async fn serve_sse(listener: TcpListener, deadline: Instant) -> io::Result<Vec<u8>> {
    timeout_at(deadline, async move {
        let (mut socket, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        let header_end = loop {
            if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break end + 4;
            }
            let read = socket.read(&mut buffer).await?;
            if read == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
            request.extend_from_slice(&buffer[..read]);
            if request.len() > 64 * 1024 { return Err(io::ErrorKind::InvalidData.into()); }
        };
        let header = std::str::from_utf8(&request[..header_end])
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let length: usize = header.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().ok()).flatten()
        }).ok_or(io::ErrorKind::InvalidData)?;
        let total = header_end.checked_add(length).filter(|total| *total <= 64 * 1024)
            .ok_or(io::ErrorKind::InvalidData)?;
        while request.len() < total {
            let remaining = (total - request.len()).min(buffer.len());
            let read = socket.read(&mut buffer[..remaining]).await?;
            if read == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
            request.extend_from_slice(&buffer[..read]);
        }
        let mut body = String::new();
        for (delta, finish) in [
            (json!({"content": r#"{"output":{"answer":"#}), serde_json::Value::Null),
            (json!({"content": r#""ok"},"status":"finished"}"#}), serde_json::Value::Null),
            (json!({}), json!("stop")),
        ] {
            body.push_str(&format!("data: {}\n\n", json!({
                "id":"synthetic-wire-response", "object":"chat.completion.chunk",
                "model":"loopback-sse", "choices":[{"index":0,"delta":delta,"finish_reason":finish}]
            })));
        }
        body.push_str("data: [DONE]\n\n");
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
        socket.shutdown().await?;
        Ok(request)
    }).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[tokio::test]
async fn official_http_sse_preserves_partial_and_final_audit_events() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let model = OpenAICompatible::new_no_auth(
        OpenAICompatibleConfig::new("", "loopback-sse").with_base_url(endpoint),
    )
    .unwrap()
    .with_retry_config(RetryConfig::disabled());
    let agent: Arc<dyn Agent> = Arc::new(
        LlmAgentBuilder::new("agent")
            .model(Arc::new(model))
            .max_iterations(1)
            .build()
            .unwrap(),
    );
    let plan = compile_str("sse.workflow.toml", SEQUENTIAL).unwrap();
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &BTreeMap::from([("agent".into(), agent)]))
        .unwrap();
    let mut mapper = AdkEventMapper::new("wire-observed", "sequential").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(64 * 1024).unwrap(),
        NonZeroU64::new(64 * 1024).unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    // Both futures settle under the same absolute deadline; no detached server survives an assertion.
    let (request, result) = tokio::join!(
        serve_sse(listener, deadline),
        timeout_at(
            deadline,
            graph.invoke_observed(
                State::new(),
                ExecutionConfig::new("wire-observed"),
                &mut mapper,
                &mut artifacts
            )
        )
    );
    let request = request.expect("finite SSE server completed");
    let header_end = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let header = std::str::from_utf8(&request[..header_end]).unwrap();
    assert!(header.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(!header.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    }));
    let body: serde_json::Value = serde_json::from_slice(&request[header_end..]).unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["model"], "loopback-sse");
    assert!(body["messages"].is_array());
    let state = result
        .expect("bounded official SDK HTTP SSE")
        .expect("SDK response identity is distinct from each audit observation identity");
    assert_eq!(state.get("node:agent"), Some(&json!({"answer":"ok"})));
    let model_events: Vec<_> = mapper
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ModelRequestCompleted)
        .collect();
    assert_eq!(model_events.len(), 3);
    assert_eq!(
        model_events.last().unwrap().payload()["finish_reason"],
        "stop"
    );
    assert_eq!(
        mapper
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        mapper.events().len()
    );
    assert_eq!(
        mapper.events().last().unwrap().kind(),
        WorkflowRuntimeEventKindV1::WorkflowCompleted
    );
}
