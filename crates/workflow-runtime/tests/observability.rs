use std::fmt::Debug;

use workflow_runtime::{
    CallLedgerRecord, EventCounts, ObservabilityError, OtelMapping, RedactedEvent, RunStatus,
    SensitiveSnapshot, SensitiveSnapshotKind, ToolProvenance,
};

const CANARY_COT: &str = "CANARY_COT_52";
const CANARY_SECRET: &str = "CANARY_SECRET_52";

fn counts() -> EventCounts {
    EventCounts::new(2, 3)
}

fn assert_snapshot_is_redacted<T: Debug + serde::Serialize + std::fmt::Display>(value: &T) {
    let debug = format!("{value:?}");
    let display = value.to_string();
    let json = match serde_json::to_string(value) {
        Ok(json) => json,
        Err(error) => panic!("snapshot serialization failed: {error}"),
    };
    for rendered in [debug, display, json] {
        assert!(!rendered.contains(CANARY_COT), "leaked CoT in {rendered}");
        assert!(
            !rendered.contains(CANARY_SECRET),
            "leaked secret in {rendered}"
        );
    }
}

fn assert_sensitive_rejected(error: ObservabilityError, kind: SensitiveSnapshotKind) {
    assert_eq!(error.sensitive_kind(), Some(kind));
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(CANARY_COT));
    assert!(!rendered.contains(CANARY_SECRET));
}

#[test]
fn redacted_event_rejects_sensitive_snapshots_and_exposes_safe_metadata() {
    let cot_error = RedactedEvent::try_new(
        "tool_call",
        "TOOL_CALL",
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        Some(SensitiveSnapshot::chain_of_thought(CANARY_COT)),
    )
    .expect_err("CoT snapshots must fail closed");
    assert_sensitive_rejected(cot_error, SensitiveSnapshotKind::ChainOfThought);

    let secret_error = RedactedEvent::try_new(
        "tool_call",
        "TOOL_CALL",
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        Some(SensitiveSnapshot::raw_secret(CANARY_SECRET)),
    )
    .expect_err("raw secret snapshots must fail closed");
    assert_sensitive_rejected(secret_error, SensitiveSnapshotKind::RawSecret);

    let event = RedactedEvent::try_new(
        "tool_call",
        "TOOL_CALL",
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        None,
    )
    .expect("safe event metadata must be accepted");
    assert_eq!(event.kind(), "tool_call");
    assert_eq!(event.code(), "TOOL_CALL");
    assert_eq!(event.redaction(), "<redacted>");
    assert_snapshot_is_redacted(&event);
}

#[test]
fn call_ledger_rejects_sensitive_snapshots_and_keeps_provenance() {
    let provenance = ToolProvenance::new("search", "1");
    let cot_error = CallLedgerRecord::try_new(
        7,
        provenance.clone(),
        RunStatus::Failed,
        counts(),
        Some(SensitiveSnapshot::chain_of_thought(CANARY_COT)),
    )
    .expect_err("CoT snapshots must fail closed");
    assert_sensitive_rejected(cot_error, SensitiveSnapshotKind::ChainOfThought);

    let secret_error = CallLedgerRecord::try_new(
        7,
        provenance.clone(),
        RunStatus::Failed,
        counts(),
        Some(SensitiveSnapshot::raw_secret(CANARY_SECRET)),
    )
    .expect_err("raw secret snapshots must fail closed");
    assert_sensitive_rejected(secret_error, SensitiveSnapshotKind::RawSecret);

    let record = CallLedgerRecord::try_new(7, provenance, RunStatus::Failed, counts(), None)
        .expect("safe call-ledger metadata must be accepted");
    assert_eq!(record.call_index(), 7);
    assert_eq!(record.tool().tool_id(), "search");
    assert_eq!(record.redaction(), "<redacted>");
    assert_snapshot_is_redacted(&record);
}

#[test]
fn otel_mapping_rejects_sensitive_snapshots_and_maps_only_safe_attributes() {
    let cot_error = OtelMapping::try_new(
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        Some(SensitiveSnapshot::chain_of_thought(CANARY_COT)),
    )
    .expect_err("CoT snapshots must fail closed");
    assert_sensitive_rejected(cot_error, SensitiveSnapshotKind::ChainOfThought);

    let secret_error = OtelMapping::try_new(
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        Some(SensitiveSnapshot::raw_secret(CANARY_SECRET)),
    )
    .expect_err("raw secret snapshots must fail closed");
    assert_sensitive_rejected(secret_error, SensitiveSnapshotKind::RawSecret);

    let event = RedactedEvent::try_new(
        "tool_call",
        "TOOL_CALL",
        "workflow.tool",
        RunStatus::Completed,
        counts(),
        None,
    )
    .expect("safe event metadata must be accepted");
    let mapping = OtelMapping::from_event(&event);
    assert_eq!(mapping.span_name(), "workflow.tool");
    assert_eq!(
        mapping.attributes().get("event.kind"),
        Some(&"tool_call".to_owned())
    );
    assert_eq!(
        mapping.attributes().get("redaction"),
        Some(&"<redacted>".to_owned())
    );
    assert_snapshot_is_redacted(&mapping);
}
