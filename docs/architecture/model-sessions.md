# Caller-owned model conversations

`ModelInvocationSpec::invoke` and `ModelRoutePolicy::invoke` remain stateless.
Their prompt bytes, invocation identity, and default behavior do not depend on a
session service. Opt in with `invoke_in_session` or `invoke_in_session_validated`.

The caller creates and retains an ADK `SessionService` and an existing typed
`adk_rust::AdkIdentity` containing the app name, user ID, and session ID. Create a
session with ADK's `CreateRequest` before invoking. A new invocation object can
resume the same conversation by using the same service and full identity. The
shipped `InMemorySessionService` retains conversations while that service lives;
this API does not provide process-restart persistence or create missing sessions.

For route calls, pass the spec, credential broker, cancellation token, service,
and identity to `ModelRoutePolicy::invoke_in_session`. The policy authorizes each
candidate before its I/O; the first authorized candidate admits the logical
session operation before credential resolution. Direct spec calls require an
already authorized matching binding and also take an absolute `Instant` deadline
and cancellation token. A mismatched binding fails before session I/O.

History is loaded once and projected by ADK's official `MutableSession` rather
than by a second history algorithm. This API uses its unscoped projection:
compaction is honored, partial events are omitted, and all branches are visible.
The model receives the current protocol
system message, projected prior conversation, and current rendered user message.
The user is appended once before inference. Validation retries and route fallback
share that fixed history and user message. Only a completed Stop whose output
passes domain and schema validation permits an assistant append. The stored
assistant is the accepted JSON value in canonical form; provider usage and other
raw provider metadata are not stored as conversation content.

The same absolute route deadline and cancellation cover loading, both appends,
credential resolution, and model collection. Store errors are typed `Session`
failures and never trigger stateless or provider fallback. I/O futures are owned
by the call and dropped on cancellation; no detached store work is launched.

Persistence is not transactional. An unsuccessful call can retain its user
message. A backend may already have committed an append when an error or
cancellation is observed; the caller must reconcile such backend outcomes.
Invalid or partial assistant output is never submitted for persistence.

Callers must serialize concurrent calls for one identity. Injected backends must
implement full `(app, user, session)` addressing for typed get and append. ADK's
`SessionService::append_event_for_identity` legacy default delegates using only a
bare session ID; a backend that permits repeated bare IDs must override it. The
shipped in-memory service supplies the required full-identity override. The kit
checks the loaded snapshot identity and uses the typed methods exclusively.

Session-enabled provenance adds `session_history_digest()`, a digest of the full
identity and projected prior content. That digest participates in invocation
identity and deterministic seed, while stateless provenance returns `None`.
Only the digest is exposed: no session identity or raw history is added to
provenance or diagnostics.
