# Sandbox Contract

`workflow-runtime` treats capabilities as an allowlist. `SandboxCapability` values are explicit; requested capabilities are intersected with backend and policy capabilities. Missing capabilities produce a typed denial instead of silently widening access.

## Context policy

`evaluate_context_policy` checks every `PolicyLayer` before capability intersection:

- the subject tenant must be allowed by every layer;
- the subject role must be allowed by every layer;
- the subject `Classification` must not exceed any layer maximum;
- network access requires an approved non-`None` `NetworkProfile`;
- brokered destinations must be in the intersected allowlist;
- incompatible profiles fail closed.

`ContextPolicyDeniedKind` distinguishes `MissingSubject`, `RoleDenied`, `TenantMismatch`, `ClassificationDenied`, `NetworkProfileRequired`, `DestinationDenied`, `CapabilityDenied`, and `InvalidPolicy`. `EffectivePolicy` exposes only the resulting capabilities, network profile, and brokered destination allowlist.

## Privacy and parsing

`NetworkDestination` validates host and port at construction and deserialization. Policy structures reject unknown fields. `ContextPolicyDenied` diagnostics contain stable denial categories and missing capability names, not tenant, role, host, port, or payload values. Debug and display output therefore redact untrusted boundary data.

The sandbox contract documents policy evaluation only. It does not claim to be a new process, filesystem, network, or WASM backend; those effects remain owned by the caller/platform boundary.
