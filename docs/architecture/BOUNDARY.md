# Architecture Boundary

This boundary accepts and makes explicit the limits in [ADR-0001](adrs/ADR-0001.md) and [ADR-0013](adrs/ADR-0013.md).

- ADK-Rust imports belong only in designated compatibility crate(s); currently that boundary is `workflow-adk`.
- Applications remain the source of truth for their domains, authoritative stores, ACLs, and product semantics.
- Platform core must not absorb application-domain models, stores, ACLs, or semantics. Application adapters validate every crossing.

These are dependency and ownership rules, not runtime behavior or provider configuration.