# Accepted Architecture Decisions

The following decisions accept the proposed initial set in [planning-pack 18](../planning-pack/18_INITIAL_ARCHITECTURE_DECISIONS.md). The planning pack remains immutable; these files are the accepted record.

| Accepted ADR | Proposal | Title |
|---|---|---|
| [ADR-0001](ADR-0001.md) | A | Build above ADK-Rust rather than another agent framework |
| [ADR-0002](ADR-0002.md) | B | Declarative workflows are production artifacts |
| [ADR-0003](ADR-0003.md) | C | TOML is the first authoring format; canonical IR is authoritative |
| [ADR-0004](ADR-0004.md) | D | Closed node and route sets |
| [ADR-0005](ADR-0005.md) | E | Per-run workdir and verified sandbox |
| [ADR-0006](ADR-0006.md) | F | Network denied by default |
| [ADR-0007](ADR-0007.md) | G | Skills are instructions and resources, not authority |
| [ADR-0008](ADR-0008.md) | H | Skill scripts are declared by ID |
| [ADR-0009](ADR-0009.md) | I | Objective validators outrank model reviewers |
| [ADR-0010](ADR-0010.md) | J | All review and correction cycles are bounded |
| [ADR-0011](ADR-0011.md) | K | Producer and reviewer sessions are isolated |
| [ADR-0012](ADR-0012.md) | L | Large stage outputs become artifacts |
| [ADR-0013](ADR-0013.md) | M | Domain source truth remains in applications |
| [ADR-0014](ADR-0014.md) | N | Exact stable dependency pins and committed lockfiles |
| [ADR-0015](ADR-0015.md) | O | Extract with characterization tests |
| [ADR-0016](ADR-0016.md) | P | CLI is thin over libraries |
| [ADR-0017](ADR-0017.md) | Q | Upstream contributions preferred to long-lived fork |
| [ADR-0018](ADR-0018.md) | R | No hidden chain-of-thought persistence |
| [ADR-0019](ADR-0019.md) | S | Explicit incomplete and abstained terminal states |
| [ADR-0020](ADR-0020.md) | T | Visual editing is deferred, interchange is preserved |
| [ADR-0021](ADR-0021.md) | #49 | Multi-reviewer disagreement defers by default |
| [ADR-0022](ADR-0022.md) | #74 | Typed subworkflow invocation is deferred |
| [ADR-0023](ADR-0023.md) | #170 | Isolate ADK-Rust 2.1 graph ownership at the integration boundary |
| [ADR-0024](ADR-0024.md) | #187 | Do not create a companion recipes repository |
| [ADR-0025](ADR-0025.md) | #223 | Freeze ADK-Rust 2.1.0 as the production pin |

The [architecture boundary](../BOUNDARY.md) makes the ADK/domain separation explicit. ADR-0025 freezes the production pin at `adk-rust =2.1.0`; ADR-0014 still requires exact pins and a committed lockfile.