# Per-Run Work Directory, Sandbox, and Security Model

## 1. Core decision

Every workflow execution receives a unique work directory and an independently evaluated sandbox plan. The work directory is the reproducibility boundary; the sandbox is the security boundary. They are related but not interchangeable.

```text
Run request
   │
   ▼
Resolve immutable workflow package and lock
   │
   ▼
Allocate unique run root
   │
   ▼
Materialize read-only inputs, Skills, references, and approved tools
   │
   ▼
Compile required sandbox capabilities
   │
   ▼
Select backend and verify conformance
   │
   ▼
Execute every child process inside the boundary
   │
   ▼
Publish approved artifacts, then retain or clean the run root
```

## 2. Proposed directory layout

```text
$RUN_ROOT/
├── manifest.json             # immutable run identity and lock references
├── input/                    # immutable input snapshot, read-only in sandbox
├── package/                  # workflow package, prompts, schemas, read-only
├── skills/                   # active Skill packages, read-only
├── refs/                     # resolved external references, read-only
├── work/                     # mutable scratch space
├── out/                      # candidate final outputs
├── artifacts/                # content-addressed stage artifacts
├── logs/                     # redacted structured events
├── tmp/                      # bounded temporary files
└── checkpoints/              # optional durable workflow checkpoints
```

The runtime should expose logical paths such as `$RUN_INPUT`, `$RUN_WORK`, and `$RUN_OUT`. Workflow definitions must not depend on host absolute paths.

## 3. Workdir lifecycle

### Allocation

- Generate a cryptographically strong run ID.
- Create the root with restrictive permissions.
- Refuse symlinked or pre-existing roots unless resuming an authenticated run.
- Record owner, tenant, workflow package hash, and creation time.

### Materialization

- Prefer immutable snapshots or read-only bind mounts.
- Record source hashes and freshness metadata.
- Copy only when a mount would expose too much parent structure.
- Never copy broad credential directories into the run root.

### Execution

- All node and script processes use the run root as their only writable filesystem namespace.
- No node may switch to an arbitrary host working directory.
- Process trees inherit sandbox, resource, and environment policy.

### Publication

- Only explicitly selected outputs become published artifacts.
- Validate file type, size, schema, ownership, and path before publication.
- Side effects outside the run root go through registered tools, not direct filesystem access.

### Retention and cleanup

- Completed low-risk runs may retain only manifests, traces, and published artifacts.
- Failed runs may retain diagnostic material under a stricter access policy.
- Customer policy controls retention duration.
- Cleanup is idempotent and recorded.
- Pinned artifacts outlive the run only through an ArtifactStore reference.

## 4. Sandbox capability model

Define requested capabilities independently from backend names:

```text
filesystem.read paths/globs
filesystem.write paths/globs
network mode and destinations
process spawning
maximum PIDs
CPU time
wall time
idle time
memory
output bytes
open files
environment variables
syscall profile
user/group identity
device access
```

Each backend publishes what it can enforce. Preflight computes:

```text
requested capabilities ⊆ enforceable backend capabilities
```

If false, execution is rejected. Logging a warning and running less isolated is not acceptable for a required control.

## 5. Recommended backend tiers

### Tier A: pure in-process transform

Use embedded JavaScript or a similarly constrained engine when a task only transforms JSON-like data and requires no filesystem or network. This has low startup overhead and a small capability surface.

### Tier B: WASM

Use a WASM backend for portable deterministic modules when the required libraries fit the guest environment. No host filesystem or network should be exposed unless an explicit capability interface is added.

### Tier C: Linux bubblewrap

Use bubblewrap for fast local/Linux execution after implementing and testing a complete policy. Bubblewrap provides primitives, not a ready-made policy. The framework must construct a new mount namespace, expose only selected paths, use read-only mounts where appropriate, unshare network by default, create a new session, and apply seccomp/resource controls where supported.

### Tier D: rootless OCI/Podman

Use rootless containers when customer operations, dependencies, or stronger image-level reproducibility warrant the overhead. Pin images by digest, use a read-only root filesystem, mount only the run directories, drop capabilities, deny network by default, and avoid the Docker/Podman control socket.

### Tier E: remote isolated worker

A later deployment may execute on a dedicated worker or managed sandbox. It must still satisfy the same capability contract and return signed/verified run artifacts.

## 6. Default security policy

- network: none;
- writable paths: `work/`, `out/`, `tmp/`, and node-specific artifact paths;
- read-only paths: workflow package, Skills, references, immutable inputs;
- environment: empty except explicitly injected non-secret metadata;
- secrets: requested through a brokered tool or short-lived file descriptor/token;
- devices: none beyond minimal pseudo-devices;
- host IPC: none;
- host PID namespace: hidden;
- host home: not mounted;
- SSH agent, Docker socket, cloud metadata, D-Bus, and browser profiles: absent;
- process count, memory, disk, file count, and output: bounded;
- child process spawning: denied unless a declared script runtime requires it.

## 7. Network policy

The policy should support:

```text
none
loopback-only
service-alias allowlist
hostname/IP/port allowlist through a broker
full network only by explicit high-risk policy
```

Direct DNS and arbitrary egress make allowlists fragile. Prefer a network broker/proxy that authenticates destination profiles and records requests. Credentials should be audience-bound and short lived.

A model or Skill cannot expand the allowlist at runtime.

## 8. Secret handling

Never serialize secrets into:

- workflow state;
- prompts;
- Skill files;
- lockfiles;
- ordinary traces;
- workdir manifests;
- model-visible environment dumps.

Preferred patterns:

- registered connector holds credentials outside the sandbox;
- node calls a narrow broker tool;
- short-lived token injected only for the exact node;
- Unix socket or file descriptor with capability-limited protocol;
- secret reference in config resolved by policy at runtime.

Redaction must occur before telemetry export, not after storage.

## 9. Filesystem attacks to test

- `../` traversal;
- absolute paths;
- symlink escape created before and during execution;
- hard-link surprises where permitted;
- bind-mount parent exposure;
- special files and device nodes;
- Unicode/confusable path names;
- time-of-check/time-of-use replacement;
- archive extraction traversal;
- excessive file count and sparse files;
- world-readable output permissions;
- cross-run artifact ID collision.

Use descriptor-relative operations and `openat2`-style restrictions where practical on Linux. Recheck the resolved target at the operation boundary.

## 10. Process and resource attacks to test

- fork bombs;
- child process escape from limits;
- background process surviving node completion;
- output floods;
- CPU spin without output;
- memory ballooning;
- disk exhaustion;
- file descriptor exhaustion;
- nested container invocation;
- invoking setuid binaries;
- terminal injection;
- signal handling and cancellation races.

The sandbox supervisor owns and reaps the full process tree. Node completion requires child cleanup.

## 11. Tool and script distinction

A registered tool is a host capability implemented and reviewed by the platform or application. A Skill script is untrusted or less-trusted code packaged with a Skill. They should not share the same default authority.

```text
Registered Tool: narrow host operation, explicit schema, brokered credentials
Skill Script: sandboxed computation over mounted inputs, no implicit host access
```

Stable, frequently used Skill scripts should graduate to registered Rust nodes or tools.

## 12. Data classification

Every run carries a classification such as:

```text
public
internal
confidential
restricted
```

The classification constrains:

- permitted model endpoints;
- telemetry destination;
- artifact retention;
- network profiles;
- Skill/catalog source;
- eligible sandbox workers;
- human reviewer access;
- cache sharing.

The most restrictive input classification becomes the default run classification unless an approved declassification validator exists.

## 13. Audit events

Record, without chain-of-thought:

- workdir allocation and cleanup;
- package and lock identity;
- sandbox backend/capabilities;
- mounts and network profiles by stable identifier;
- node start/finish/status;
- model/tool/script call metadata and digests;
- files published or rejected;
- policy and approval decisions;
- resource-limit events;
- cancellation and cleanup results.

Raw sensitive payload logging is opt-in and separately protected.

## 14. Sandbox conformance test suite

Every backend must pass the same fixture suite:

1. cannot read undeclared host file;
2. cannot write read-only input/Skill/reference;
3. can write only declared work/output paths;
4. cannot use network when denied;
5. can reach only approved destination when allowlisted;
6. cannot see host processes;
7. cannot access injected secrets outside the declared node;
8. time and output limits terminate the full process tree;
9. memory/PID limits are either enforced or backend selection fails;
10. cancellation leaves no surviving process;
11. symlink escape is blocked;
12. artifacts retain correct ownership and hashes.

Do not label a backend production-ready until these tests run in CI on the target platform.

## 15. Initial implementation recommendation

Implement the abstract capability contract and local workdir manager first. Then add:

1. a test-only fake backend;
2. Linux bubblewrap backend with conformance tests;
3. WASM or embedded-JS pure transform path;
4. rootless OCI backend;
5. remote workers only after real customer demand.

This order gives fast local iteration without pretending that a process wrapper is a complete sandbox.
