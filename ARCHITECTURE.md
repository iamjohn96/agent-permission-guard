# Agent Permission Guard Architecture

## Product Boundary

Agent Permission Guard enforces only execution paths deliberately routed through it.

```text
MCP client -> APG MCP gateway -> MCP server

Developer/agent -> APG Install Guard adapter -> controlled npm/npx runner

Direct shell/npm/npx/browser/API -> outside APG coverage
```

Install Guard is an APG module, not a separate product or repository. It shares decision vocabulary, risk conventions, one-time approval, redaction, and tamper-evident audit concepts with the MCP firewall. It does not reuse MCP-specific request types or execution forwarding.

## Major Components

### MCP Firewall

- STDIO downstream and upstream transports
- versioned YAML policy and deterministic evaluator
- risk escalation and one-time approval
- local dashboard
- SQLite audit recorder and hash chain

### Exact MCP Identity Foundation

The MCP gateway prepares one cloned, deeply frozen request snapshot before policy evaluation. That same
snapshot is the only payload forwarded upstream, preventing the evaluated parameters and dispatched
parameters from diverging.

An `IdentityAuthority` may apply an explicitly registered, APG-built profile to the configured server ID
and tool name. Profiles use closed typed field definitions and return only bounded safe claims. They do
not hash arbitrary arguments or trust upstream descriptions and JSON Schema to classify secrets.

Identity assurance is explicit:

- `structural_only`: configured server ID and operation only
- `adapter_scoped`: a reviewed safe subset, with unbound behavior declared
- `adapter_action_exact`: all behavior-determining parameters accepted by a reviewed profile
- `execution_plan_exact`: a separate immutable execution plan, currently used by Install Guard

Unknown fields, invalid types, schema drift, unsupported request metadata, and profile failures cannot
produce exact assurance. Normal MCP calls remain `structural_only` unless a reviewed built-in profile is
selected explicitly. Each later production profile remains a separate approval boundary.

The first opt-in production profile is `filesystem.list-allowed-directories.v1`. It covers only the
zero-parameter `list_allowed_directories` operation on the configured `local-upstream` boundary. The CLI
validates the selector before opening the database or starting upstream, then verifies the tool and its
bounded input-schema digest during startup. Once selected, exact identity is required for that operation;
profile mismatch blocks before policy evaluation and upstream dispatch instead of silently downgrading.
Other operations retain structural identity and existing policy behavior.

This profile does not authenticate the launched command, package, publisher, or binary. Its server
provenance remains `configured_label_only`. Returned directory paths and dynamic MCP Roots state are not
part of request identity and are not retained in portable receipt result evidence. The separately
approved real acceptance against `@modelcontextprotocol/server-filesystem@2026.7.10` validated the
captured draft-07 wire schema, one target-only call, exact receipt evidence, and the audit chain in an
isolated credential-free npm environment.

The audit recorder, rather than a generic interceptor, decides whether a runtime identity result came
from the trusted authority. Portable receipt schema 1.1 carries profile evidence; existing schema 1.0
receipts continue to verify and are never upgraded retroactively. No database migration is required.

### Upstream Launch Integrity Foundation

Before the MCP gateway opens its audit database or starts an upstream process, it prepares one
runtime-authenticated, deeply frozen launch snapshot. APG resolves the command once without a shell,
binds the exact arguments, canonical working-directory identity, and allowlisted environment, and takes
a bounded SHA-256 snapshot of the local executable. The STDIO transport accepts only that prepared
object and revalidates the working directory, executable identity, bytes, and complete launch digest
immediately before connection.

This is local pre-spawn integrity, not package provenance. Hashing Node, npm, npx, an interpreter, or a
launcher does not identify scripts, packages, dependency graphs, dynamic libraries, publishers, or
runtime behavior. Production receipts therefore remain `configured_label_only`. The foundation and its
network-free tests are committed at `1fee336`.

### Verified MCP Package Stage Foundation

The accepted staging design admits only an APG-owned exact graph profile. A stage plan binds the full
reviewed graph, exact registry artifacts and SHA-512 values, metadata expiry, resource limits,
scripts-disabled behavior, and one private stage-root identity before a future download approval.
Registry metadata, artifact download/private staging, project installation, staged-package startup, and
MCP tool actions are separate authority boundaries; none authorizes another.

The first implementation checkpoint is intentionally network-free and not connected to the CLI. It
provides runtime-authenticated synthetic profiles, plans, integrity results, one-time test approvals,
monotonic state transitions, archive-entry policy validation, and deterministic materialized-tree
revalidation. It includes no production package profile, registry request, downloader, tar extraction,
persistent stage, package launch, dependency, receipt change, or stronger production provenance claim.
See `docs/verified-mcp-package-stage-architecture-check.md`.

The accepted archive-adapter security boundary prefers an exact pinned `tar/parse` candidate but keeps
all library filesystem APIs outside APG's design. The first archive grammar is gzip-wrapped USTAR only;
PAX, GNU extensions, links, special files, warnings, recovery, and ambiguous end states fail closed.
Inspection and materialization are separate passes over a revalidated artifact and must match one
authenticated ordered transcript including body hashes. APG alone will own future exclusive no-follow
filesystem writes, and no scratch output becomes runnable before complete validation and sealing.

The archive fixture builder remains parser-free. It produces deterministic USTAR/gzip bytes for valid
controls, gzip/tar ambiguity and corruption, PAX/GNU parser-smuggling cases, semantic path/type/resource
attacks, and equal-length cross-pass substitutions. A separate production module imports only
`tar/parse`: APG validates a strict single-member gzip and USTAR envelope first, then requires the
candidate's ordered header/body interpretation to match before portable policy validation can issue an
authenticated frozen transcript. Neither module performs extraction or filesystem writes. See
`docs/archive-adapter-dependency-security-check.md`.

The exact artifact/lock review accepts only `tar@7.5.22` and its reviewed six-node public production
graph for the implemented network-free synthetic checkpoint. APG declares the direct version exactly,
preserves every reviewed resolved URL and SHA-512, disables scripts, imports only `tar/parse`, and tests
the lock contract. Registry integrity is artifact-selection evidence, not publisher provenance or a
safety claim. See
`docs/exact-archive-parser-artifact-lock-review.md`.

The candidate adapter currently accepts in-memory bytes and uses synchronous bounded decompression and
parsing. It checks cancellation only around those phases, so it cannot yet guarantee prompt interruption
of hostile CPU work. Real artifact use remains blocked on a separately accepted worker/streaming limit,
two-pass descriptor revalidation, APG-owned materialization, and Node 24-26 compatibility architecture.

The accepted bounded-worker foundation runs each archive pass in a fresh shell-free child process and
keeps all filesystem writes in the APG parent. Pass A emits a complete write-free authenticated
transcript; pass B streams bounded body chunks whose order, metadata, length, and hashes must match that
transcript before and during exclusive no-follow writes beneath a private random pending root. Complete
tree revalidation, durable audit ordering, and an exclusive authenticated seal are all required before
a stage can become launchable.

The child-process boundary limits failure propagation but is not a sandbox. Node's Permission Model is
not a malicious-code security boundary, and Node 24 cannot restrict network access through that model.
Accordingly, a real archive worker must capability-gate no-network assurance: Node 25/26 can run with no
network grant, while Node 24 requires a separately reviewed OS containment provider or fails closed for
real artifacts. Standard Node filesystem APIs also cannot eliminate same-user intermediate-path races;
the POSIX-only v0 writer mitigates them with private ownership, random roots, no-follow exclusive leaf
opens, continuous identity checks, and never publishing unsealed paths. See
`docs/bounded-archive-worker-two-pass-materialization-architecture-check.md`.

The network-free implementation binds a hashed allowlist of runtime files, starts Node with an empty
environment and no shell, uses stdin for the bounded request/artifact/acknowledgement stream, and accepts
only length-prefixed closed-schema stdout frames. The parent reconstructs and authenticates pass-A
evidence, compares every pass-B body chunk, owns all POSIX file handles, revalidates the complete tree,
and publishes a read-only seal before the final synthetic audit transition. The local fixture matrix is
validated on Node 26; Node 24/25 runtime behavior remains a release gate and no real artifact path is
connected.

### Install Guard

- strict npm/npx parser
- offline and guarded registry metadata providers
- install-specific risk and built-in policy
- immutable execution-plan builder
- one-time approval and install audit adapter
- read-only precondition and result verifier
- controlled POSIX runner plus injectable test-runner interface
- explicit install CLI with a temporary localhost approval dashboard

## IG3 Data Flow

```text
InstallRequest
  -> resolve exact metadata
  -> evaluate package risk
  -> build immutable InstallExecutionPlan
  -> record planHash and Ask decision
  -> one-time human approval
  -> controlled runner using executable + argument array, never a shell command string
  -> verification result
  -> terminal audit result
```

The execution plan binds:

- resolved top-level package and exact version
- original mutable specifier for explanation
- HTTPS registry and tarball URLs
- SHA-512 integrity evidence
- deterministic npx binary when applicable
- executable realpath and SHA-256 hash
- Node runtime realpath/hash and the captured PATH used by the approved process
- canonical argument array and supported options
- canonical working-directory identity
- metadata observation time and timeout
- lifecycle-script evidence
- pre-execution package manifest and lockfile hashes

The canonical plan is hashed. Approval is scoped to that hash and consumed once. Changed metadata, executable, arguments, working directory, manifest, or lockfile requires a new plan and approval.

## Permission Boundary

- Registry metadata read: explicit inspection/install analysis invocation; anonymous HTTPS only
- Package download: available only inside an approved controlled runner call
- Local installation: always Ask in the controlled preview
- npx package code: always Ask and requires one deterministic binary
- Direct npm/npx: not intercepted and not audited by APG

## Credential Boundary

IG2 and the IG3 planner do not read `.npmrc`, environment tokens, certificate keys, or login state. A project `.npmrc` causes the execution planner to fail based only on file presence. The runner uses private temporary user/global npm configuration, HOME, TMP, and cache paths plus an allowlisted environment. Parent token, credential, proxy, certificate, and `NODE_OPTIONS` variables are not forwarded.

Authenticated registries are out of scope until a separate credential architecture is accepted.

## State and Persistence

- Registry cache: bounded memory only
- Approvals: process-local and one-time
- Audit: local SQLite database with append-only hash-chained events
- Execution plan: immutable in memory and represented by a SHA-256 plan hash in approval/audit data
- Raw stdout/stderr and previews: not persisted; audit stores only byte counts and truncation status. Bounded pattern-redacted previews exist only in the in-memory execution result.
- MCP prepared request and identity result: immutable memory for one call; only profile-approved safe
  claims enter receipt evidence

## Failure Handling

- Missing or contradictory mutable resolution: Deny
- Missing fresh execution evidence: Deny for execution
- Plan construction or precondition failure: no runner call
- Denied, expired, or cancelled approval: no runner call
- Pre-execution audit failure: fail closed
- Timeout, cancellation, non-zero exit, or verification failure: non-success terminal result
- Post-execution audit failure: return `audit_failed`; do not retry execution or claim rollback

## Verification and Rollback Limits

The verifier checks working-directory, npm/npx executable, Node runtime, PATH-bound plan identity, and known package manifest/lockfile hashes. A successful npm result requires both the exact top-level version and the approved SHA-512 integrity in the resulting lockfile. It does not observe every filesystem effect, ignored file, child process, network request, or transitive dependency decision.

The anonymous APG metadata adapter rejects redirects. After approval, npm itself performs dependency and tarball requests; APG fixes the public registry argument and credential-free environment but does not proxy or independently observe every HTTP redirect or transitive endpoint.

APG v0 does not promise automatic rollback or OS-level containment. Lifecycle scripts and npx executables may escape the project boundary unless a future sandbox architecture is accepted.

## macOS Companion Boundary

The future macOS app is a client of the local APG gateway, not a second enforcement engine. The CLI remains authoritative when the app is closed, disconnected, or holding stale state.

```text
private dashboard.json
  -> strict native validation
  -> exact 127.0.0.1 origin + memory-only bearer token
  -> authenticated /api/health
  -> state instance_id == health instance_id
  -> pending approvals and one-time decisions
```

The state document uses additive version-1 fields. `instance_id` is a random non-secret identity for one dashboard lifetime and is returned by authenticated health. PID and start time are diagnostic only. State replacement invalidates the complete prior connection generation, including in-flight responses and the old token.

Native clients must not read SQLite directly, persist the bearer token, follow redirects, weaken Ask behavior while offline, or treat a custom HTTP header as process identity. A same-user malicious process remains outside the protection offered by private file permissions; stronger OS process identity is deferred to packaged-product hardening.

## Exact Production Graph Read-only Acceptance Foundation

Production graph identity is an evidence-promotion path, not a self-asserted manifest. An
`ExactGraphCandidateV1` is compiled from a closed npm lockfile-v3 shape and binds exact install layout,
Node ancestor-resolution edges, public registry tarball URLs, SHA-512 values, runtime/compiler identity,
worker protocol, and resource ceilings. Candidate ownership is separate from accepted-profile ownership;
a correct candidate digest alone cannot create production authority.

The accepted network-free foundation adds separate metadata, plan, artifact-file, acceptance, and review
authorities. Fake transports confirm a complete exact metadata set under byte, deadline, redirect, origin,
URL, and freshness limits. A one-time plan binds the complete ordered artifact set, runtime, worker
protocol, resource limits, private root, and explicit read-only-inspection consequence. Fixture bytes are
streamed into exclusive owner-only files and SHA-512 verified before descriptor-backed parser access.

Archive worker protocol version 2 adds `pass_a_manifest`, which streams only the exact bounded
`package.json` body after the complete authenticated transcript. The acceptance authority requires two
fresh independently reopened Pass-A workers, transcript equality, a bounded duplicate-key-rejecting
manifest projection, exact cleanup, and complete synthetic evidence before a test-only human-review
stand-in can authenticate a profile. This workflow never grants Pass B.

No production HTTPS adapter, built-in Filesystem graph, CLI, durable audit schema, materialized tree,
stage, or package process is connected. Real graph genesis, metadata confirmation, artifact download,
production registration, materialization, startup, and MCP actions remain independent approval boundaries.
See `docs/exact-production-graph-profile-read-only-artifact-acceptance-architecture-check.md`.

## Bounded Metadata-only Graph Genesis Foundation

The first exact production-graph candidate may be generated only for
`@modelcontextprotocol/server-filesystem@2026.7.10` by exact npm `11.16.0` inside a disposable private
workspace. A complete plan binds the Node/npm runtime trees, exact executables, OS/provider/profile,
workspace identities, one loopback broker port and route digest, immutable launch vector, empty-built
environment, target, and resource ceilings. Approval is one-time and cannot be reused to re-arm a broker.

Node's Boolean `--allow-net` permission is insufficient to scope a destination. The development-only macOS
provider layers a generated Seatbelt profile that permits one exact IPv4 loopback port with Node filesystem
and process permissions. A fresh same-plan positive/negative local-only probe is mandatory; absence or drift
blocks with no unsandboxed fallback. This is not a production sandbox claim.

The metadata broker begins disarmed and owns URL construction. It accepts only one canonical anonymous
packument GET grammar, never a tarball endpoint, forwards no inbound credentials or general headers, rejects
redirect/status/type/UTF-8/JSON/name/size/deadline failures, and retains only a bounded safe digest ledger.
The current implementation has only an injected fake transport and no production HTTP/HTTPS adapter.

After a synthetic run, exact workspace validation, the existing closed lock compiler, verified cleanup, and
ordered terminal audit are all required before controlled-genesis evidence is authenticated. A compiler-owned
candidate alone has no production authority. Real npm, public metadata egress, exact metadata confirmation,
artifact download, registration, materialization, startup, and MCP action remain separate approvals. See
`docs/bounded-metadata-only-graph-genesis-architecture-check.md`.

## Metadata-only Graph Genesis Production-adapter Hardening

The real-run boundary uses a safe immutable plan plus a separate memory-only execution capsule. Runtime file
and tree snapshots, Node/npm versions, finalized workspace contents, containment observations, broker
reservations, process terminal state, strict post-state, cleanup, and terminal audit are owned by separate
authorities. The final completion authority authenticates only when every branded result agrees on the same
plan and the candidate was compiled from the exact privately inspected lock document.

The production-shaped transport resolves only `registry.npmjs.org`, rejects any mixed or non-public address
set, pins one accepted socket address while preserving npm hostname TLS verification, sends only fixed
anonymous headers, refuses redirects/decompression, and applies one absolute DNS-plus-response deadline and
streaming byte ceiling. The local listener binds exact `127.0.0.1`, starts disarmed, accepts one canonical GET
grammar, and disarms the session on malformed or failed authorized traffic.

The process supervisor has no general command API. It revalidates the complete authority-owned runtime and
initial workspace before durable spawn intent, launches only the matching private capsule with no shell or
inherited environment, bounds output and time, and requires child close after TERM/KILL. Post-state rejects
unknown roots, links, hardlinks, executables, archive residue, manifest substitution, and budget excess.
Cleanup inventories and removes only the exact private tree and quarantines ambiguity.

This remains a development-host foundation. It has not run real npm or public DNS/registry traffic, and the
local Seatbelt provider is not a supported production sandbox. See
`docs/exact-real-metadata-only-graph-genesis-plan-architecture-check.md`.
