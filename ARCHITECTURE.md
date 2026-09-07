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
