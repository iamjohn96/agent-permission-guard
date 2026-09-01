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
