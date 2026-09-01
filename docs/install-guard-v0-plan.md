# Install Guard v0 Implementation Plan

Status: IG0–IG3 implemented and published in `0.2.0`
Product boundary: an APG module with a separate npm/npx execution adapter

## Goal

Prove that APG can help an individual developer understand and authorize risky JavaScript package execution without weakening or complicating the existing MCP firewall.

Install Guard v0 is deliberately invoked. It does not replace the global `npm` or `npx` command and does not claim to intercept commands that bypass APG.

## User experience

The first supported flows are:

```text
apg install npm <package-spec> [supported options]
apg install npx <package-spec> [supported options]
```

The runner:

1. parses the requested command without executing it
2. resolves an exact package name and version
3. gathers trusted registry metadata
4. calculates install-specific risk with visible reasons and uncertainty
5. applies Allow / Ask / Deny
6. shows the exact command and target before approval
7. executes only the approved immutable command
8. records the decision and result in the local audit log

The exact command syntax may be adjusted during implementation if it conflicts with npm semantics, but v0 must remain explicit and bypass-transparent.

## Reuse from APG

Reuse where the current abstraction already fits:

- decision types: Allow, Ask, Deny
- common risk score, band, and reason-code shape
- local approval coordinator and one-time approval behavior
- SQLite audit chain and redaction utilities
- CLI error conventions and fail-closed startup behavior

Do not directly reuse MCP-specific request or response types. Install requests need their own domain model and adapter.

## New modules

Suggested source boundaries:

```text
src/install/
  types.ts             normalized install request and analysis result
  parser.ts            safe npm/npx argument parsing
  resolver.ts          exact package/version resolution
  metadata.ts          registry metadata provider interface
  risk.ts              install-specific signals and reason codes
  policy.ts            Core Policy + Install Override evaluation
  runner.ts            approved command execution
  verifier.ts          post-execution evidence
  service.ts           orchestration
```

Existing approval and audit modules should be adapted through small shared interfaces. Avoid a broad refactor of the stable MCP gateway.

## Risk Scoring v0

The score is an explanation aid, not the final authority. Hard policy rules can always raise the result to Ask or Deny.

Initial signals:

| Signal | Suggested points | Default consequence |
| --- | ---: | --- |
| Package version cannot be resolved exactly | 100 | Deny |
| Registry metadata unavailable or contradictory | 50 | Ask |
| Lifecycle install script present | 35 | Ask |
| Known high/critical advisory | 60 | Ask or Deny by policy |
| Possible typosquat | 50 | Ask |
| Very new package or publisher | 25 | Explain; combine with other signals |
| Repository missing or provenance inconsistent | 20 | Explain; combine with other signals |
| Requested package uses a mutable/non-registry source | 45 | Ask |
| No material signal from trusted evidence | 0 | Eligible for Allow |

Suggested bands:

- 0–24: low
- 25–49: medium
- 50–74: high
- 75–100: critical

Risk points must not silently auto-Allow an action. The effective result is the strictest of Core Policy, Install Override, and risk escalation.

## Policy v0

Start with conservative built-in behavior rather than expanding the existing YAML schema immediately:

- Deny unresolved or malformed package targets.
- Ask when lifecycle scripts, unavailable metadata, mutable sources, possible typosquatting, or material advisories are present.
- Allow only exactly resolved registry packages with no material risk signal.
- Approval is valid once for the exact package, version, runner, options, working directory, and analyzed metadata revision/time window.
- Any change after approval requires re-analysis and a new decision.

Custom Install Guard YAML rules and permanent allowances are deferred until the built-in model has real usage evidence.

## Metadata and privacy

Package analysis normally requires read-only npm registry access. This is an external read and may reveal the requested package name to the configured registry.

Requirements:

- use the user's configured npm registry only after clearly documenting the data flow
- send no telemetry to APG-operated services
- cache only non-sensitive metadata locally with bounded retention
- record source and retrieval time without storing credentials or request headers
- never read npm credentials directly in v0; use the npm process/configured client boundary if authenticated registry support is added later

Because adding registry integration and any new dependency affects security and architecture, implementation must stop for approval before those changes are executed.

## Execution safety

- Never execute during analysis or dry-run.
- Never build a shell command string; spawn an explicit executable with a validated argument array.
- Pin the approved package identity and version in the executed arguments.
- Reject unsupported flags instead of forwarding them blindly.
- Preserve the working directory as part of the approval identity.
- Capture bounded stdout/stderr metadata, exit status, duration, and cancellation state without storing secrets.
- v0 does not promise complete containment of package lifecycle scripts; the approval UI must state this clearly.

## Tests

Minimum automated coverage:

- parser rejects shell operators, ambiguous targets, unsupported flags, and malformed specs
- resolver locks mutable input to an exact version
- metadata failure cannot produce silent Allow
- each risk signal produces stable reason codes
- strictest policy result wins
- approval cannot be replayed or used for a modified request
- Deny and expired approval never invoke the runner
- runner uses an executable plus argument array, not a shell
- audit contains analysis, decision, execution result, and redaction evidence
- existing MCP tests remain unchanged and pass

Tests should use a fake metadata provider and fake runner first. A live registry integration test should be optional and must not run during the default suite.

## Milestones

### IG0 — Domain model and offline analysis

- install request types and parser
- fake metadata provider
- deterministic risk signals
- built-in policy evaluator
- unit tests only; no process execution and no network

### IG1 — Approval and audit integration

- adapt shared approval interfaces
- add install audit event types without breaking existing records
- fake runner end-to-end tests
- dashboard representation for an install approval

Implemented locally without a database migration. Install requests use the existing one-time approval API with an additive `kind: install` field and are recorded in the existing tamper-evident audit chain under the `install-guard` source. The runner remains an interface backed only by test fakes.

### IG2 — Read-only registry adapter

- exact npm package/version resolution
- metadata source and freshness handling
- optional live integration tests
- privacy/data-flow documentation

This milestone requires approval before external registry access or dependency changes.

Implemented locally behind an injectable transport using Node's built-in fetch implementation. Automated tests use fake registry responses only. The adapter has not made a live registry request. Its privacy and credential boundary is documented in `docs/npm-registry-data-flow.md`.

### IG3 — Controlled local execution preview

- explicit npm/npx runner
- exact approved arguments
- cancellation, timeout, result capture, and verification
- manual local acceptance scenario

Actual install execution changes the local project and dependency state. It requires explicit approval during development acceptance testing.

IG3 now includes an immutable execution plan, exact resolved approval identity, mandatory Ask for local execution, registry integrity/bin evidence, a controlled POSIX process runner, `apg install`, bounded redacted output, timeout/cancellation, and pre/post verification. Automated tests use fake registry responses, fake runners, and locally generated known executables. A separately approved manual acceptance installed `yaml@2.9.0` once in an isolated temporary project with `--ignore-scripts --save-exact`; the command completed, the approved SHA-512 integrity was observed in the lockfile, and the audit hash chain remained valid.

## Definition of done for v0

- Existing MCP Firewall behavior and test suite remain stable.
- A user can explicitly analyze an npm/npx package request.
- APG explains the important install risks and evidence.
- Ask decisions can be approved or denied once through the existing local approval path.
- Only an unchanged approved request can execute.
- The local audit log shows what was analyzed, decided, executed, and observed.
- Direct npm/npx commands are clearly labeled as outside APG coverage.
- No account, hosted service, telemetry, ContextGate, Team feature, or payment is introduced.

## Implemented first task

IG0 now includes offline domain types, a strict parser, an in-memory metadata provider, a deterministic install risk evaluator, a built-in policy evaluator, and unit tests. It does not add dependencies, access a registry, run npm/npx, or change the existing runtime policy schema.
