# Current State

## Current Milestone

First production Exact MCP Identity profile: network-free implementation for
`list_allowed_directories` is committed and pushed at `035bef6`.

The first opt-in production profile has explicit CLI selection, startup schema preflight, target-only
exact-required behavior, privacy-safe UX, and network-free coverage. The remaining task in this milestone
is the separately approved pinned-package acceptance. Package execution, registry access, and real
Filesystem MCP acceptance have not occurred.

## Completed

- IG0: strict npm/npx parsing, offline metadata fixtures, deterministic risk and policy evaluation
- IG1: one-time approval, dashboard representation, and tamper-evident audit integration using fake runners
- IG2: anonymous read-only HTTPS npm registry metadata adapter with bounded transport and memory-only cache
- IG2.5: `apg inspect npm|npx <package-spec>` analysis-only CLI
- IG3 foundation:
  - exact resolved package/version execution identity
  - registry tarball URL, SHA-512 integrity, and executable-bin evidence
  - canonical executable, arguments, working directory, timeout, and pre-state plan hash
  - mandatory one-time Ask for every proposed local install execution
  - fake-runner outcomes for timeout, cancellation, verification failure, and audit failure contracts
  - read-only precondition and post-execution verification helpers
  - controlled `shell: false` runner with private npm config/HOME/cache, captured PATH, bounded redacted output, timeout, cancellation, and process-group termination
  - explicit `apg install npm|npx` CLI with local one-time approval dashboard and non-success exit behavior
  - exact version and approved SHA-512 integrity verification from npm lockfiles
  - isolated real npm acceptance for `yaml@2.9.0` with lifecycle scripts disabled, exact-save enabled, verified lockfile integrity, and a valid audit hash chain
- Release R0:
  - local version and lockfile updated to `0.2.0`
  - package dry-run confirmed 56 intended files, including compiled Install Guard CLI and dashboard assets
- macOS M0:
  - additive version-1 `instance_id` in private dashboard state
  - authenticated health response bound to the same dashboard instance
  - strict loopback URL, credential, query, path, port, token, and UUID validation
  - state cleanup identity includes URL, PID, start time, and instance ID
  - native rotation, token lifetime, SQLite, redirect, and fail-closed contracts documented
  - stale-token and same-PID replacement integration coverage
- ER0:
  - product boundary and assurance-level vocabulary
  - separate Authorization and Outcome Receipt semantics
  - exact policy-content digest distinct from policy schema version
  - actor/approver assurance without unsupported human-identity claims
  - privacy-safe redaction-before-digest and direct-bypass disclosure
  - durable pre-dispatch evidence and incomplete post-audit failure semantics
  - deferred signing-provider and external-anchor boundaries
  - risk register, mitigations, release-blocking controls, ER1 scope, and security test strategy
- ER1 portable unsigned evidence, committed and pushed:
  - strict version-1 Authorization and Outcome Receipt schemas
  - exact validated YAML policy digest and centralized Install Guard built-in policy digest
  - durable authorization-before-dispatch and approval state-machine guards
  - exact Install Guard plan identity; explicit structural-only generic MCP identity
  - allowlisted bounded result projection without raw arguments or stdout/stderr
  - deterministic canonical export with golden fixtures and strict resource limits
  - offline digest, action-link, completeness, and local event-proof verification
  - read-only audit database export and exclusive private output-file creation
  - legacy-incomplete and started-without-terminal incomplete projection
  - explicit post-dispatch `audit_failed` incomplete semantics without action retry
  - Dashboard Action ID visibility and receipt usage documentation
- Exact MCP Identity shared foundation, committed and pushed at `f9da468`:
  - cloned and deeply frozen `PreparedToolCall` as the only upstream dispatch payload
  - centralized `McpIdentityAuthority` with runtime-trusted result provenance
  - closed typed safe projection fields and exact/partial/rejected/structural invariants
  - profile manifest and optional observed-schema digests
  - receipt/envelope schema 1.1 evidence with schema 1.0 compatibility
  - approval/Dashboard identity presentation and synthetic network-free coverage

## In Progress

- Pinned `@modelcontextprotocol/server-filesystem@2026.7.10` real acceptance awaiting separate approval.
- Committed `list_allowed_directories` profile behavior:
  - explicit CLI activation; never infer a profile from tool name, schema, annotations, or command text
  - exact zero-parameter request identity with closed arguments and schema-drift detection
  - target-only fail-closed behavior without changing Allow/Ask/Deny or other tools
  - configured-label-only server provenance; no official binary or publisher claim
  - returned directory paths and dynamic MCP Roots state excluded from request identity and receipts
  - MCP text and structured result bodies omitted from audit summaries; only bounded outcome metadata is retained
  - unknown selectors fail before database open or upstream execution
  - 64 KiB observed input-schema bound and sanitized mismatch failures
  - network-free implementation complete; pinned real-package schema capture and read-only call require
    a separate approval within the same milestone

## Remaining

- Decide whether to accept the POSIX-only preview or design a Windows runner separately.
- Separately approve the pinned Filesystem package execution, possible registry/download access, and
  isolated real acceptance before running it.
- Review every later production MCP profile separately before it can emit exact assurance.
- Select signing and trust architecture only after receipt semantics, verifier behavior, and identity
  assurance are accepted.

## Important Architecture

- APG protects only actions explicitly routed through an APG adapter.
- Install Guard is an APG module but its execution path remains separate from the MCP proxy.
- An install approval is one-time and bound to the complete immutable execution-plan hash.
- Direct npm/npx commands remain outside APG coverage.
- ContextGate is outside this repository and roadmap.
- The future macOS app is a client of the local API; the CLI remains the enforcement boundary.
- State `instance_id` and authenticated health matching establish freshness. PID and start time are diagnostic only.
- A receipt must distinguish Authorization evidence from observed Outcome evidence and declare its exact
  assurance level, APG adapter coverage, and unobserved effects.
- The current hash chain is local integrity evidence, not independent cryptographic proof against a
  database owner who can recompute it.

## Important Decisions

- Real local execution always requires Ask, even when package risk evaluation is otherwise Allow.
- Execution requires fresh resolved metadata, an exact version, HTTPS registry/tarball URLs, and SHA-512 integrity evidence.
- npx requires one deterministic executable binary; ambiguous packages fail closed.
- Project `.npmrc` files are rejected by presence only; their contents are not read.
- The current milestone does not claim OS sandboxing, complete child-effect observation, or automatic rollback.
- State version and API version remain 1 because `instance_id` is an additive field; new native clients must require it.
- Reserve `Cryptographic Execution Receipt` for a future signed or anchored assurance level. ER1 should
  use portable unsigned evidence with precise local-verification wording.
- Receipt export opens the audit database read-only, refuses invalid chains and output-file overwrite,
  and performs no network request.
- SQLite can create or retain normal WAL/SHM coordination sidecars for a read-only connection; export
  does not write audit rows, run migrations, or modify the main database bytes.
- Missing terminal evidence remains incomplete. Automatic recovery mutation is deferred until an
  exclusive-writer/session-ownership mechanism exists.

## Known Issues

- Exact identity currently covers the approved top-level package, not the complete transitive dependency graph.
- File verification is limited to package manifests and npm lockfiles.
- The npm runner has one successful isolated real-package acceptance; npx remains validated only with controlled test executables and has not executed downloaded package code.
- Output redaction is bounded and pattern-based, so it cannot guarantee detection of arbitrary unlabeled secrets.
- The controlled runner preview currently rejects Windows.
- npm performs dependency metadata and tarball requests itself after approval; APG does not act as an HTTP proxy for each transitive request.
- npm public version is `0.2.0`, including IG2 and IG3.
- M0 does not provide OS-level process attestation. A malicious process running as the same user may read the private state file and bearer token.
- New ER1 audit records bind the exact validated policy-content digest. Historical records remain
  `legacy_incomplete`; receipts do not authenticate an APG build or verified human identity.
- Generic MCP portable identity is currently `structural_only`; arbitrary parameter values are omitted
  to avoid secret leakage. Install Guard receipts retain exact execution-plan identity.
- MCP policy evaluation and upstream dispatch now share one cloned, deeply frozen prepared snapshot.
- General key-name redaction is not a safe exact-identity projection. Exact assurance requires a trusted
  profile that binds every behavior-determining field and rejects unknown fields.
- The common registry intentionally contains no production MCP profile. Configured server identity is
  `configured_label_only`, not executable or publisher provenance.
- The proposed first profile identifies an exact zero-parameter adapter action, not the directories
  returned by the tool. The result can disclose private absolute paths to the MCP client/model.
- The Filesystem server can replace allowed directories through MCP Roots. A request receipt cannot prove
  a fixed allowed-directory state, and APG does not currently refresh upstream tool schemas dynamically.
- The local SHA-256 event chain can be recomputed by an actor with full database write access; stronger
  issuer and history guarantees require a separately approved signing and anchoring architecture.

## Tests

- Current full local suite: 159 passed, 2 skipped on 2026-09-07.
- Exact MCP Identity focused coverage: 7 synthetic tests covering deterministic typed identity, frozen
  dispatch, field mutation, ordered lists, invalid types, unknown fields, request metadata, schema drift,
  required-exact failure, partial privacy, unsafe profile definitions, assurance spoofing, approval
  projection, receipt schema 1.1, and offline verification.
- ER1 focused suite: 63 passed across receipts, audit state transitions, Install Guard integration,
  policy identity, and Dashboard state.
- IG3 coverage includes execution plan, plan tamper, parser bypass, fake executable process execution, registry adapter, dashboard approval, timeout, cancellation, output redaction, terminal audit failure, and exact integrity verification.
- Manual npm acceptance: `yaml@2.9.0`, `--ignore-scripts --save-exact`, exit code 0, verification `verified`, matching approved SHA-512 integrity, valid nine-event audit hash chain. The same temporary audit database also contains the earlier approval-expired attempt.
- Release package dry-run: `agent-permission-guard@0.2.0`, 56 files, 61,727 bytes compressed, scripts disabled, and no registry access. Public registry verification confirmed version `0.2.0` after publish.
- M0 focused suite: 30 passed across dashboard authorization, private state, and STDIO proxy rotation tests.
- M0 coverage includes instance matching, foreign origin rejection, origin-less native authorization, stale credential rejection, strict state URL validation, and same-URL/same-PID replacement safety.
- Default tests must remain network-free; live registry or installation checks are opt-in and approval-gated.
- First-profile coverage includes explicit selection, zero-field completeness, schema preflight, missing/
  duplicate/drift/oversize failures, private input non-disclosure, unknown-selector pre-launch failure,
  target-only enforcement, upstream no-forward, unchanged Deny behavior, and structured result-body
  non-retention.

## Do Not Change

- Do not merge the Install Guard runner into the MCP proxy path.
- Do not read `.npmrc`, `.env`, tokens, keys, credentials, or signing material.
- Do not add dependencies, run real installs, access a live registry, publish, push, or migrate the database without approval.
- Do not claim protection for direct npm/npx commands.

## Current Risks

- A future lifecycle script or npx executable can perform effects outside the working directory without an OS sandbox.
- Post-execution audit failure cannot undo a completed local side effect.
- Automatic rollback cannot reliably reverse lifecycle scripts, child processes, cache changes, or external requests.
- Native clients must invalidate in-flight work on state rotation; server-side instance matching cannot cancel stale client responses by itself.

## Next Recommended Task

Approve the isolated pinned `@modelcontextprotocol/server-filesystem@2026.7.10` acceptance with package
execution and any required npm registry/download access stated independently. Capture only the public
target tool schema, invoke only `list_allowed_directories` against a disposable directory, verify exact
receipt/audit evidence, and keep every later production profile behind its own Architecture Check.
