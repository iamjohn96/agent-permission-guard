# Current State

## Current Milestone

The Archive Adapter Dependency Security Check is accepted. Its library-independent adversarial fixture
foundation is implemented and verified locally: deterministic test-only USTAR/gzip bytes, explicit
expected transcripts, layered format/policy/limit failures, and equal-length cross-pass substitutions.
No archive dependency has been added and no real package archive has been parsed or extracted.

The committed foundation accepts only owning-authority synthetic exact graph profiles, separates plan
and one-time synthetic approval identities, validates injected bytes/archive descriptions and
test-created trees, and exposes no public CLI path. Real registry access, package download, archive
extraction, persistent staging, production profiles, receipt schema 1.2, and package startup remain
separately gated.

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
- First production Exact Filesystem profile real acceptance:
  - fixed `@modelcontextprotocol/server-filesystem@2026.7.10`; never `latest`
  - credential-free private npm HOME/cache/prefix/TMPDIR and empty user/global configs
  - lifecycle scripts disabled and no broader Everything or content-read test execution
  - initial draft 2020-12 fixture mismatch blocked before tool dispatch
  - public pinned-runtime draft-07 schema captured and bound without weakening exactness
  - exactly one `list_allowed_directories` call against a disposable directory
  - complete `adapter_action_exact` portable receipt, valid local audit chain, and no path persistence
  - temporary workspace and npm cache removed after every attempt
- Exact Filesystem acceptance checkpoint committed and pushed at `8502e64`
- Upstream Provenance v0 Architecture Check accepted on 2026-09-07
- Network-free Upstream Launch Integrity Foundation implemented and committed:
  - deterministic shell-free absolute command resolution with empty PATH entries ignored
  - canonical cwd and exact cloned/frozen arguments and allowlisted environment
  - working-directory device/inode/mode binding and immediate replacement detection
  - bounded regular executable identity and SHA-256 snapshot held only in memory
  - immediate pre-spawn revalidation and runtime-authenticated prepared launch
  - STDIO transport accepts the prepared launch as its only dispatch source
  - owning-authority authentication for synthetic launch-profile results
  - sanitized stable failures without raw path, argument, environment, or file-byte disclosure
  - explicit configured-label-only and direct-bypass UX
- Upstream Launch Integrity Foundation checkpoint committed and pushed at `1fee336`
- Verified MCP Package Stage Architecture Check accepted on 2026-09-07
- Network-free Verified MCP Package Stage foundation implemented:
  - immutable canonical graph/profile and stage-plan identities
  - profile/plan/integrity/stage runtime authorities with forgery rejection
  - one-time synthetic approval binding with replay and cross-plan rejection
  - streaming SHA-512 over injected local byte streams with bounded aggregate limits
  - portable synthetic archive entry validation without tar parsing or extraction
  - deterministic no-follow tree manifest, exact package/dependency/lifecycle/entrypoint validation,
    and complete mutation revalidation
  - monotonic failure/invalid states and matching synthetic audit evidence before a test-only seal
  - bounded privacy-safe errors and no production receipt or policy behavior change
- Verified MCP Package Stage foundation checkpoint committed and pushed at `92553b3`
- Archive Adapter Dependency Security Check accepted on 2026-09-07:
  - exact pinned `tar/parse` is the conditional parser-only candidate
  - library extraction, member-selection, and filesystem-writing APIs are prohibited
  - v0 accepts only bounded gzip-wrapped USTAR and rejects PAX/GNU extensions
  - inspection and materialization require matching two-pass authenticated transcript semantics
- Library-independent archive adversarial fixture foundation implemented:
  - deterministic test-only USTAR header/body/padding/end-block builder
  - deterministic test-only single-member gzip writer with stored DEFLATE, CRC-32, and size trailer
  - 52 fixtures across valid controls, gzip/tar corruption and ambiguity, parser-smuggling metadata,
    semantic path/type attacks, and resource ceilings
  - explicit ordered transcript expectations with body SHA-256
  - three equal-length cross-pass header/order/body substitutions
  - no archive candidate import, dependency change, filesystem materialization, or real package bytes

## In Progress

- No production archive adapter, dependency selection, or real archive handling is in progress. The
  local fixture checkpoint is ready for diff review and separate commit/push approval.

## Remaining

- Decide whether to accept the POSIX-only preview or design a Windows runner separately.
- Separately approve archive dependency selection, production graph profile, registry confirmation,
  artifact download/stage creation, receipt 1.2, and package startup.
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
- Archive handling must use the exact reviewed parser-only import, reject extension metadata in v0, and
  match a complete write-free transcript before APG-owned materialization can be sealed.

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
- The common registry contains only the separately reviewed Filesystem zero-parameter production profile.
  Configured server identity remains `configured_label_only`, not executable or publisher provenance.
- Pre-spawn executable revalidation narrows but cannot eliminate the final OS-load race. It does not
  cover interpreter-selected scripts, imported modules, dynamic libraries, child processes, packages,
  publishers, dependency graphs, or runtime attestation.
- Verified MCP package staging is foundation-only. The current synthetic authorities and injected
  adapters are not connected to the CLI, Dashboard, durable audit DB, registry, archive extraction,
  persistence, or launch. No archive library, production graph profile, receipt 1.2 evidence, or staged
  launch exists yet.
- The preferred archive parser remains an unapproved third-party candidate. Its exact registry artifact,
  integrity, APG lock graph, licenses, supported-Node behavior, and candidate-backed fixture results have
  not been verified. Current fixtures validate bytes and synthetic policy only, not a real parser.
- The first profile identifies an exact zero-parameter adapter action, not the directories
  returned by the tool. The result can disclose private absolute paths to the MCP client/model.
- The Filesystem server can replace allowed directories through MCP Roots. A request receipt cannot prove
  a fixed allowed-directory state, and APG does not currently refresh upstream tool schemas dynamically.
- The local SHA-256 event chain can be recomputed by an actor with full database write access; stronger
  issuer and history guarantees require a separately approved signing and anchoring architecture.
- The default parallel full suite can intermittently starve the STDIO/Dashboard integration's fixed
  five-second deadlines on this host. The affected file passes 28/28 in isolation and the complete
  final suite passes with one worker; this checkpoint changes no gateway or dashboard production code.

## Tests

- Current final network-free local suite with one worker: 195 passed, 3 skipped on 2026-09-07.
- Archive adversarial fixture coverage: 7 passed over 52 archive fixtures and 3 cross-pass substitutions,
  including deterministic USTAR/gzip generation, explicit transcript golden values, layered rejection,
  existing portable-policy behavior, gzip multi-member ambiguity, and dependency/import absence.
- STDIO/Dashboard integration focused retry: 28 passed. Default parallel full retries encountered
  pre-existing fixed-deadline timeouts under contention; the same final suite passed with
  `--maxWorkers=1`.
- Verified MCP Package Stage foundation coverage: 12 passed across profile/plan canonical identity,
  authority forgery, metadata expiry, approval replay/substitution, streaming SHA-512 ordering and
  limits, archive traversal/link/special-file/ambiguity rejection, deterministic exact package trees,
  mode/link/layout/byte drift, terminal states, dual synthetic audit evidence, and bounded errors.
- Upstream Launch Integrity focused coverage: 14 passed across deterministic resolution, empty PATH,
  symlinks, immutable configuration, digest binding, executable drift/no-spawn, forged dispatch,
  bounded target checks, private-value-safe failures, and synthetic profile authentication.
- Pinned Filesystem Exact Identity acceptance: 3 passed, including controlled-environment guards, exact
  runtime schema, one target call, complete portable evidence, valid audit chain, path non-retention, and
  temporary cleanup.
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

Perform an Exact Archive Parser Artifact & Lock Graph Review for the preferred `tar/parse` candidate.
This next checkpoint requires separate approval for anonymous public-registry metadata reads and an
isolated credential-free lockfile-only preview. Do not add the dependency to APG, execute parser code,
or parse/extract a real package archive until the exact resulting graph and command receive approval.
