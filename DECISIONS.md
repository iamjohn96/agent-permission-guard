# Architecture Decisions

## IG3 uses an immutable execution-plan identity

Date: 2026-09-01

Context: A request such as `yaml@latest` cannot safely authorize a later mutable execution.

Decision: Resolve the top-level package to an exact version and bind package integrity, runner executable, argument array, options, working directory, metadata time, and pre-state hashes into one canonical `InstallExecutionPlan` SHA-256 hash.

Alternatives: Approve the original request string; compare only package/version immediately before execution.

Reason: The plan hash makes approval scope explicit and detects changes between analysis, approval, and future execution.

Trade-offs: This does not pin the full transitive dependency graph and adds precondition checks.

Revisit If: A lockfile preview can reliably bind the complete dependency graph before approval.

## Every real local install execution requires Ask

Date: 2026-09-01

Context: Package risk may be low while installation still changes project state or executes code.

Decision: Install Guard execution upgrades Allow to one-time Ask with `local_install_execution`. Deny remains Deny. Unresolved execution evidence also becomes Deny.

Alternatives: Treat explicit CLI invocation as sufficient authority; auto-run low-risk packages.

Reason: Local dependency and file changes are a consequence boundary distinct from package reputation.

Trade-offs: Adds one approval interaction for every controlled execution preview.

Revisit If: The product later adds a separately accepted, tightly scoped persistent allowance model.

## Real process execution was separately approval-gated

Date: 2026-09-01

Context: IG3 foundation can be tested without installing or executing third-party packages.

Decision: Planning, approval, audit, result, and verification contracts were implemented with fake runners first. After explicit approval on 2026-09-01, connect a controlled POSIX runner and `apg install` CLI. Do not perform a real package installation acceptance test without another explicit approval.

Alternatives: Add and manually exercise the runner in the same change.

Reason: Process execution introduces credential, filesystem, lifecycle-script, cancellation, output, and rollback risks that deserve an isolated review.

Trade-offs: Automated validation continues to use only fake executables. A separately approved isolated `yaml@2.9.0` npm acceptance subsequently completed with lifecycle scripts disabled, exact lockfile integrity verified, and the audit hash chain valid; this does not authorize or validate real npx execution.

Revisit If: Isolated real npm acceptance exposes incompatibilities or a Windows runner is required.

## Approved artifact integrity is verified after npm installation

Date: 2026-09-01

Context: An exact version alone does not prove that the artifact observed after installation matches the artifact approved from registry metadata.

Decision: Bind the registry SHA-512 integrity into the execution-plan hash and require the resulting npm lockfile entry to contain both the exact version and approved integrity. A mismatch is `verification_failed` even when npm exits zero.

Alternatives: Verify only version; trust npm exit status; pre-download and independently install a local tarball.

Reason: This detects version-preserving artifact substitution without changing manifest semantics to a local tarball dependency.

Trade-offs: Verification is post-execution and therefore cannot prevent lifecycle code from running before a mismatch is detected.

Revisit If: A pre-execution, independently verified artifact staging design can preserve normal npm lockfile and manifest behavior.

## Credential-free public registry execution preview

Date: 2026-09-01

Context: npm configuration may contain registry tokens, certificates, proxy settings, or script-shell changes.

Decision: Authenticated registries are out of scope. Reject a project `.npmrc` by presence without reading it. A future runner must use controlled empty npm configuration, private HOME/cache paths, and an allowlisted environment.

Alternatives: Reuse the user's npm configuration; parse and selectively redact `.npmrc`.

Reason: Avoid implicit credential access and configuration-driven substitution.

Trade-offs: Private registries and projects requiring custom npm configuration are unsupported.

Revisit If: A separate credential-handling architecture is approved.

## Deterministic npx binary selection

Date: 2026-09-01

Context: An npx package can expose multiple binaries, and its executable code is a stronger consequence than installation alone.

Decision: Bind one binary name from registry metadata. Prefer the package basename; otherwise accept only a single declared binary. Reject ambiguity and the legacy `--ignore-existing` option.

Alternatives: Let npx infer a binary at execution time; accept arbitrary pass-through command arguments.

Reason: The approved command must identify the code entry point exactly.

Trade-offs: Some multi-binary packages are unsupported in v0.

Revisit If: The CLI adds an explicitly parsed and approved `--bin` option.

## Native connections bind state to a dashboard instance ID

Date: 2026-09-02

Context: A state file containing only a URL, PID, and start time cannot safely distinguish PID reuse, stale files, or asynchronous responses from an older dashboard generation.

Decision: Add a random non-secret `instance_id` to the version-1 state document and authenticated health response. A native client must validate both values and invalidate the entire prior connection generation on file replacement or removal. PID and start time remain diagnostic only.

Alternatives: Trust PID/start time; bump the state and API major versions; rely only on bearer-token success.

Reason: Instance matching gives the future macOS companion a stable freshness check without exposing secrets or breaking existing clients that ignore additive JSON fields.

Trade-offs: This is not OS process attestation. A malicious process running as the same user may read the private state file and token.

Revisit If: The packaged desktop product adds code-signing checks, peer-process identity, or OS-protected local credentials.

## Exact MCP identity requires a trusted profile and one immutable dispatch snapshot

Date: 2026-09-07

Context: Generic MCP arguments can contain secrets and arbitrary private data. ER1 therefore records only
structural MCP identity, while the gateway previously evaluated a cloned arguments object but forwarded
the original request parameters.

Decision: Prepare one cloned, deeply frozen call snapshot and use it for policy evaluation, approval, and
upstream dispatch. Only the centralized identity authority can elevate a call above structural assurance.
It accepts explicitly registered, APG-built, versioned profiles with closed typed field definitions.
`adapter_action_exact` requires complete behavior-parameter coverage; unknown fields, type failures,
schema drift, unsupported request metadata, or profile failure reject exactness. The first implementation
ships no production profile and changes no production policy rule semantics.

Alternatives: Hash redacted arguments; trust upstream JSON Schema annotations; allow arbitrary
user-authored projection selectors; add secret commitments immediately.

Reason: A safe subset digest is not exact identity, and key-name redaction cannot classify arbitrary
secrets. A small trusted profile boundary makes exactness reviewable while preserving structural fallback
for unknown tools.

Trade-offs: Most MCP calls remain structural until a production profile is reviewed. The configured
server ID is still only a label, not binary provenance, and tools whose credential arguments affect
account, target, or behavior may not qualify for portable exact identity.

Revisit If: APG adds reviewed production profiles, principal identity, server executable provenance,
user-defined profiles, or selective-disclosure commitments.

## First production MCP profile is explicit, zero-parameter, and target-only fail-closed

Date: 2026-09-07

Context: The shared identity authority needed one narrow production integration before considering
path-bearing, credential-bearing, or side-effecting MCP tools. The pinned Filesystem source defines
`list_allowed_directories` without input parameters, but its result can expose private paths and its
allowed-directory state can change through MCP Roots.

Decision: Ship `filesystem.list-allowed-directories.v1` as an explicit `--identity-profile` selection.
Validate the selector before database/upstream initialization, bind a bounded startup input-schema
digest, require exact identity only for the covered tool, and block profile mismatch before policy or
upstream dispatch. Do not lower Allow/Ask/Deny, auto-select from upstream metadata, alter other tools, or
claim more than configured-label server provenance. Exclude returned paths and Roots state from request
identity and portable result evidence. MCP audit summaries retain only bounded error/type/count metadata,
not text or structured result bodies.

Alternatives: Auto-detect the server from its tool/schema; begin with a path-bearing read; hash returned
directories; add a server-ID policy change simultaneously.

Reason: A zero-parameter request minimizes private identity material and exercises real profile
selection, drift detection, approval, and receipt machinery without conflating request exactness with
server authenticity or result identity.

Trade-offs: A malicious same-shape server can still mimic the reviewed tool, schema drift causes an
availability failure, and the result still reaches the requesting MCP client/model. The checked-in schema
fixture remains runtime-unvalidated until a separately approved pinned-package acceptance is run.

Revisit If: The pinned runtime advertises a different schema, executable provenance becomes available,
APG handles dynamic tool-list changes, or a result-identity design can protect private paths.

## MCP profile evidence uses receipt schema 1.1 without a database migration

Date: 2026-09-07

Context: Exact and partial MCP projections need profile identity, safe claims, coverage, schema-drift
evidence, and rejection status that version-1.0 receipts do not contain.

Decision: New profile-bearing receipts and their portable envelope use minor version 1. Existing
non-profile receipts remain version 1.0. The verifier supports both exact variants, checks their version
relationship and identity invariants, and never upgrades historical evidence. Additive receipt events
carry the data without changing the SQLite schema.

Alternatives: Overload the version-1.0 action digest; bump the major version; migrate persistent tables.

Reason: A minor version makes the semantic addition explicit while retaining existing receipt bytes and
avoiding an unnecessary persistent-data migration.

Trade-offs: Older verifiers reject 1.1 profile receipts, and the verifier maintains an explicit 1.0/1.1
compatibility union.

Revisit If: Future evidence cannot fit additive receipt-finalization events or changes the meaning of an
existing required field.
