# Architecture Decisions

## Archive parsing uses fresh child processes and APG-owned two-pass materialization

Date: 2026-09-07

Status: accepted on 2026-09-07. The approved network-free synthetic foundation is implemented locally;
real artifact and production integration remain separate approval boundaries.

Context: The exact candidate adapter is currently synchronous and in-process. Real untrusted archives
need interruptible failure containment, exact artifact/runtime identity across two passes, a filesystem
boundary outside the parser library, and a durable definition of when materialized bytes become
launchable.

Decision: Run pass A and pass B in separate fresh shell-free child processes with closed bounded
protocols, while the APG parent retains artifact descriptors, authenticates the pass-A transcript, and
owns every pass-B filesystem write. Materialize only beneath a private random POSIX pending root using
exclusive no-follow leaf opens, independently verify all body hashes and the complete tree, then require
durable audit ordering plus an exclusive authenticated seal before `READY`. Treat Node's Permission
Model as defense in depth, not a sandbox. Fail the real-worker capability gate on Node 24 unless a
separately reviewed OS provider supplies no-network containment.

Alternatives: Keep parsing in-process; use worker threads; let node-tar extract; write after one pass;
rename a directory as the sole readiness signal; silently run Node 24 without network denial.

Reason: A child contains parser crashes and permits parent-owned deadlines better than a worker thread,
while two complete matching passes keep third-party parsing and APG filesystem mutation separate. A
sealed-and-audited readiness condition prevents partial or late-failing output from becoming runnable.

Trade-offs: This is POSIX-only, rejects real archive work on an uncontained Node 24 host, and still does
not defeat root or a malicious same-user actor. Child IPC and a second full parse add complexity and
cost. USTAR-only support may reject legitimate packages, and power-loss/cleanup behavior remains
filesystem-dependent.

Revisit If: Node 24 support is dropped; a reviewed OS sandbox/native descriptor-relative writer is
added; the worker is reproducibly bundled; the selected filesystem lacks the required durability
semantics; or an exact production package requires a broader archive grammar.

## Exact tar artifact and six-node lock graph are conditionally accepted

Date: 2026-09-07

Context: The parser-only architecture required registry evidence for one exact artifact and the actual
APG production lock impact before any dependency or candidate-backed fixture execution could be
approved.

Decision: Accept exact `tar@7.5.22` for the separately approved network-free synthetic fixture
checkpoint. Its APG lock adds only `tar`, `@isaacs/fs-minipass`, `chownr`, `minipass`, `minizlib`, and
`yallist`, all at reviewed exact versions, public HTTPS registry URLs, and SHA-512 values. The adapter
imports only `tar/parse`; scripts remain disabled and every extraction, unpacking,
member-selection, and library filesystem-writing API remains prohibited.

Alternatives: Use a floating `tar` range; accept upstream repository metadata without an APG lock
preview; use `tar-stream`; download the candidate artifact during this review.

Reason: The isolated preview produced no unrelated lock churn, native/optional/prebuilt/install-script
node, or known production advisory, while the public package exports a dedicated parser entry compatible
with Node 24-26.

Trade-offs: The package still exposes broad unused APIs and has a substantial security history. Public
metadata and registry integrity do not prove publisher identity, reproducible build, or absence of a
zero-day. Registry signatures were advertised but not verified. Only synthetic in-memory fixtures have
run; synchronous decompression/parser work is not yet an interruptible real-artifact boundary.

Revisit If: Any lock node, origin, integrity, script flag, license, engine, advisory, export, or fixture
result changes; the Node 24-26 corpus differs; or a narrower maintained parser becomes demonstrably safer.

## Archive handling uses a parser-only candidate, a narrower grammar, and two matching passes

Date: 2026-09-07

Context: Verified package staging needs to interpret untrusted registry archives after integrity
verification. A parser and extractor that disagree can hide members, while a general extraction API
places path, link, ownership, and filesystem mutation behavior inside a third-party trust boundary.

Decision: Prefer an exact separately reviewed `tar/parse` version as a parser-only candidate. Prohibit
all node-tar filesystem-writing and member-selection APIs. The first profile accepts only bounded
gzip-wrapped USTAR, rejects PAX/GNU extensions and all non-file/directory types, and requires a complete
write-free inspection transcript followed by a second identical parse and APG-owned no-follow
materialization. Build adversarial fixture bytes independently before adding the candidate dependency.

Alternatives: Use node-tar extraction; use `tar-stream`; invoke system tar; implement a custom parser;
admit PAX/GNU metadata in v0; inspect once and extract through another implementation.

Reason: Parser-only use plus a deliberately narrow grammar and same-parser transcript comparison reduces
filesystem escape and interpretation-differential exposure while retaining a maintained parser candidate.

Trade-offs: `tar` still has a significant security history and installs unused broader APIs. USTAR-only
support will reject some legitimate packages. Parser zero-days and same-user/root races remain, and the
exact registry artifact, APG lock graph, licenses, and Node-version behavior are not yet approved.

Revisit If: The preferred candidate fails the exact artifact/lock review or adversarial corpus, a
narrower maintained parser becomes available, the first exact package requires an extension grammar,
or OS isolation changes the filesystem boundary.

## Verified MCP staging starts with one closed graph and non-transitive approvals

Date: 2026-09-07

Context: Hashing a configured npm/npx launcher does not bind the package code, dependency graph, or
materialized files that a future MCP process executes. A general npm resolver would place too much
mutable package-manager behavior inside APG's trust boundary.

Decision: The first verified package stage accepts only an APG-shipped exact package/version/artifact/
dependency-layout profile. Metadata confirmation, package download/private staging, project install,
package startup, and MCP tool action remain separate authority boundaries. Integrity must succeed before
archive inspection; scripts stay disabled; a complete normalized file tree is revalidated before a
future launch. Begin with network-free authenticated types, validators, state, and synthetic adapters;
ship no production profile or external action in this checkpoint.

Alternatives: Continue launching `npx package@version`; trust a lockfile and npm exit status; implement a
general resolver; reuse npm's cache as the durable stage; select a tar implementation immediately.

Reason: A closed reviewed graph and consequence-specific approvals make the strongest evidence APG can
honestly support at the package-action layer without claiming publisher trust, reproducible builds,
runtime safety, containment, or attestation.

Trade-offs: No real package can use the foundation yet. The first production profile will support fewer
packages, archive handling remains blocked on a dependency/security review, and same-user/root races
remain until stronger OS containment or descriptor-based launch primitives exist.

Revisit If: A production exact graph is accepted, maintained archive handling is approved, npm
provenance is added as a separate assurance dimension, or runtime sandboxing/attestation becomes part of
the product boundary.

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
availability failure, and the result still reaches the requesting MCP client/model. The first approved
pinned-package run rejected the SDK 2.x fixture before dispatch, captured the package's draft-07 wire
schema, and the corrected profile then passed a target-only real acceptance with exact receipt evidence.

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

## Production graph authority requires complete read-only artifact acceptance

Date: 2026-09-08

Context: A lockfile and self-consistent profile digest can describe exact package bytes and layout, but
cannot prove that every artifact is served as declared, accepted by the bounded parser, or semantically
consistent with its package manifest. Direct promotion would overstate assurance.

Decision: Keep an untrusted exact graph candidate distinct from an accepted production profile. Limit the
first target to `@modelcontextprotocol/server-filesystem@2026.7.10` on darwin-arm64/Node 26. Before
repository registration, require complete fresh exact metadata, a one-time full-artifact plan, SHA-512
verification into private disposable files, two independently reopened write-free Pass-A workers, bounded
package-manifest projection, complete exact cleanup, and human review. Every later real network,
registration, materialization, startup, and MCP-action boundary retains separate authority.

Alternatives: Trust the lockfile and metadata; accept only the top artifact; materialize during acceptance;
reuse npm's cache; automatically promote a successful runtime report.

Reason: Separate authorities prevent a valid digest, partial graph success, or unclean temporary run from
becoming production identity while retaining a software-only evidence path that never executes package code.

Trade-offs: The first profile is platform-specific and conservative, rejects unsupported lock semantics,
adds two parser processes per unique artifact, and still does not prove publisher identity, source/build
equivalence, maliciousness, sandboxing, or runtime safety.

Revisit If: A second runtime/platform profile is proposed, resumable acceptance is needed, provenance or
signing evidence is added, or persistent materialization/startup becomes eligible for separate review.
