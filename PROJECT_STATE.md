# Current State

## Current Milestone

**Latest authority (committed `8ffd0b9`):** v14 produced a verified safe failure, not successful candidate
acceptance. The network-free, memory-only Plan3/Projection3/Envelope2 binding foundation is implemented but
un-wired. Fresh evidence is typecheck/build, 75/75 focused tests, and 364 passed with 3 conditional skips
(32 files passed, 1 skipped). It changes neither live authority nor v1 production semantics, and v2
integration remains separately approval-gated. See
`docs/exact-candidate-v2-plan-envelope-binding-architecture-check.md`.

The Exact Production Graph Genesis Live Run Readiness Architecture Check was accepted on 2026-09-09. Its first
network-free readiness foundation is committed and pushed at `7c15130`. The approved non-injectable production
owner and synthetic full-flow are committed and pushed at `592b286`: the exact CLI now hands off to one
owner of runtime capture, containment, approval, audit, broker, process, output, cleanup and terminal
reconciliation. The compiled production probe no longer depends on a test fixture. Default tests do not invoke
the live owner; the full network-free regression is `290 passed, 3 skipped`. One disposable first command
attempt reached Dashboard approval and expired before external read, npm, candidate output or package effect;
its lingering disarmed broker listener exposed a process-liveness defect. The committed correction drains that
listener on deny, expiry and cancellation. A separately approved disposable v2 attempt observed public metadata
and a lock-only npm child, then naturally exited in the conservative quarantine path (exit 5): no candidate or
Dashboard-state output remained. Its immutable audit evidence records six validated metadata requests and four
additional starts without validation; the product terminal sequence is incomplete and is not replayed. The
broker-latch correction committed and pushed at `c0b48b6` keeps `genesis_incomplete` out of the shared audit gate, hands one
authenticated private bounded failure summary to the live owner, and waits for process/listener observation before
that owner writes the existing product terminal outcome. A separately approved v4 run confirmed that ownership:
the product terminal sequence records npm cancellation, listener drain, one incomplete outcome and completion after
10 metadata starts and six validations. The last four starts (`ajv`, `zod`, `cors`, `hono`) do not identify the
initiating failure: a fifth concurrent request or invalid route can fail before an intent record and abort those
four transports. Three network-free tests reproduce the same safe counts and ordered intents with distinct
initiating conditions. The exact v4 predicate remains unknown. The locally implemented, user-approved v5
diagnostic checkpoint in `docs/graph-genesis-v5-private-diagnostics-design.md` adds an authenticated first-failure
predicate and one bounded local stderr projection without receipt/audit schema changes or relaxed checks.
It is covered by synthetic broker, owner, child-exit and broken-pipe tests. The separately approved v5 live
acceptance then observed `concurrent_request_limit` with a null pre-reservation ordinal, ten request starts,
six validations and 644145 validated bytes; it quarantined with exit 5 and left no candidate or Dashboard state.
The follow-up approved network-free checkpoint fixes npm's per-origin connection limit at four in the launch
identity while retaining the broker's four-request fail-closed cap, no queue and no retry. It requires a fresh
review and acceptance; it does not reinterpret or reuse v1-v5 evidence. See also
`docs/exact-production-graph-genesis-live-run-readiness-architecture-check.md` and
`docs/graph-genesis-v5-maxsockets-architecture-check.md`. The supplied v7 safe result reports npm exit 0, metadata
126/126 validated, maximum active requests of four, 6,792,802 validated bytes and listener drain, but stops at
`lock_validation_started` without candidate/Dashboard output and with a quarantined forwarding/no-terminal result.
It does not establish the exact post-state predicate or a successful action. The current network-free checkpoint
corrects the validated-metadata terminal mismatch and adds authority-owned, bounded local post-state predicates;
it leaves the audit/receipt schema, broker limits, fixed npm arguments, no-queue/no-retry behavior and all v1-v7
evidence untouched. See `docs/graph-genesis-v7-terminal-post-state-checkpoint.md`.
The approved v9 bounded manifest classification later found exact base fields but an absent/invalid dependencies
container and target spec, without exposing the quarantined file. The current v10 network-free checkpoint keeps the
exact post-state manifest requirement and makes npm's production save type explicit with fixed
`--save-prod` after `--save-exact` and before `--maxsockets=4`. The resulting launch digest changes the plan,
execution capsule and Dashboard envelope, so prior approvals cannot be reused. It changes no broker/containment/
cleanup/terminal semantics or audit/receipt/DB schema and does not establish a live success. See
`docs/graph-genesis-v10-save-prod-architecture-check.md`.
The approved v11 network-free checkpoint replaces the base-only initial workspace manifest with one shared,
canonical exact dependency declaration written exclusively at mode `0600` by both Graph Genesis initializers. Its
protected-file descriptors bind inode, mode, size and content digest into the workspace binding, containment
evidence, plan, capsule and Dashboard envelope; pre-spawn and post-state drift checks reject replacement,
in-place mutation and same-semantic byte rewrites. The fixed `--save-prod`/four-socket launch, exact post-state,
broker limits, no-queue/no-retry, cleanup and terminal semantics remain unchanged. It changes neither audit,
receipt nor DB schema, dependencies, approval logic or parsing, and does not establish a live success. See
`docs/graph-genesis-v11-predeclared-manifest-architecture-check.md`.

The approved Exact Project Root Binding correction now makes the fixed npm launch use exactly
`--prefix=<workspace>` rather than the former nested `prefix/` directory. Both workspace
initializers and post-state inventories reject that legacy directory, while plan reconstruction
rejects missing, changed, duplicate and moved prefix arguments. The changed launch digest flows
through the plan, execution capsule and Dashboard envelope; protected manifest binding,
workspace-root lockfile validation, containment, no-`node_modules`, no-download, broker,
cleanup and terminal behavior remain unchanged. The related network-free Graph Genesis unit regression
passed 107/107. No npm, Dashboard, DNS/HTTPS, live execution, product DB, candidate, quarantine,
prior evidence, dependency, commit or push action occurred. See
`docs/graph-genesis-exact-project-root-binding-architecture-check.md`.

The current approved network-free Candidate Compiler Private Diagnostics checkpoint gives the
exact lock compiler thirteen closed, authority-authenticated rejection predicates while preserving
the public `graph_lock_invalid` error and all generic terminal behavior. Candidate authority and
the hardened Graph Genesis compiler use private WeakMap/WeakSet provenance and one-time claims;
the live owner may write one bounded redacted stderr line only after terminal handling and terminal
observation/listener drain. It neither writes a candidate artifact on failure nor changes audit,
receipt, DB schema, approval, broker, cleanup, dependencies or terminal semantics. Synthetic
tests cover every predicate, copied/foreign error rejection, one-time projection and owner
ordering. The synthetic boundary verifies candidate absence, omitted candidate evidence,
post-state-bound cleanup and the unchanged pure classification; it does not claim a full production
live terminal triple. The targeted local Vitest command passed 66/66 and the full local safe suite
passed 330 tests with 3 conditional skips; `tsc -p tsconfig.json --noEmit` and `git diff --check`
also passed. No real npm, Dashboard, DNS/HTTPS, live execution, product DB,
candidate/evidence or quarantine access, dependency change, commit or push occurred. See
`docs/graph-genesis-candidate-compiler-private-diagnostics-architecture-check.md`.

The approved Candidate Package Role Private Subpredicate checkpoint replaces the compound private
`package_role_rejected` vocabulary with fourteen deterministic field-level predicates and raises
candidate diagnosticVersion to 2. Sorted install-path traversal and the prescribed field order
select one first failure; boolean flags remain rejected only when true, while defined dependency,
bundle and selector fields remain rejected even when false. Public `graph_lock_invalid`, strict
compiler behavior, provenance, bounded one-time stderr, post-terminal ordering, candidate absence,
cleanup, approval, audit/receipt/DB schemas and dependencies remain unchanged. Targeted tests
passed 50/50 and the full network-free suite passed 331 tests with 3 conditional skips; typecheck
and diff check also passed. No real npm, Dashboard, DNS/HTTPS, live execution, product DB,
candidate/quarantine/evidence access, dependency change, commit or push occurred. See
`docs/graph-genesis-candidate-package-role-private-subpredicate-architecture-check.md`.

The v14 Graph Genesis Live Acceptance Architecture Check executed once on 2026-09-12 and produced
a verified safe failure, not successful candidate acceptance. Dashboard approval was approved;
the lock-only child exited 0, while the version-2 private compiler predicate was
`package_peer_dependencies_rejected`, with public result `incomplete_external_read` (exit 4).
New-v14-only read-only verification found 126 validated metadata responses across 117 packages,
6,796,352 bytes, schemas `[1,2]`, a valid 275-event hash chain and receipt bindings, terminal
order `graph_genesis_incomplete` → `execution_completed` → `outcome_receipt_finalized`, absent
candidate/output events, and complete cleanup. The evidence supports existing no-installation and
no-package-download claims without direct tarball/download/node_modules observation. No retry or
prior evidence/quarantine access occurred. Next work is a network-free Exact Candidate Peer
Dependency Semantics Architecture Check before source changes or v15. See
`docs/graph-genesis-v14-live-acceptance-architecture-check.md`.

The approved Exact Candidate Peer Dependency Semantics checkpoint adds an un-wired, in-memory
evaluator and synthetic unit coverage for the documented strict peer subset. It neither reads
lockfiles nor has candidate, approval, audit, receipt, artifact, diagnostic, process, or runtime
authority; existing v1 peer rejection and all production wiring remain unchanged. Diff check,
typecheck, and the focused evaluator test passed (8/8). Test-only timing hardening retained the 150ms
hang boundary, gave only malformed/stderr startup cases 1000ms, bounded state polling at 5000ms, and
gave only policy-update announcement/state-rotation tests 10000ms/15000ms deadlines. Archive worker
targeted tests passed 5/5, stdio proxy targeted tests passed 28/28, and canonical `npm test` passed:
29 files passed, 1 skipped; 339 tests passed, 3 skipped (342 total). No production source, global
Vitest configuration, dependency, or security boundary changed. These network-free results do not
prove live product behavior; no evaluator source/import connection was found. No real npm, Dashboard,
DNS/HTTPS, live execution, product DB,
candidate/evidence/quarantine access, dependency change, commit, or push occurred. See
`docs/exact-candidate-peer-dependency-semantics-architecture-check.md`.

The historical v7 terminal-classification and other earlier current-state entries remain historical evidence.
The current follow-up pure evaluator correction processes each reachable peer once, closes required peers
through ordinary dependencies, accepts the approved one-or-more-U+0020 grammar, counts slash-delimited path
segments, and rejects global combined requirements before range parse/traversal. Its synthetic regressions
cover lexical/input ordering, missing/conflicting peers, required-peer ordinary closure, ordinary peer-subgraph
cycle, and exact/+1 combined/global/per-node budgets. The approved memory-only v2 authority now accepts only
explicit v1-compatible metadata plus `packageLock: unknown`, retains exact artifact/runtime/security identity
and raw dependency/peer/meta/peer-role presence, and derives edges and tagged peer outcomes through the shared
evaluator. The canonical memory codec rejects noncanonical bytes and duplicate keys at every depth, then
reconstructs and recompiles retained declarations before accepting a digest. A self-consistent alternate valid
payload remains decodable plain evidence, but it authenticates under neither its original compiler authority nor
any other authority; malformed or recomputed-inconsistent evidence is rejected. Typecheck and 22/22 focused tests
passed. The canonical build/full network-free suite passed 31 files with 1 skipped and 353 tests with 3 conditional
skips (356 total); diff check passed. The foundation
remains un-wired and changes no v1 production integration, identity/schema, approval, audit, candidate, or live
behavior. No Graph Genesis npm child, package resolution/install, registry/network, Dashboard, live execution,
product DB, real candidate/evidence/quarantine access, dependency change, commit, or push occurred. The v2 design
and memory-only foundation are prepared; see
`docs/exact-candidate-peer-semantics-v2-integration-architecture-check.md`.

The prior Production Graph Genesis Approval & Execution Composition Architecture Check was accepted on
2026-09-08 and its foundation was committed and pushed at `6108936`. It provides exact execution envelope,
durable-before-visible local
one-time approval, authenticated existing-schema DB opener with pre-session identity/schema/chain revalidation,
receipt 1.2, central abort/inert-child composition, two-phase
start lease, tracked listener drain, post-state-bound cleanup, and a terminal-proof-bound candidate artifact.
No real npm, public DNS/registry, product DB, real candidate output, artifact, or package code was used. See
`docs/production-graph-genesis-approval-execution-composition-architecture-check.md`.

The Exact Local Graph Genesis Plan Capture & Preflight Architecture Check was accepted on 2026-09-08;
its internal preparation workflow, disposable SQLite adapter and actual local capture are committed and
pushed at `d988310`. The capture passed and closed all owned resources; no reusable execution
authority, real npm CLI invocation or public DNS/registry request was created. See
`docs/exact-local-graph-genesis-plan-capture-preflight-architecture-check.md`.

The prior Exact Real Metadata-only Graph Genesis Plan Architecture Check was accepted on 2026-09-08 and its
network-free production-adapter hardening is committed and pushed at `3860338`. The checkpoint separates the
safe plan from its private execution capsule and closes the owned runtime/probe/workspace, concurrent broker,
pinned HTTPS, process supervision, strict post-state, no-follow cleanup, ordered audit, and final completion
authority gaps. No public DNS/registry request or real npm launch has occurred.

The exact parser plus bounded worker/two-pass POSIX materializer foundation is committed and pushed at
`46497f9`. All archive work to date used repository-owned synthetic bytes and disposable private
directories. No real MCP package archive, new registry request, production graph profile, persistent
stage, receipt/database change, or staged package startup has occurred in the current milestone.

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
- Exact Archive Parser Artifact & Lock Graph Review completed on 2026-09-07:
  - exact candidate `tar@7.5.22` with public `tar/parse` export and reviewed registry SHA-512
  - six-node added production graph, all public HTTPS registry artifacts with exact integrity values
  - no optional/native/prebuilt/install-script lock nodes and no unrelated APG lockfile churn
  - combined production audit reported zero known advisories at review time
  - at review completion, dependency addition and parser execution remained a separate approval gate
- Exact `tar@7.5.22` candidate-backed fixture foundation implemented locally:
  - reviewed exact six-node production lock graph added with scripts disabled
  - literal `tar/parse` is the only tar import; no filesystem/network/subprocess API in the adapter
  - strict one-member gzip CRC/size/ratio gate and narrow USTAR checksum/type/end/padding gate
  - node-tar ordered path/type/size/mode/body results must match the APG envelope interpretation
  - frozen runtime-authenticated transcripts bind artifact SHA-512 and ordered body SHA-256 evidence
  - complete transcript equality covers three same-length cross-pass substitutions
  - no real MCP package archive, extraction, materialization, persistent stage, or startup
- Bounded Archive Worker & Two-Pass Materialization Architecture Check accepted on 2026-09-07:
  - fresh shell-free child process per pass, bounded closed-schema IPC, parent deadline/cancellation
  - retained-descriptor artifact hashing and exact reopen identity across passes
  - parent-authenticated write-free pass-A transcript and streaming pass-B equality
  - APG-owned POSIX private-root materializer with exclusive no-follow leaf writes
  - independent full-tree revalidation and seal-plus-durable-audit readiness
  - explicit Node Permission Model non-sandbox language and Node 24 no-network capability gate
  - synthetic isolated failure/crash/audit/cleanup test strategy with no real artifact or package code
- Network-free Bounded Archive Worker & Synthetic Two-Pass POSIX Materializer implemented locally:
  - fresh shell-free permission-gated child per pass with empty environment and private cwd
  - exact hashed Node/worker/parser runtime manifest revalidated before both passes
  - bounded request/artifact/ACK stdin and length-prefixed closed-schema stdout protocol
  - timeout, cancellation, process-group termination, V8 limits, and bounded stderr/stdout
  - parent-authenticated pass-A transcript and ordered pass-B metadata/body/hash equality
  - exclusive no-follow parent writer, restrictive initial modes, sync, and complete tree verification
  - exclusive read-only seal plus ordered synthetic audit with post-seal audit failure blocking `READY`
  - monotonic pass/seal states, runtime drift rejection, quarantine without blind cleanup
  - all 52 fixtures through child processes and isolated temporary materialization only
- Bounded Archive Worker foundation committed and pushed at `46497f9`
- Exact Production Graph Profile & Read-only Artifact Acceptance Architecture Check accepted on 2026-09-08
- Network-free Exact Production Graph and Read-only Artifact Acceptance foundation implemented locally:
  - candidate and accepted production profile are owned by separate authorities
  - strict synthetic lockfile-v3 compilation binds exact Node-resolution install edges and rejects unsupported graph behavior
  - complete fresh metadata confirmation uses fake transports with exact URL/integrity and byte/deadline limits
  - one-time approval binds the complete ordered artifact set, runtime, protocol, limits, and private root
  - exclusive private files are SHA-512 verified before descriptor-backed worker access
  - worker protocol v2 supports bounded package-manifest evidence without Pass B
  - two independent Pass-A processes, transcript equality, duplicate-key rejection, manifest projection,
    exact cleanup, and synthetic terminal evidence precede test-only profile promotion
  - no registry request, npm graph generation, real artifact, materialization, persistent stage, DB change,
    CLI integration, package startup, or production profile registration
- Exact Production Graph Read-only Acceptance foundation committed and pushed at `b1d4fe5`
- Bounded Metadata-only Graph Genesis Architecture Check accepted on 2026-09-08
- Network-free Bounded Metadata-only Graph Genesis foundation implemented locally:
  - bounded exact runtime-tree snapshots with path, identity, mode, size, content, symlink, collision,
    hardlink, special-file, world-write, entry-count, and byte-limit checks
  - private workspace creation with protected-file identities, exact synthetic pre/post state, archive/content
    rejection, bounded no-follow reads, exact-root cleanup, and cleanup authority
  - generated one-port macOS Seatbelt development profile and successful repo-owned local-only containment
    probe across approved/alternate/non-loopback/IPv6 destinations plus Node write/process/worker/addon denial
  - immutable exact npm command/environment builder without shell, inherited PATH/config/proxy/auth state,
    npm execution, or production process runner
  - one-time plan/approval brands that bind runtime, workspace, containment, broker, route, target, launch,
    resource limits, and reject forgery/replay/substitution
  - injected fake packument transport with closed canonical route, owned public URL construction, no header
    forwarding, strict bounded JSON/name validation, deadline/aggregate/concurrency limits, and safe digest ledger
  - synthetic exact lock compiler handoff; controlled completion requires genuine authorization, complete broker
    ledger, exact workspace cleanup, and authenticated ordered terminal audit
  - full network-free regression: 226 passed, 3 skipped
- Exact Real Metadata-only Graph Genesis Plan Architecture Check accepted on 2026-09-08
- Network-free Graph Genesis production-adapter hardening implemented locally:
  - safe immutable approval projection and plan are separated from the memory-only route/path capsule
  - authority-owned exact file/tree snapshots, Node/npm version observation, finalized workspace, local-only
    Seatbelt probe, and spawn-time full revalidation reject drift and caller-shaped evidence
  - exact disarmed loopback listener and anonymous public-registry transport enforce canonical routes,
    fixed headers, DNS deadline/classification, pinned socket address, npm hostname TLS, and streaming limits
  - broker limits are atomically reserved before dispatch; first failure aborts the session, disarms local
    traffic, rejects late results, and prevents approval replay or terminal ledger authentication
  - shell-free private-capsule supervision bounds time/output, TERM/KILL escalation, child close, and audit
    failures without retaining raw output
  - strict no-follow post-state evidence rejects unknown/link/executable/archive residue and binds the exact
    private lock document to the closed candidate compiler
  - final completion requires matching process, ledger, post-state, candidate, cleanup, and ordered terminal
    audit evidence for one exact plan
  - no dependency, product database, CLI, policy, Dashboard, registry, artifact, or package execution change
  - full network-free regression: 242 passed, 3 skipped

## In Progress

The following early composition checkpoints are historical. The latest v14 safe failure and current
un-wired evaluator/v2-design summary above supersede them as the current Graph Genesis status.

- The pre-spawn cancellation classification correction is committed and pushed at `31fd835`: an approved
  action cancelled before spawn and before any external read returns `not_started`/exit 2, while quarantine,
  terminal ambiguity, spawn and external-read outcomes retain their conservative classifications.
- A disposable first live command attempt expired before approval and produced no external read, npm,
  candidate or package effect. The local uncommitted liveness correction drains the disarmed broker listener
  before Dashboard teardown on denial, expiry or cancellation.
- Historical early-composition note: the public CLI was locally connected before later v14 safe-failure
  evidence. Any new live acceptance remains a separate approval for named paths plus Dashboard decision.
- The execution envelope directly binds the owner-captured comprehensive runtime-manifest digest as well as
  the exact plan/projection, Dashboard instance, policy,
  persistent audit sink, candidate output, limits and deadlines. The closed preflight hash is never reused.
- Broker arm and process spawn now require distinct one-time consumptions of the same authenticated start
  lease; listener close-and-drain and the synthetic single abort owner close the prior race gaps.
- Receipt schema 1.2 and a terminal-audit-bound candidate artifact let later stages verify the
  observed graph without treating a copied/orphan file as launch or profile authority.
- A closed synthetic result remains evidence-only, not reusable approval or execution authority. The test-only
  full-flow twin has no production resolver, HTTPS client or spawn adapter.
- A candidate output is durable before terminal commit but is not importable without matching DB-backed
  `graph_genesis_complete` and Outcome Receipt proof. An interrupted acknowledgement performs one read-only
  reconciliation and never retries the action.
- Post-spawn cleanup is permitted only from authenticated post-state. Unknown trees are retained as a bounded
  private quarantine and represented by a digest reference instead of unsafe broad deletion or path disclosure.
- The implemented preflight audit adapter reuses the current schema only in a new owned temporary DB, with namespaced
  preflight events, a dedicated parent row and committed/reopened chain verification; it creates no receipt
  or fictional approval and does not open the product audit database.

## Remaining

- Historical production-owner commit/live-acceptance checkpoint; superseded as current work by the peer v2
  design gate above. Any future live action still requires its own exact approval.
- Decide whether to accept the POSIX-only preview or design a Windows runner separately.
- Separately approve a production graph profile, registry confirmation, target artifact download/stage
  creation, receipt 1.2, and package startup.
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
- A production Graph Genesis approval must bind the complete execution envelope, including its persistent
  audit sink and candidate output; `planHash` alone is insufficient.
- The production process supervisor must require the same authenticated live-session start lease as the
  broker. No low-level production component may independently convert copied evidence into execution.
- A Graph Genesis candidate artifact is public graph evidence only and is importable only with matching
  terminal audit/Outcome Receipt evidence; it is not a production profile, stage, or startup authority.

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
- Archive worker isolation is capability-gated rather than described as a sandbox. Real artifact work
  on Node 24 fails closed unless a separately reviewed OS provider supplies no-network containment.
- A materialized path is not launchable by presence alone. The exact tree, authenticated seal, and
  durable terminal `READY` audit state must all validate.

## Known Issues

- Historical pre-v14 note: later v14 produced a safe failure rather than a successful candidate acceptance.
  Exact macOS/Node/npm/runtime-path checks still fail closed with no fallback or version widening.
- APG verifies the captured runtime files and containment observations, not the complete OS, kernel, dynamic
  libraries or system trust store.
- A post-spawn failure before authenticated post-state leaves the bounded private temporary root quarantined.
  Automatic deletion is intentionally withheld; the audit/result carries only a reference digest. v7 identifies
  neither the exact post-state predicate nor a successful terminal outcome; the new local predicate projection is
  diagnostic-only and cannot retroactively classify that action.
- A successful Graph Genesis candidate is unsigned public graph evidence, not a production profile, staged
  package or MCP launch authority.
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
  adapters are not connected to the CLI, Dashboard, durable audit DB, production registry path, archive
  extraction, persistence, or launch. The selected parser library is exercised only by synthetic
  fixtures; no production graph profile, receipt 1.2 evidence, or staged launch exists yet.
- Exact `tar@7.5.22` and its six-node graph are present, but only synthetic in-memory fixtures have run.
  Registry signatures remain unverified. Synchronous parser CPU now runs inside a bounded child for the
  new path, but Node 24/25 cross-version behavior is not yet evidenced and the child boundary is not an
  OS sandbox. It is not approved for a real untrusted package artifact or persistent materialization.
- Exact production graph acceptance remains foundation-only. Metadata and artifact adapters have injectable
  network-free interfaces but no production HTTPS implementation or built-in Filesystem graph. Synthetic
  acceptance does not establish publisher identity, source/build equivalence, maliciousness, sandboxing,
  materialized-tree integrity, launch readiness, or protection for direct npm/npx bypasses.
- Metadata-only graph genesis remains foundation-only. Production-shaped listener and HTTPS transport now
  exist, but the composed workflow has not run npm or contacted the registry. Its macOS Seatbelt provider is a
  deprecated/private, exact-host development mechanism, not a supported production sandbox; every real plan
  must repeat the complete local-only containment probe and fail closed on any drift or unavailable negative
  test. Node's `--allow-net` remains broad without that provider.
- Node's Permission Model is defense in depth, not a malicious-code security boundary. Node 24 has no
  network permission gate, and standard Node filesystem APIs cannot eliminate same-user
  intermediate-component races. The proposed architecture therefore blocks unsupported real-worker
  capability and never claims OS sandboxing or same-user containment.
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

- Live-run readiness focused coverage: 42 passed across exact CLI grammar, effect-free fail-closed route,
  action/envelope-scoped Dashboard approval and audit, exclusive state handoff, WAL/FULL/integrity/sidecar
  durability identity, immediate bounded Graph audit, `output_overflow` incomplete receipt evidence,
  candidate final readback/parent fsync and read-only DB-backed terminal proof.
- Historical 2026-09-09 full network-free regression: 290 passed, 3 skipped. The later 342 passed, 3 skipped
  result is historical; the current committed v2 foundation evidence is 353 passed, 3 conditional skips.
  Build, typecheck and whitespace
  checks passed. No product DB, public DNS/registry, npm/npx, real candidate/state output, package download,
  installation, package code, dependency/migration, credential/config read, publish or push occurred.
- Production Graph Genesis composition focused coverage: 10 tests for static no-network/no-real-spawn wiring,
  exact envelope/private capsule substitution, durable-before-visible approval failure, approve/deny/replay,
  receipt 1.2 and atomic terminal evidence, approval/audit-only Dashboard mode, existing private schema open
  without migration plus copied/substituted handle and chain-tail drift rejection, one-owner fake
  transport/inert-child abort composition, exclusive identity-bound candidate
  output with descriptor-based terminal-proof import, and post-state inventory cleanup/quarantine.
- Historical network-free full regression: 278 passed, 3 skipped on 2026-09-08 with one worker. Build, typecheck,
  and whitespace validation passed. No public DNS/registry, npm/npx, product DB, real candidate output, package
  download, installation, package code, publish, push, or credential/config read occurred.
- Final network-free full regression: 263 passed, 3 skipped on 2026-09-08. The subsequently added compiled
  cancellation suite passed 5/5 against the same unchanged runtime build. Build and final typecheck passed.
- Preparation/SQLite focused coverage: 21 passed for real disposable commit/reopen, concurrent scheduling,
  closed event sequence, malformed/oversize/forged input, lock timeout, injected insertion failure,
  chain/schema/parent/file/directory substitution, ambiguous cleanup, pre-cancel and entry-point restrictions.
- Compiled cancellation coverage: 5 passed for cancellation immediately after runtime capture, workspace
  creation, containment observation, audit reopen and cleanup; every report remained unauthorized/non-reusable.
- Final local capture at 2026-09-08T10:52:03.863Z passed runtime/version/containment/audit/revalidation checks;
  three audit events verified after reopen, owned temporary state removed, session closed. No public DNS,
  registry, npm CLI or package execution occurred. Exact safe evidence is in the Architecture Check document.
- Production-adapter hardening focused coverage: 16 passed across public-plan/private-capsule separation,
  authority-owned runtime/version/workspace/probe evidence, runtime drift with zero spawn, public/private and
  mixed DNS classification, pinned transport construction, durable request-before-transport ordering,
  concurrent reservation/session abort, disarmed exact loopback routing, supervised terminal/output/audit
  failure, strict post-state/candidate binding, no-follow cleanup/quarantine, all-authority completion, and a
  real local-only macOS Seatbelt/Node containment probe plus memory-only local TLS hostname/streaming checks.
- Metadata-only graph genesis focused coverage: 8 passed across runtime/workspace identity, exact launch,
  plan/approval/ledger/audit authority forgery and replay, canonical broker routing, redirect/JSON/deadline
  failures, internal/escaping symlinks, post-state substitution, controlled compiler handoff, exact cleanup,
  and a real local-only macOS Seatbelt/Node permission probe with no public destination.
- Exact production graph/read-only acceptance focused coverage: 6 passed. Cases cover candidate authority
  forgery, unsupported/unreachable/cyclic locks, exact Node ancestor resolution, metadata mismatch,
  metadata/artifact deadlines, one-time approval replay, private artifact streaming, two fresh descriptor-backed Pass-A workers,
  complete cleanup before profile promotion, duplicate manifest keys, and pre-parser SHA-512 rejection.
- Bounded worker/materializer focused coverage: 12 passed. All 52 fixtures run through fresh child
  processes; additional cases cover pass-B streaming, cross-pass substitution, authority forgery,
  pre-cancel, runtime drift, unsafe cwd, timeout, malformed stdout, stderr overflow, private-root writes,
  symlink preexistence, pending-root permission drift, intermediate-directory replacement, post-write
  mutation, seal collision, and audit failures before and after seal.
- Exact tar candidate focused coverage: 12 passed across 2 files. Candidate-specific tests cover two
  accepted transcripts, all 50 negative fixtures, three cross-pass substitutions, authority forgery,
  pre-abort/invalid limits, exact import restrictions, and exact six-node lock integrity.
- Archive adversarial fixture coverage: 7 passed over 52 archive fixtures and 3 cross-pass substitutions,
  including deterministic USTAR/gzip generation, explicit transcript golden values, layered rejection,
  existing portable-policy behavior, gzip multi-member ambiguity, fixture-source independence, and the
  exact candidate pin.
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

- Historical composition note: later v14 was a safe failure, not successful candidate acceptance. Any future
  live action remains separately approval-gated with a fresh exact plan and personal Dashboard decision.
- Terminal Outcome Receipt detail, action/envelope-scoped Dashboard data, DB durability identity, final
  candidate readback/parent fsync and read-only terminal proof are composed by that owner, but have not been
  evidenced by a real action.
- The production-shaped listener, transport, supervisor, post-state, cleanup, and completion authorities have
  network-free composition evidence but have not performed one real combined npm/registry run.
- An existing exact private SQLite schema can be opened without migration and bound into an execution
  envelope, but the product DB has not been opened or used by Graph Genesis. Every live sink/output identity
  and terminal reconciliation remains tied to one fresh exact plan.
- Seatbelt remains a deprecated/private, exact-host development mechanism. It must pass a fresh complete
  local-only probe for each plan; there is no fallback, cross-platform claim, or hostile same-user defense.
- DNS classification and npm-hostname TLS reduce destination substitution but do not prove registry honesty,
  publisher identity, source/build equivalence, or that a locally trusted root was uncompromised.
- A future lifecycle script or npx executable can perform effects outside the working directory without an OS sandbox.
- Post-execution audit failure cannot undo a completed local side effect.
- Automatic rollback cannot reliably reverse lifecycle scripts, child processes, cache changes, or external requests.
- Native clients must invalidate in-flight work on state rotation; server-side instance matching cannot cancel stale client responses by itself.
- The supervisor and broker reject missing, copied, expired, replayed or phase-reused start leases, and the
  listener reports zero-outstanding handler/socket drain. Later v14 evidence is a safe failure only; any new
  real run remains separately approval-gated.
- Candidate receipts and audit chains remain portable unsigned local evidence. A local DB owner can recompute
  history, same-user races remain possible, and public metadata disclosure cannot be rolled back.

## Next Recommended Task

Review and separately approve the authenticated production snapshot/approval/session wiring gate for the
implemented but dormant Plan3/Projection3/Envelope2 foundation. It must not implicitly include the later
compiler/post-state/terminal join, Artifact2/disk consumers, or live acceptance. Those remain separate gates,
and any future live acceptance requires a fresh exact scope and personal Dashboard decision.
