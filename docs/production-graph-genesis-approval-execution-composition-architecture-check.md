# Production Graph Genesis Approval & Execution Composition Architecture Check

Status: accepted on 2026-09-08. The network-free foundation is implemented locally; no real execution occurred.
Baseline: `d988310` (`feat: add local graph genesis preflight`), clean `main` at review start.

## Decision summary

Add one production composition authority around the existing Graph Genesis foundations before any real npm
or registry run. The authority creates a fresh live session, exact execution envelope, approval-only local
Dashboard, existing-schema durable audit session, single abort owner, broker/listener/transport, approved
process supervisor, post-state/compiler/cleanup sequence, and a non-executable candidate artifact.

The first production target remains fixed:

```text
@modelcontextprotocol/server-filesystem@2026.7.10
Node 26.3.1
npm manifest version 11.16.0
registry https://registry.npmjs.org/
macOS arm64, exact observed build and boot session
```

The one-time approval authorizes only anonymous public package-metadata GETs needed to generate an exact
lock graph, an exact shell-free npm `--package-lock-only --ignore-scripts` process, disposable private
workspace/cache/log writes, persistent audit rows, and one new candidate artifact. It does not authorize a
tarball request, package installation, `node_modules`, lifecycle or package code, profile registration,
materialization, startup, an MCP action, or direct npm/npx. Unexpected behavior aborts the session.

Architecture acceptance permits a network-free composition foundation with fake public transport, inert
child processes, local Dashboard requests, and disposable databases. It does not authorize the real action.

## Observable success

The foundation is ready for a separately approved real plan only when:

1. one internal production constructor owns every real collaborator and accepts no injected transport,
   spawn adapter, approval verifier, audit sink, registry, command, target, version, limit, or private root;
2. a fresh execution envelope binds the authenticated plan, safe projection, Dashboard instance, exact
   audit sink identity, candidate output identity, built-in policy identity, approval TTL, runtime manifest,
   and a monotonic start deadline;
3. the Dashboard shows the exact consequence before one `Approve once` decision and records only local
   capability possession, not a verified human identity;
4. denied, expired, cancelled, unavailable, stale, replayed, substituted, or audit-uncommitted approval
   cannot arm the broker, expose the route, resolve DNS, spawn npm, or create the candidate output;
5. the same authenticated authorization/session capability is required by broker, listener, supervisor,
   post-state, compiler, cleanup, output writer, terminal audit, and final completion;
6. listener responses are tracked and drained, all awaited pre-dispatch operations recheck cancellation,
   and one idempotent abort owner disarms traffic and terminates the child group;
7. every external-read attempt is durably recorded before transport, no response is accepted after failure,
   and process success cannot outrun request drain or terminal audit;
8. the candidate artifact contains only bounded public graph evidence, is created exclusively, and is not
   importable without a matching terminal audit record from the same action;
9. cleanup removes only an authenticated allowed inventory and quarantines ambiguity; and
10. all tests remain network-free and the real npm executable is never spawned by automated tests.

## Current gaps that block production composition

| Current behavior | Problem | Required change |
| --- | --- | --- |
| `HardenedGraphGenesisAuthorization` binds only `planHash` and a caller-facing `implementationKind` | It omits sink, Dashboard, output, policy, projection and session identity | Replace production use with an authenticated version-2 execution envelope and session capability |
| only `SyntheticHardenedGraphGenesisApprovalAuthority` exists | No Dashboard outcome becomes production authorization | Add a type-specific authority over the owned local approval service and durable audit session |
| process supervisor takes plan/capsule/audit but no authorization | The production npm spawn API is callable without approval evidence | Require the authenticated session/start lease and consume it through the orchestrator |
| broker consumes authorization independently | Separate low-level successes do not prove one state-machine owner | Require one session capability shared under the composition authority; reject standalone production assembly |
| broker records `authorization_finalized` while arming | It cannot prove Dashboard resolution, revalidation, sink and output binding | Finalize authorization in the approval authority before broker arm; broker records only its own arm transition |
| listener does not track outstanding handler promises | Child exit can race with response relay and broker completion | Add close-and-drain with exact outstanding count and bounded terminal wait |
| approval request kind supports only MCP/install | Graph Genesis would appear as an untyped generic action | Add `graph_genesis` and a closed safe view rendered with dedicated consequence language |
| current Dashboard always exposes policy editing | Graph execution does not need policy mutation | Add an approval/audit-only capability mode and hide/reject policy routes |
| preflight SQLite is disposable and has only three rehearsal events | It cannot serve durable execution evidence | Add a production Graph Genesis audit session over an explicitly selected existing APG DB, without migration |
| cleanup is authenticated only to the initial workspace | Unexpected post-state can be deleted without an accepted final inventory | Bind cleanup to an authenticated success inventory or a narrow known-initial inventory; quarantine everything else |
| final completion does not bind an exported candidate file | The in-memory candidate cannot support later approval-separated stages | Add an importable candidate artifact whose authority also requires terminal audit evidence |
| receipt schema has no Graph Genesis boundary/result | Generic evidence would understate or mislabel the action | Add a backward-compatible receipt minor version with exact Graph Genesis coverage and result fields |

## Explicit command and configuration surface

The later production entry point is:

```text
apg graph genesis filesystem \
  --audit-db <existing-apg-audit.sqlite> \
  --output <new-private-candidate.json> \
  [--dashboard-port <port>] \
  [--dashboard-state <dashboard.json>]
```

It accepts no package specifier, registry, runtime, command, npm option, policy file, limits, approval TTL,
transport, sandbox profile, cache, workspace, credential, proxy, or environment override. `filesystem` maps
to the single compiled profile and exact package/version above. Unknown or repeated options fail before local
probe, audit write, Dashboard start, DNS, or spawn.

The audit database must already exist, be explicitly named, be a regular 0600 current-user file under a real
private directory, and match the exact supported schema. Open it read/write with `fileMustExist`; do not call
the migration path. Record device/inode/schema/application identity and the current chain tail. WAL/SHM
sidecars are expected persistent-database coordination files and are not candidate workspace content.

The output must not exist. Its parent must already be a real current-user 0700 directory. The approval view
may show the exact output and audit paths to the authenticated local operator, because they identify affected
resources. Audit events and portable receipts retain only their digests and safe classifications.

The Dashboard uses the existing bearer-token loopback boundary and optional state-file handoff. It advertises
`approvals` and `audit` capabilities only; policy endpoints return not found and the Policy UI is hidden. The
state file remains an ephemeral capability, is removed on close using existing ownership checks, and is not
part of the approval identity except through the authenticated Dashboard instance ID.

## Built-in decision and safe approval view

Graph Genesis has a compiled, non-overridable `Ask` decision. The first profile reports a deterministic
`70 / high` explanatory score with these reason codes:

```text
public_registry_metadata_disclosure
local_npm_process
persistent_audit_write
candidate_artifact_write
development_only_containment
```

The score is not proof of package safety and does not come from the user's MCP policy. Missing or invalid
evidence is Deny/fail-closed, not a lower score. This adds a separate Graph Genesis policy identity; it does
not change MCP or Install Guard decisions.

Add `kind: graph_genesis` to the pending request type. The closed approval view contains:

- exact target, registry origin, OS build/architecture, Node version and npm manifest version;
- plan hash and execution-envelope hash;
- exact request/name/body/aggregate/concurrency/time/output/lock limits;
- exact local audit and output paths for the local human view only;
- statements that package names are disclosed to npm infrastructure, npm itself runs locally, and private
  temporary cache/lock/log plus persistent audit/candidate files are written;
- statements that tarball, install, lifecycle/package code, materialization and startup are prohibited;
- development-only containment and same-user/Seatbelt limitations;
- approval expiration and `Approve once`; and
- `Direct npm/npx commands bypass APG and receive none of this protection or evidence.`

The request exposes no route token, capsule, launch argv/environment, boot identifier, raw path in audit,
metadata body, stdout/stderr, credential, `.npmrc`, proxy, inherited environment, or Dashboard token.

## Exact execution-envelope identity

Create `GraphGenesisExecutionEnvelopeV1` after the fresh owned local observations and before asking approval:

```text
session ID and plan ID/hash
safe projection digest
runtime-manifest and host evidence digests
boot-session digest
workspace/profile/listener/route-token digests
exact launch/environment/capsule digests
Graph Genesis built-in policy digest
audit sink: schema digest, file identity digest, database instance ID, initial chain tail
candidate output: canonical-path digest, parent identity, expected exclusive-new-file rule
Dashboard instance ID
requested-at wall time, monotonic plan deadline, fixed approval TTL = 120 seconds
all resource limits and consequence identifier
execution-envelope hash
```

The raw output/audit paths remain in a private memory-only session capsule and are represented by digest in
portable evidence. The locally rendered approval may obtain them only from an authority-owned safe local
view. A copied JSON envelope or approval view is not authenticated and cannot reconstruct the capability.

The plan has a maximum 180-second pre-start lifetime. The approval request expires after 120 seconds. After
an approved decision, `startBy` is the earliest of the request expiry, plan deadline, and 15 seconds after
the decision. Broker arm and process spawn must both begin before `startBy`. Once the exact child is spawned,
the already approved 120-second execution deadline applies; approval expiration does not terminate a running
action. All monotonic deadlines remain in-process and wall times are audit evidence only.

Any runtime, build, boot, workspace, profile, listener, route, limit, Dashboard instance, audit identity/tail,
output parent, policy, or execution-manifest drift invalidates the envelope. A fresh plan and approval are
required. Normal expected audit appends advance the chain tail and are validated against the session's own
ordered records rather than misclassified as sink substitution.

## Production approval authority and durable ordering

The composition owns one `LocalApprovalService`; arbitrary coordinators cannot create production authority.
The type-specific authority creates the pending request, immediately writes `approval_requested` through the
Graph Genesis audit session, then yields so the Dashboard can expose it. Since the write is synchronous on
the local event loop before an HTTP decision can be processed, an unaudited request cannot be approved in the
normal production composition.

The Dashboard decision proves control of the current local bearer capability and is recorded as
`principalAssurance = local_dashboard_session`. It does not prove legal name, account ownership, biometrics,
team role, or remote identity. Direct calls to the generic coordinator are excluded from the production
constructor; synthetic/test authorities keep separate brands.

Required pre-dispatch sequence:

```text
session_created
runtime_snapshot_complete
containment_probe_complete
plan_ready
approval_requested
approval_approved | approval_denied | approval_expired | approval_cancelled
[approved only] complete revalidation
authorization_receipt_finalized
authorization_finalized
broker_armed
npm_spawn_intent_recorded
```

Approval resolution must commit before `authorization_finalized`. If audit fails after the human clicks but
before durable authorization, no execution occurs. Denial/expiry/cancellation closes the listener and private
workspace, records `genesis_not_started` where possible, produces a blocked Authorization Receipt, and does
not create an Outcome Receipt because execution never began.

Use the existing schema without a migration. Create one `tool_calls` parent with fixed server/tool identity,
Ask decision, the safe envelope projection, and a fresh action UUID. Create the existing approval row. A
production Graph Genesis audit adapter owns closed event schemas, synchronous immediate transactions, exact
action/envelope binding, global previous-hash lookup inside the transaction, byte/event ceilings, and terminal
status updates. Interleaved APG events are allowed if every transaction reads the committed global tail; event
proofs for this action remain ordered by global sequence.

Opening the DB must verify the existing full chain before creating the session. A chain failure blocks the
request. An audit failure is never repaired with an in-memory success, a different DB, a temporary sink, a
retry under the same approval, or an unchained side log.

## Receipt extension

Use a backward-compatible `apg-action-receipt` minor version `1.2`:

- coverage boundary `graph_genesis_plan`;
- identity assurance `execution_plan_exact` over the execution-envelope hash;
- observed result kind `graph_genesis`;
- bounded fields for external-read status, metadata request/name/byte counts, process terminal/exit/output
  byte counts, lock/candidate digest, candidate artifact digest, cleanup status, quarantine reference digest,
  and terminal audit status; and
- explicit not-observed values for registry/publisher honesty, package safety, source/build equivalence,
  kernel integrity, same-user containment, later artifact bytes, materialization, startup and direct bypass.

Finalize the Authorization Receipt after approval plus revalidation and before broker arm. Finalize an Outcome
Receipt only from observed terminal evidence. `audit_failed`, `outcome_unknown_after_interruption`, and
`incomplete_external_read` are distinct. Receipts remain portable unsigned local evidence under ER1; this
milestone does not add signing, attestation, external anchoring, verified human identity, or schema migration.

## Single-owner execution state machine

```text
CREATING
  -> LOCAL_PROBING
  -> PLAN_READY
  -> APPROVAL_PENDING
  -> AUTHORIZED
  -> BROKER_ARMED
  -> NPM_RUNNING
  -> LISTENER_DRAINING
  -> LOCK_INSPECTING
  -> CANDIDATE_COMPILED
  -> CANDIDATE_OUTPUT_PREPARED
  -> WORKSPACE_CLEANING
  -> TERMINAL_AUDITING
  -> COMPLETE

deny/expire/cancel                 -> NOT_STARTED
failure before first transport    -> FAILED_NO_EXTERNAL_READ
failure after transport starts    -> INCOMPLETE_EXTERNAL_READ
ambiguous child/request state     -> INCOMPLETE_EXECUTION_UNKNOWN
ambiguous workspace cleanup       -> INCOMPLETE_QUARANTINE
post-dispatch audit failure        -> INCOMPLETE_AUDIT_FAILED
```

One internal `ProductionGraphGenesisSessionAuthority` owns transitions. It creates non-exported capabilities
for each phase; low-level production methods require the appropriate capability and cannot accept an
`allowSynthetic` flag. Test-only orchestration remains separately constructed and cannot enter production
methods. No public general process runner or URL fetcher is introduced.

The central AbortController is registered before the first awaited operation. Recheck it after each awaited
audit, revalidation, listener, approval, transport-drain and filesystem operation and immediately before arm,
spawn, inspection, output creation and completion. The first failure atomically latches a stable state,
disarms new requests, aborts transport, closes listener connections, signals the process group TERM/KILL,
waits for child close and request drain within the overall deadline, and refuses later success evidence.

The listener tracks every accepted handler promise and socket. `closeAndDrain` clears the session, refuses new
traffic, destroys idle sockets, waits for all handler settlements, and returns authenticated counts. If npm
exits while a handler remains or a response arrives after terminal latch, the run is incomplete. Broker
completion requires child close, listener drain, zero outstanding requests, matching started/validated
request counts, and no terminal failure.

The supervisor must require the authenticated session start lease as well as plan/capsule. It revalidates
again after durable spawn intent, checks cancellation/start deadline, then performs the single shell-free
spawn. If `npm_spawn_started` audit fails after spawn, it kills and waits for the group and returns no process
success. There is no retry or alternate npm vector.

## Post-state, candidate artifact and cleanup

After child close and exact listener drain, require exit zero, authenticated broker ledger, and strict
post-state inspection. The lock compiler remains memory-only and rejects any graph not representable by the
accepted exact production graph model.

Add `GraphGenesisCandidateArtifactV1`, containing only:

```text
schema/canonicalization identity
action ID, execution-envelope hash, plan hash
exact target/runtime constraints and registry origin
sorted graph nodes and dependency edges
public resolved tarball URLs and SHA-512 integrity values observed in the lock
candidate digest, broker-ledger summary/digest, post-state digest
local unsigned assurance and limitation declarations
artifact digest
```

It contains no packument bodies, route token, private path, workspace identity, Dashboard data, raw output,
credentials, user config, environment, boot identifier, or approval token. Public package names, versions,
URLs and integrity values are intentionally disclosed in this operator-owned artifact.

Before approval, validate the output parent and reserve its path logically; do not create the file. After
candidate compilation, record `candidate_output_intent`, create a random same-parent pending file with `wx`
0600, write/fsync/close/revalidate it, and atomically rename only if the final path is still absent and parent
identity is unchanged. Record `candidate_output_written` with the file/artifact digest. An orphan file after
later audit failure is evidence only: subsequent import must require a matching `genesis_complete` event and
Outcome Receipt for its action/envelope/artifact digest. Without that proof it is rejected and cannot become a
profile, stage, or launch authority.

Successful cleanup requires an authenticated post-state inventory and removes only those exact entries after
child/listener/DB ordering permits. Initial-only cleanup is allowed before spawn if the exact initial tree is
still authenticated. Any unexpected/link/hardlink/special/ownership/mode/identity ambiguity becomes
quarantine; record only a residue-path digest in durable/portable evidence and display the private path only
to the local operator. Broad recursive cleanup is prohibited.

Candidate output is outside the disposable workspace and survives success. Persistent audit survives every
outcome. A successfully written orphan candidate may also survive an audit failure; its required terminal
proof prevents promotion. Automatic rollback cannot undo public metadata disclosure or prove deletion from
registry logs.

## Terminal ordering and failure semantics

Successful post-dispatch ordering is:

```text
npm_spawn_started
metadata_request_started -> public transport -> metadata_response_validated (repeated, bounded)
npm_terminal_observed
listener_drained
broker_ledger_finalized
lock_validation_started
post_state_validated
candidate_compiled
candidate_output_intent
candidate_output_written
cleanup_complete
genesis_complete
outcome_receipt_finalized
```

`genesis_complete` and the Outcome Receipt should be committed atomically in one final DB transaction. The
final completion authority authenticates only after that transaction acknowledges success and every authority
agrees on the same execution-envelope hash. The command exits nonzero for every other state.

If a public transport call began, report `externalReadMayHaveOccurred = true` even if no response validated.
If the DB becomes unavailable after such a read, stop the action and report the audit failure locally; do not
claim durable terminal evidence. This is an irreducible local storage failure mode. It never authenticates a
candidate or triggers a retry. If the final transaction committed but acknowledgement is uncertain, reopen
read-only and verify the exact action once; this is reconciliation, not replay. If exact verification is not
possible, return `outcome_unknown_after_interruption`.

## Approval boundaries

| Boundary | Approval identity | Permitted consequence | Explicitly excluded |
| --- | --- | --- | --- |
| this Architecture Check | current conversation approval | repository analysis and docs | implementation or execution |
| network-free composition foundation | separately accepted architecture | source/tests; fake transport, inert child, local loopback, disposable DB | public DNS/registry, npm, product DB, output artifact |
| one exact metadata graph genesis | live execution-envelope hash plus Dashboard Approve once | anonymous bounded metadata GETs, exact npm lock-only process, private temp writes, named audit DB and candidate file | tarball/install/code/profile/stage/startup |
| exact metadata confirmation | complete candidate digest and listed packages | fresh exact metadata GETs only | resolution change or artifact |
| artifact acceptance | exact URL/integrity set and private artifact root | tarball download and bounded read-only inspection | materialization or code |
| profile registration | reviewed candidate/profile content | repository profile-source change | download or execution |
| materialization | exact accepted graph/artifacts and stage root | private stage writes | startup |
| startup | exact sealed stage/launch | one MCP process | tool call or download |
| MCP action | existing exact action policy/approval | one APG-routed call | direct bypass or restart |

No approval is transitive. The real Graph Genesis approval does not authorize a normal project install, and
an Install Guard approval does not authorize Graph Genesis, MCP staging, startup, or tool calls.

## Network-free foundation implementation scope

After architecture acceptance, implement and verify:

1. closed Graph Genesis policy, safe view, `graph_genesis` approval kind, Dashboard capability mode and UI;
2. execution-envelope/session/start-lease authorities with production/synthetic separation;
3. existing-schema production audit session over disposable test DBs and receipt schema 1.2;
4. supervisor authorization requirement, broker authorization refactor, listener tracking/drain and central
   abort composition;
5. post-state-bound cleanup and candidate artifact writer/import verifier using temporary test directories;
6. a network-free orchestrator using fake metadata transport and repo-owned inert child only; and
7. documentation/state updates.

Do not add dependencies or migrations. Do not connect the public CLI command to real production adapters in
this foundation; parse/format tests may use the intended command surface, but the real entry point remains
unavailable until the exact one-time run is separately approved. Do not open the product audit DB, write a
real candidate artifact, run npm/npx, resolve public DNS, contact a registry, download an artifact, register a
profile, materialize a stage, or start package code.

## Required network-free tests

- execution-envelope mutation and cross-plan/sink/Dashboard/output/runtime/policy substitution;
- approval request durable-before-visible ordering, approve/deny/expire/cancel/unavailable, decision-at-expiry,
  replay, copied view, fake coordinator, instance rotation and audit failure before authorization;
- Dashboard approval-only capabilities, graph-specific rendering, token/origin/host rules and no policy route;
- production constructors rejecting synthetic/injected transport, spawn, verifier, audit and output adapters;
- cancellation before and after every await, including the gap between revalidation, authorization, arm and
  spawn; monotonic and wall-clock disagreement;
- supervisor refusing plan/capsule without the start lease and consuming exactly one spawn intent;
- listener socket/handler tracking, late response, child-exit race, drain timeout and terminal idempotence;
- concurrent broker/audit ordering and global-chain interleaving without a fork;
- audit lock/full/commit/acknowledgement/reopen/chain/schema/parent/tail failures and exact reconciliation;
- output preexistence, parent/file replacement, symlink/hardlink/mode drift, short write, fsync/rename/audit
  failure, orphan rejection and cross-action import;
- initial cleanup before spawn, authenticated post-state cleanup after spawn, unknown residue quarantine and
  no blind deletion;
- Authorization/Outcome Receipt 1.2 canonical golden fixtures, 1.0/1.1 compatibility, privacy canaries and
  incomplete external-read/audit-failure semantics; and
- static/runtime guards proving zero public DNS/socket, real npm/npx, product DB, real candidate output,
  tarball, project mutation, package code, publish, push, or credential/config read.

Default full tests must remain network-free. One later real acceptance must use the exact built composition,
require the user's Dashboard decision, and preserve its audit/candidate artifacts for review.

## Risks and mitigations

| Risk | Mitigation | Residual limit / release blocker |
| --- | --- | --- |
| approval applied to a changed execution | envelope binds all identities; revalidate before authorization, arm and spawn | any unbound behavior or standalone production runner blocks release |
| approval UI implies verified human identity | record local Dashboard capability only | team identity/RBAC remains unsupported |
| policy editing changes approval meaning | fixed built-in Ask and approval-only Dashboard | any Graph path accepting MCP/user policy weakening blocks release |
| audit failure after public disclosure | pre-request durable event, abort, no retry/candidate authority | disclosure cannot be rolled back; absence of terminal durable evidence remains possible |
| process/listener race | tracked handlers/sockets, central abort, close-and-drain, child-close join | unresolved handler or child makes outcome incomplete |
| npm requests a tarball or unknown route | exact broker grammar returns failure; Seatbelt permits only broker port | unexpected request aborts; npm compatibility is not proven until real acceptance |
| candidate artifact mistaken for trusted profile | terminal-audit import proof and explicit candidate/unsigned labels | local DB owner can rewrite the unsigned chain |
| orphan output after terminal audit failure | later import requires matching complete action; show recovery reference | file may remain and need manual deletion |
| cleanup deletes foreign state | initial or post-state inventory authority, identity checks, quarantine | hostile same-user races remain outside guarantee |
| Seatbelt removal/change | exact host/build/provider digest and fresh full probe; no fallback | deprecated/private provider is development-only |
| DNS/TLS/registry compromise | reject mixed/non-public DNS, pin address, npm-hostname TLS | registry/publisher honesty and trusted-root compromise remain unproven |
| output exposes package graph | 0600 file under explicit 0700 parent and approval disclosure | package names/URLs are deliberately present for review |
| receipt sounds cryptographically final | portable-unsigned terminology and limitations | signing/attestation/anchor remain future architecture |

## Architecture acceptance requested

Accept only the network-free foundation implementation scope above. This is an authorization architecture
and receipt-schema change, so implementation starts only after explicit acceptance. The later real action
will still present a fresh exact execution envelope for separate one-time approval.

Suggested acceptance:

```text
Production Graph Genesis Approval & Execution Composition Architecture Check 승인 — network-free composition foundation 구현 진행
```

Acceptance was provided verbatim on 2026-09-08. The resulting foundation adds the exact envelope and built-in
Ask view, durable-before-visible approval, approval/audit-only Dashboard mode, receipt 1.2, authenticated
existing-schema private DB opener with identity/schema/chain-tail revalidation, two-phase start lease,
broker/supervisor enforcement, tracked listener drain, central abort
with fake transport/inert child, post-state inventory cleanup, and exclusive terminal-proof candidate import.
Automated tests use only memory or disposable private local state. The real CLI, Node spawn adapter, public DNS,
HTTPS registry transport, product DB, and operator candidate output are not connected by this implementation.
Focused coverage passes 10 tests and the network-free full suite passes 278 with 3 skipped using one worker.

## Rollback

This review changes documentation/state only. Before acceptance, remove this document and revert its scoped
entries in `ARCHITECTURE.md`, `DECISIONS.md`, and `PROJECT_STATE.md`. No runtime, dependency, database,
approval, Dashboard, registry, candidate, package, external service, credential, commit, or remote changed.

## Next

After acceptance, implement the network-free composition foundation and present its exact diff and test
evidence. Then prepare a fresh live production plan and stop at the separately named real-run approval. The
closed preflight plan from commit `d988310` is never reused.
