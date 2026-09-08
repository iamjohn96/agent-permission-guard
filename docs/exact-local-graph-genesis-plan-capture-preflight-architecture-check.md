# Exact Local Graph Genesis Plan Capture & Preflight Architecture Check

Status: accepted and implemented on 2026-09-08; network-free verification and actual local capture passed.
Baseline: `3860338` (`feat: harden metadata graph genesis adapters`), clean `main` at review start.

## Implementation and acceptance evidence

The internal `dist/src/stage/graph-genesis-preflight-main.js` entry point now composes owned runtime, host,
version, workspace, disarmed listener, containment and plan authorities. It imports no execution supervisor,
constructs no public transport, and creates no authorization. Caller options are limited to a captured
AbortSignal; source loaders, Node flags/options and unknown input properties are rejected.

The dedicated disposable SQLite adapter writes three fixed namespaced events, uses immediate transactions
with explicit FULL synchronous mode and a 1-second busy timeout, and checks exact in-memory expected records,
chain, schema, parent identity, zero approval rows, file and parent-directory identity after reopening. A
preflight parent has an explicit unevaluated-risk reason; no product DB or receipt integration was added.
Cleanup checks root ownership, bounded inventory, modes, link counts and per-entry/ancestor identities and
uses individual unlink/rmdir operations. It remains path-based and makes no hostile same-user guarantee.

Final capture: `2026-09-08T10:52:03.863Z` to `2026-09-08T10:52:04.716Z` (exit 0).

```text
status: local_preflight_passed
runtime/version/containment/audit/revalidation: passed
audit: 3 events, committed and reopened, chain verified
cleanup: passed
sessionClosed: true
executionAuthorized: false
planReusable: false
publicDns/registry/npmCli/packageExecution: not_attempted
productionExecution: blocked
runtimeManifestDigest: 50b5762c821c33b2c19ee07754e52e335bc72d73909410624e05271ae82ffb0e
expired rehearsal planHash: c9360de0db2dd49bce8a05403e69dba26c8c1b98fd6d718433193e9babb25827
```

These hashes record a closed rehearsal, not a future execution approval. An earlier successful capture was
superseded after schema/parent-directory checks were strengthened. Neither run made public requests.

Validation: build and final typecheck passed; full regression 263 passed / 3 skipped; a subsequently added
compiled cancellation suite passed 5/5 against the same unchanged runtime build. New audit/preparation
coverage is 21 tests plus those 5 cancellation tests. SQLite insertion failure is injected; power loss and
physical disk exhaustion are not claimed as tested. Cleanup completed for the actual capture's private DB,
sidecars and workspace; no raw path or token was retained in this document.

## Decision

Implement one bounded, network-free preparation workflow that composes the existing owned runtime,
workspace, containment, plan, and cleanup authorities; exercise a Graph Genesis SQLite adapter in an
APG-owned disposable database; then perform one local capture rehearsal. Return a safe report and close
the session. A successful rehearsal is `local_preflight_passed`, never `execution_authorized`,
`genesis_complete`, a production graph profile, or a reusable execution capability.

The target remains `@modelcontextprotocol/server-filesystem@2026.7.10`, with Node `26.3.1`, npm tree version
`11.16.0`, and the existing exact macOS development containment provider. No fallback version or broadened
permission is selected after a failure. Apple Feedback and the macOS release investigation are independent.

## Evidence and gaps in the current code

| Source | Observed behavior | Required preparation rule |
| --- | --- | --- |
| `src/stage/graph-genesis-hardening.ts` | Version probe executes snapshotted Node and reads npm `package.json`; it does not run npm CLI | Label evidence `npm_manifest_version`; do not claim npm command behavior was tested |
| same file | Plans/capsules are authenticated with in-process WeakSets; `revalidatePair` checks files, trees and initial workspace | Reports are evidence only; reconstructing JSON cannot resume a plan; reobserve host/boot and enforce session expiry separately |
| same file | Only `SyntheticHardenedGraphGenesisApprovalAuthority` is implemented | Local preparation creates no execution authorization; production approval remains a real-run blocker |
| `src/stage/graph-genesis-network.ts` | Listener can bind disarmed without a broker session | Capture must never prepare an authorized session, arm the listener, or construct an active public transport |
| `src/stage/graph-genesis-supervisor.ts` | Supervisor validates plan/capsule and spawn adapter, but takes no approval object | Composition must gate all access to the production runner; standalone supervisor is not an approval boundary |
| `src/audit/recorder.ts` | Chained append is private and tied to tool-call recording | Do not fake an MCP or Install Guard receipt to obtain an audit sink |
| `migrations/001_initial.sql` | Every audit event requires a `tool_calls` parent; event type/status are text | Dedicated Graph Genesis parent plus namespaced events can reuse this schema in a new disposable DB |
| `src/db/database.ts` | `openAuditDatabase` creates directories, runs existing migrations and `optimize` | Never call it on the user's product DB during preparation; initialize only a freshly owned fixture DB |
| cleanup authority | Uses path-based inventory followed by unlink/rmdir, not retained descriptor-relative traversal | Preserve the same-user race limitation; revalidate exact entries before deletion and quarantine ambiguity |

Implementation-kind strings and caller-supplied verifier/sink objects alone are not production authority.
The preparation entry point must own its concrete collaborators and expose no `allowSynthetic`, arbitrary
command, external URL, audit path, verifier, sink, or transport override. Separate test composition is allowed.

## Composition and lifecycle

Create an internal development preparation entry point, not a new public `apg install` option. It owns:

1. A bounded runtime manifest built from the actual preparation entry point and its transitive execution
   dependencies, including Graph Genesis helpers, probe, SQLite JS/native adapter, and schema files.
   Snapshot an explicit reviewed set/tree; do not hash only a nominal broker file or the entire home/repository.
2. Exact file/tree authorities, version and host observers, and a fresh disarmed loopback listener.
3. One exclusive private session parent under canonical `/private/tmp`, with separately owned `workspace`
   and `audit` children. Resolve concrete paths at creation; accept no pre-existing root. Use 0700 directories
   and 0600 files. The npm read/write profile names only `workspace`, never the audit sibling or parent.
4. A finalized workspace/profile tied to the listener's OS-selected port, fresh route token, and exact runtimes.
   Build the launch vector with `buildGraphGenesisLaunch`; inspect its safe representation without executing it.
5. The owned version/host observations and complete local containment probe, followed by runtime, host/boot,
   profile, listener, and initial-workspace revalidation. Bind the report to the same owned evidence objects.
6. A private audit probe, closed report projection, and termination/cleanup owner that runs on every outcome.

Proposed state progression:

```text
CREATED -> SNAPSHOTTED -> LOCAL_PROBED -> PLAN_CAPTURED -> AUDIT_CHECKED
        -> CLOSING -> LOCAL_PREFLIGHT_PASSED_SESSION_CLOSED
failure -> CLOSING -> LOCAL_PREFLIGHT_FAILED | LOCAL_PREFLIGHT_QUARANTINED
```

Use a monotonic 60-second preparation deadline, including audit waits, and the existing bounded subprobe
timeouts. No background session survives report completion. Close all sockets/processes before inventory
cleanup. On timeout, exception, cancellation or process interruption, invalidate the plan first; cleanup
failure changes the result to quarantined and must not be swallowed by a `finally` block.

Do not hold a listener/workspace alive across a chat approval. This rehearsal ends with an explicitly expired
plan. A later execution workflow must generate a fresh plan and obtain approval while that exact session is
alive. Its production approval delivery is not supplied by this preparation entry point.

## Allowed local observations

The preparation may execute only the snapshotted Node binary with `--version`, the fixed repository-owned
manifest-version reader, `/usr/bin/sw_vers -buildVersion`, `/usr/sbin/sysctl -n kern.bootsessionuuid`, and the
existing repository-owned containment probe under the snapshotted `/usr/bin/sandbox-exec`.

The probe opens temporary listeners on IPv4 loopback, IPv6 loopback, and one address assigned to this Mac.
The non-loopback local-interface listener can be reachable from the local network while open; it returns
no data and must close promptly. The probe connects only to this Mac, resolves no public DNS, and sends no
request to a LAN peer. Missing interface/IPv6 capability or an unavailable negative test fails closed.

Read only explicit runtime files, manifests and the owned workspace. Generated empty `user.npmrc` and
`global.npmrc` are APG fixture files; never locate or read user/project config, credential or signing files.
Use an empty-built environment. Do not execute npm CLI, `npm --version`, npm install, npx, or package code.
Do not import modules with startup behavior that constructs a public client or opens the product DB.

## Plan capture and report contract

Retain the existing immutable safe projection and memory-only capsule split. The report is a separate,
closed schema with: report version, baseline/runtime manifest digest, plan ID/hash, safe projection,
capture/close timestamps, observed check results, audit verification result, cleanup result, stable failure
codes, and `sessionClosed: true`, `executionAuthorized: false`, `planReusable: false`.

Use `not_attempted`, `passed`, `failed`, and `blocked` distinctly. In particular, `publicDns`, `registry`,
`npmCli`, and `packageExecution` are `not_attempted`, not successful tests. Production approval/real-run
composition is `blocked`. No exported Graph Genesis completion authority or candidate is created.

Never serialize the capsule, launch argv/environment, route token, raw local paths, host boot identifier,
stdout/stderr, raw DB errors, or package metadata. The internal launch vector is the existing fixed lock-only
command with scripts disabled and no arbitrary options; the safe display describes its consequences and
hash. Report hashes are local evidence, not human authentication, encryption or executable capabilities.

Capture limits validated by `assertGraphGenesisLimits` and `validateMetadataBrokerLimits`. The proposed
rehearsal projection uses 128 unique names, 256 requests, concurrency 4, 4 MiB per response, 64 MiB aggregate,
10 seconds per request, a 120-second prospective execution deadline, 256 KiB each stdout/stderr, 64 KiB
manifest and 4 MiB lock. These are displayed prospective ceilings, not permission to make requests; the
preparation itself retains its separate 60-second deadline and zero public requests. They do not establish
that the real graph fits. Any later change in a limit, runtime, workspace, port, profile, transport or audit
sink changes the real execution plan.

Default report delivery is a safe returned object/console projection. A local report file, if requested,
must use exclusive creation and be outside the cleanup inventory; it remains evidence-only after cleanup.
An ambiguous residue path may be shown privately to the operator for recovery, but never enters portable
report, audit payload, source control or a model-facing generic exception.

## Disposable SQLite adapter design

Use the existing installed `better-sqlite3` and current schema, without adding dependencies or a migration.
Initialize existing migrations only inside a new `audit` child. A future adapter must refuse arbitrary DB
paths and default product-state discovery. The child process cannot read or write this sibling.

Create a dedicated parent row with fixed `server_id = apg.graph-genesis`,
`tool_name = metadata_graph_genesis_preflight`, empty arguments, `request_hash` equal to the plan hash,
Ask decisions, and an explicit `preflight_only` status/reason. Any required numeric risk placeholder is
documented as unevaluated; it must never be displayed as a risk assessment or an Allow decision.
No approval row, authorization receipt, outcome receipt, or fictional human approval is written.

Use closed `graph_genesis.preflight.*` events for capture/audit/cleanup reporting. The existing execution
event union must not be filled with fabricated `authorization_finalized` or `genesis_complete` events merely
to test persistence. Exercise execution-event payload/order handling separately with synthetic fixtures.
The adapter validates event names, exact payload keys/types/lengths, fixed session/plan binding, event count,
and total byte budget before serialization. For this preparation: at most 64 events, 4 KiB per canonical
event envelope, 256 KiB total event bytes, and a 1-second SQLite busy timeout. This is separate from any
later execution-ledger budget. Redaction is not the schema.

Each append uses one immediate transaction for previous-hash lookup plus insertion, the current canonical
event-envelope/hash format, and a single owned writer with serialized callers. Set and verify `synchronous`
explicitly (`FULL` for the acceptance probe); bound busy waits and reject stale/unknown schema or chain state.
Commit acknowledgement precedes any dependent success. Verify by closing, reopening without migrations,
checking exact ordered events/plan binding and the full chain, then closing again. WAL/SHM sidecars belong to
the private audit inventory; delete only after all connections close. This evidences committed/reopened local
state, not power-loss immunity or an independently authenticated history.

Keep this adapter internal and specific. Do not refactor the product recorder or connect Dashboard/export in
this checkpoint. A separate namespaced sink implementation may support existing execution event schemas for
network-free tests, but cannot authorize a real broker/process. If schema reuse would require fabricated
receipt semantics or broader product changes, fail the checkpoint and return that concrete conflict.

## Real-run preflight requirements retained as blockers

Before any later public read or npm launch, the production execution composition must own and validate all
collaborators, including a genuine one-time approval provider and exact durable sink identity. Bind a session
envelope to the existing plan hash, safe projection digest, sink identity/schema, policy/approval version,
expiry and implementation manifest. An old hash, `production` string or arbitrary verifier must not suffice.

Immediately before arm and spawn, recheck expiry with a monotonic bound, cancellation, host/boot,
runtime/workspace/profile/listener identity and durable approval. Couple broker, supervisor and audit failure
to one abort owner. Recheck cancellation after awaited audit/revalidation operations and before dispatch;
close the window in which cancellation arrives before an abort listener is registered. A failure consumes
the session; retry requires fresh evidence and approval.

Current `revalidatePair`, `prepareSession` expiry checks, and the supervisor alone do not supply this full
composition. The successful 242-test baseline is foundation evidence, not proof of these later properties.

## Verification required after architecture acceptance

| Scenario | Required observation |
| --- | --- |
| Complete rehearsal | Exact owned local evidence; public transport, npm CLI and product DB calls remain zero; report session closed |
| Forged/synthetic collaborators or imported report | Rejected by production preparation entry point; no capability reconstructed |
| Snapshot/build/boot/workspace/profile/port drift | No passed report; session invalidated and safely cleaned or quarantined |
| Cancel/deadline at each await | No subsequent phase starts; sockets and children terminate; no surviving capsule |
| Audit malformed/foreign/oversize payload | No row committed; safe error; no private values in errors or exported evidence |
| SQLite lock/full/write/commit/reopen/chain failure | No passed audit/preflight; no fake terminal success; no blind retry |
| Concurrent audit appends | Serialized hash chain without forks, duplicate terminal events or cross-plan records |
| Symlink/hardlink/root/entry replacement | Reject adoption and quarantine ambiguity; do not traverse/delete foreign state |
| Report privacy | Seed path/token/output canaries absent from serialized report, logs and audit |
| Default regression | Build/typecheck and network-free tests; reuse unchanged test evidence where valid |

Network-free tests may use disposable SQLite files with the existing schema and repo-owned inert fixtures.
One actual local capture after implementation acceptance must exercise the exact reviewed composition.
Do not replace a failed real local observation with a synthetic result. The current architecture-only change
requires document/diff consistency checks, not rerunning the unchanged full code suite.

## Risks, mitigations and residual limits

- Seatbelt remains an exact-host development provider. Require fresh negative probes, no fallback, and
  explicit unsupported status when unavailable; this does not resolve Apple's separate release issue.
- Same-user inspection and path races remain outside the guarantee. Use exclusive private roots, no inherited
  config, minimal lifetime, per-entry revalidation and quarantine; do not call path-based cleanup race-free.
- Startup/native dependencies can exceed a nominal broker-file snapshot. Bind the actual execution manifest,
  record unobserved system libraries, and fail on unexplained runtime selection.
- Audit and workspace have different lifetimes. Keep separate children so cleanup does not destroy the live
  sink before its final event; report verification before closing/removing the disposable DB. A retained
  real-run audit would need its own approved retention rule.
- Local capture cannot establish npm request/file compatibility, graph completeness, registry honesty,
  package safety, third-party attestation or actual installation rollback. Show these as untested/unsupported.

## Scope, approval and rollback

The user accepted the implementation and local capture scope below on 2026-09-08. That scope is now complete;
commit/push and production execution remain separate actions. The following is the accepted scope record.

Proposed next action: implement the internal preparation/report workflow and disposable SQLite adapter,
verify with network-free tests, and run one exact local capture rehearsal. Affected resources are repository
source/tests/docs and newly created owned temporary roots, loopback/local-interface sockets and local probe
processes. Risk is local process/filesystem execution; worst case is partial private residue or probe failure.
Rollback is reverting scoped code/docs and cleaning only verified owned temporary entries, preserving ambiguous
residue for review. Public DNS/registry, real npm/npx, product DB mutation, dependency change, remote push,
publish, artifact download, profile registration, materialization and package startup remain outside this action.

Suggested acceptance:

```text
Exact Local Graph Genesis Plan Capture & Preflight Architecture Check 승인 — network-free preparation 및 임시 SQLite adapter 구현·로컬 capture 검증 진행
```
