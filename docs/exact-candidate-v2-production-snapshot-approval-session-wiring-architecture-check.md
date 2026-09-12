# Exact Candidate v2 Production Snapshot / Approval / Session Wiring Architecture Check

Status: **implementation in progress; no live wiring approved**. Baseline is committed
`a2a85ae949c45d0019ec9c9edb6c2d9c7e119a13` on `main`/`origin/main`. The initial raw-input implementation was
rejected, so its 4/4 targeted and 368/3 suite results are historical failed-design evidence, not acceptance.
The first repair checkpoint removed rejected raw session references and restored typecheck with 2/2 shallow
dormant-bridge tests; it did not establish production snapshot provenance. The bounded snapshot provenance,
fail-closed revalidation, owned session context, output intent, Plan3/Projection3/Envelope2 preparation, and
durable approval lifecycle units are now complete. Fresh evidence is typecheck, build, and 58/58 targeted tests
on macOS: one closed-API test is platform-independent, while 57 concrete macOS tests are explicitly skipped on
non-macOS CI. The targeted tests use disposable real SQLite databases and output directories with a mocked local
Dashboard module boundary; no real server is started. Independent fresh evidence also includes the full
network-free single-worker suite: 422 passed, 3 skipped, across 33 passed and 1 skipped files (exit 0). The
lifecycle foundation is technically verified but remains dormant and unimported by live routes; it adds no
candidate/compiler, broker/process, start-lease, or external behavior. No real npm, network, Dashboard approval,
product DB, candidate, evidence, or quarantine action has run for this work.

## Scope and non-goals

This gate designs a dormant, network-free production adapter which binds existing low-level authority-owned
snapshots and evidence to Plan3/Projection3/Envelope2 and one durable local human-approval session. It does
not implement candidate-v2 compiler/post-state/terminal composition, Artifact2/disk proof/consumer, broker or
child process, start lease, public CLI/live route, registry/DNS/HTTPS/npm, real Dashboard/DB/candidate, or any
dependency, policy-semantics, audit/receipt DB-schema, or lockfile change.

## Production ownership boundary

Hardened Plan2/Capsule1 can never promote into V2 proof, and a caller-provided digest can never become a
“production” Plan3 value. The production snapshot authority receives and authenticates exact authority-owned
file snapshots, tree snapshots, host evidence, runtime-version evidence, finalized workspace, and containment
profile/evidence. The session preparation unit separately owns fixed launch, route, environment, private-path,
broker address/port, limits and one-output identities, and generates `planId` and `sessionId` internally.

There is no `allowSynthetic` switch: synthetic fixture authorities and production authorities are disjoint.
The adapter derives every Plan3/Envelope2 input itself, and uses `GraphGenesisV2BindingAuthority` only after
that derivation. An unowned object or copied caller digest cannot pass this boundary.

## Closed role-labelled runtime manifest

The snapshot authority constructs `runtimeManifestVersion: 2` from a closed exact-key, role-labelled manifest.
Omitted, extra, accessor-backed, duplicated, moved, reordered, aliased, or substituted roles fail closed.
Duplicate canonical file paths, device/inode pairs, and tree roots are rejected while legitimate file-inside-tree
relations remain allowed. The 16 required roles are exactly:

- five core files: node executable, npm CLI, sandbox-exec, broker runtime, and containment-probe runtime;
- five trees: npm, compiled `dist/src`, better-sqlite3 `lib`, migrations, and web assets;
- six auxiliary files captured by the existing file authority under an explicit semantic mapping:
  better-sqlite3 package/native, repository `package.json`/`package-lock.json`, `/usr/bin/sw_vers`, and
  `/usr/sbin/sysctl`.

The adapter verifies the fixed npm CLI path inside the npm tree, the compiled broker/probe files inside the exact
`dist/src` tree, the repository and better-sqlite3 sibling layouts, and the two exact system-tool paths. It does
not capture a whole system directory or repository tree.

The owned snapshot binds host/runtime/boot identity, workspace binding, owned Seatbelt profile, and containment
evidence. Its public projection contains only versioned semantic labels and identity digests, never raw paths,
profile text, or a route token. The separate session preparation unit derives broker, route, launch, limits,
output and session identities from the original private bundle; none are accepted as caller-provided digests.

Revalidation uses a fresh private wrapper of original authenticated references rather than the caller's mutable
wrapper. It revalidates all 11 files, five trees and the finalized workspace, then re-observes host, runtime
version and containment evidence through their original authorities and requires exact evidence-digest and
relationship equality. Abort and finite nonnegative nondecreasing monotonic time are checked immediately before
and after every awaited call; deadline equality fails. Drift or interruption stops all later probes.

## Split preparation and privacy

Phase A captures and owns the production snapshot set plus its exact original authority references. Phase B
authenticates a caller-owned existing Graph Genesis audit database, creates an internal `LocalApprovalService`,
`SqliteAuditRecorder` and `AuditQueryService`, and starts one local `graph_run` Dashboard through the mocked
module boundary in tests. The returned handle, UUID instance ID, loopback URL/token and port are authenticated
and pair-bound; copied, foreign, reused, closed, duplicate-instance and duplicate-port inputs fail closed.
The authority closes only its Dashboard and approval service, leaving the caller-owned database untouched.

Output identity comes from an authority-owned `exclusive_new_private_file` intent. The authority canonicalizes
a private caller-owned parent, opens it with directory/no-follow flags, binds descriptor device/inode/owner/mode,
requires `candidate.json` to be absent, and revalidates the descriptor, path and absence before preparation.
It never creates or deletes the target or parent and closes only its own descriptor. Replacement, symlink,
cross-context, copied, closed, pre-existing and post-capture-created targets fail closed without deleting bytes.

Only after those bindings exist does Phase B create Plan3/Projection3/Envelope2 with internal random `planId`,
`sessionId` and route token, the exact fixed launch and limits, the original snapshot bundle, exact audit/source,
Dashboard and output identities, and owner Date/performance clocks. Public plan/envelope expose hashes and closed
evidence only; raw route token, Seatbelt profile text and private paths remain in the private execution binding.
The human approval view alone may show audit/output paths; receipt identity remains digest-based. This gate never
creates a candidate file. The later Artifact2 unit must revalidate and perform its own separately bounded write.

Phase C consumes one exact active prepared/context/output tuple once. It revalidates the original audit source
before the first write, records one Ask/high V2 call and `graph_genesis_v2_session_created`, and at the last
pre-request fence derives a positive safe integer TTL bounded by both 120 seconds and the remaining monotonic
plan window. It creates a hidden request with that TTL, durably records `approval_requested`, binds the recorder
action UUID to the Dashboard, then publishes. A request can therefore never advertise validity beyond its plan;
deadline equality remains expired/fail-closed.
The terminal denial, expiry and cancellation paths durably resolve and block the request without capability. For
approval, owner Date/performance and cancellation fences surround fresh snapshot/output revalidation. A narrowly
owned post-write audit check verifies path/file/schema/durability and accepts only this action's expected
hash-chain advance; it does not weaken the old initial-tail helper. It persists approved-revalidation evidence,
the existing authorization receipt, and V2 authorization-finalization evidence before minting an opaque
memory-only seal. Copied, foreign, closed, replayed, drifted, audit-failed or deadline-equal inputs fail closed.

## Exact V2 approval identity

V1 approval view compatibility remains intact. V2 is a discriminated extension with
`approvalIdentityVersion: 2`, `candidateSchemaVersion: 2`, `peerSemanticsVersion: 1`,
`compilationContractVersion: 1`, semantic/compilation/projection/runtime-manifest digests, and one candidate
maximum. It shows exact target/version, public registry, metadata-only and lock-only local effect, all V2
versions, exclusions, development-only containment, and the direct npm/npx bypass warning. Long digests can
remain in JSON detail, but exact envelope/plan identity must be visible.

`LocalApprovalService` action arguments remain exactly `{ executionEnvelopeHash, planHash }`; Envelope2
transitively binds the tuple. A V1 approval or an approval from another envelope/session cannot authorize V2.

## Durable fail-closed session order

The adapter implements this exact order:

1. Authenticate exact Envelope2/private capsule and existing Graph Genesis audit DB; verify path, file, schema,
   durability, and initial-tail identity before any write.
2. Atomically begin one Ask/high audit call with V2 receipt context; persist `graph_genesis_v2_session_created`;
   create the hidden approval request; persist `approval_requested`; only then publish that exact request.
3. Await one terminal outcome and persist it. For any non-approval, persist a blocked terminal result and return
   without capability.
4. On approval, check expiry/cancellation/deadline and revalidate every owned file/tree/workspace/host/runtime/
   containment relation through its original authority, checking cancellation/deadline between async groups.
5. Revalidate the same audit DB file/schema/durability identity after its tail legitimately advanced. Persist
   approved revalidation evidence, V2 authorization receipt, and `authorization_finalized`.
6. Only after every required durable write succeeds, create opaque authority-owned sealed authorization evidence.

Audit failure before sealing fails closed. If authorization rows exist but a later write fails, no sealed object
is issued: it is incomplete authorization with no execution effect. Dashboard approval is necessary, never
sufficient. Once hidden request creation begins, the envelope is one-shot: denial, expiry, cancellation, drift,
or failure cannot retry it.

## No transferable token or start lease

The result is memory-only sealed authorization evidence, authenticated only by the same V2 session authority
and bound to action ID, approval ID, Envelope2/Plan3/Projection3 tuple, and start/execution deadlines. It is
not serialized, exported, reusable, accepted by V1 consumers, or consumable by broker/process. A later,
separately approved start-lease gate must consume it once and enforce `broker_arm` before `process_spawn`.
“One-use” here means this session can issue sealed evidence at most once and no current consumer can use it;
actual one-time start consumption remains exclusively the later start-lease gate.
Failure output is closed/redacted: no route token, raw metadata/package value, credential path/content, or
private capsule can escape.

## Receipt, policy, and audit compatibility

Reuse the existing receipt format and DB schema. The prepared V2 receipt context records adapter version/boundary plus
Envelope2, Plan3, Projection3, semantic, compilation, runtime, policy, audit, and output identity digests;
there is no migration. Policy remains exact Ask/70/high with current reasons. The adapter fails closed unless
its V2 policy identity equals approved current policy semantics, preventing duplicated-constant drift.
The dormant module now contains this recorder integration, exercised only against disposable SQLite in the
targeted tests. It has no live import and no production DB or Dashboard execution evidence.

## Implementation sequence and tests

The existing approval keeps implementation dormant and network-free, limited to:

- new `src/stage/graph-genesis-v2-production.ts`;
- `src/approval/types.ts` and `web/app.js` only for a versioned approval projection;
- minimal shared DB/receipt helpers only when needed and without schema change;
- new `test/unit/graph-genesis-v2-production.test.ts`, focused Dashboard projection tests, this document, and
  `PROJECT_STATE.md`.

Do not wire `graph-genesis-live.ts`, CLI, compiler, Artifact2, broker/process, or start lease. Current tests reject
foreign authority objects; caller digest substitution; missing/extra/accessor/duplicate/moved/aliased roles;
Plan2/V1 downgrade; copied/foreign/cross-context audit, Dashboard, output and prepared objects; audit drift;
Dashboard-handle/instance/port reuse; output target creation and parent replacement; and closed-resource reuse.
They also prove every snapshot category revalidates, mutable caller wrappers cannot redirect revalidation,
evidence-family drift stops later probes, abort/deadline fences hold at every async group, preparation writes no
audit/approval/candidate state, and cleanup preserves caller-owned DB/output bytes. Lifecycle tests prove durable
request recording precedes Dashboard publication; delayed request expiry is bounded to remaining plan time;
Dashboard bind/publish failure and context closure leave no reusable visible request and produce a conservative
durable terminal state; terminal deny/cancel/expiry consume the tuple; approved snapshot/output/audit drift and
audit-write failure cannot seal; V1 cannot authenticate a V2 seal; and closing its own context revokes seal
authentication. Successful OS/version/
containment observations remain clearly labelled isolated mocks over real file/tree/workspace captures; separate
real authority ownership checks reject synthetic and foreign evidence. Fakes are never live acceptance.

The full network-free single-worker suite is independently verified at 422 passed and 3 skipped across 33 passed
and 1 skipped files. A current-tree allowlist review and `git diff --check` remain release hygiene; compiler/
post-state/terminal composition, Artifact2 consumers and start-lease acceptance are separate future gates.

## Risks, mitigations, and unverified work

| Risk | Required mitigation |
| --- | --- |
| Duplicated policy drift | Exact policy-digest equality assertion; fail closed. |
| Incomplete runtime coverage | Closed role-labelled manifest and omission/duplicate/substitution tests. |
| Mutable path or TOCTOU | Descriptor/authority revalidation immediately after approval and before future effect. |
| Approval replay/cross-binding | One-shot envelope plus exact hash/action/audit/session ownership. |
| Post-write audit failure | Mint sealed evidence last; never mint after incomplete authorization. |
| Same-user hostile process/development containment | Explicit UI warning and fresh disposable workspace; no hostile-user claim. |
| V2 UI ambiguity | Versioned exact display and JSON details. |
| Execution scope creep | No current consumer accepts sealed evidence; retain separate start-lease gate. |

Unverified: real production observation execution, real Dashboard serving/decision flow, product-DB durable audit
behavior, compiler/post-state/terminal join, Artifact2/disk consumers, broker/process start lease, full-suite
compatibility, and live acceptance.
Rollback is removal of the new dormant module, its targeted unit test, V2 approval projection, and this
change set's documentation/state wording; there is no runtime state, migration, approval, or external effect
to revoke.
