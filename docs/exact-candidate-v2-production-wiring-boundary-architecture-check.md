# Exact Candidate V2 Production Wiring Boundary Architecture Check

## Status, baseline, and authority

**FIRST FAILURE-LIFECYCLE UNIT SUPERVISOR-VERIFIED; code/tests FROZEN; full slice NOT ACCEPTED.**
The user-approved nine-file dormant concrete V2 boundary remains unchanged. On 2026-09-13 the authorized
Astra–High correction completed the first failure-lifecycle/audit-ownership unit described below. The concrete
branch does not call synthetic completion, create an Artifact2, or claim a successful metadata run. It returns
only `execution_error` or `outcome_unknown_after_interruption`. All exercised Node listener/child boundaries are
module-mocked; SQLite and workspace resources belong to the tests. Concrete runtime proof values carry no
`module_mocked_concrete`, `local_observed`, or synthetic-success provenance label.

Earlier rejected raw-ledger, exported arbitrary `argv/env`, synthetic-wrapper, and partial concrete scaffolds
are historical checkpoints, not current acceptance evidence. Their failures motivated this unit; preserving
that history does not assert that those old source defects remain present. The larger metadata, protected
post-state/compiler/Artifact2, authenticated cleanup and successful terminal composition is still incomplete.
No live route/network/Dashboard/product DB/real candidate or prior evidence access, schema/dependency change,
commit, or push is authorized by this checkpoint.

The reviewed clean baseline is `main` and local `origin/main` at
`00bd0c9c826947b8c7196f932087837e1ce9b1b7`. The committed state includes `4eb870d` (the dormant Exact Candidate V2
quiesced execution foundation) and `00bd0c9` (bounded integration startup lifecycle tests). Historical dirty-tree,
Partial Verification, and timing-failure descriptions in prior Architecture Checks describe their then-current
state only; they are not production evidence and are retained rather than erased.

The prior issuer/quiesced-run Architecture Check has an older next-decision section. It is historical and
superseded for planning purposes by this wiring-boundary document. It does not grant production wiring authority.

## Current source facts, not proposals

- `src/cli/graph-genesis.ts` exposes `runGraphGenesisReadiness`, dynamically imports
  `graph-genesis-live.ts`, and invokes only `runExactProductionGraphGenesisLive`. No V2 module is imported by that
  CLI handoff.
- `src/stage/graph-genesis-live.ts` constructs the V1 `HardenedMetadataBrokerAuthority` and
  `GraphGenesisProcessSupervisor`. Their APIs authenticate the V1 Plan2/Capsule1/start-lease model; that is not
  V2 Plan3 authority.
- `src/stage/graph-genesis-v2-execution.ts` exports only `SyntheticGraphGenesisV2ExecutionAuthority` and opaque
  synthetic listener/run/transport values. It opens no listener and spawns no child.
- `src/stage/graph-genesis-v2-post-state.ts` exports `SyntheticPostStateV2Authority` with an explicit
  `synthetic_fixture` evidence origin. `src/stage/graph-genesis-v2-completion.ts` is a reserved boundary and exports
  only `export {}`.
- `ProductionGraphGenesisV2SessionAuthority.createSyntheticCompletion` in
  `src/stage/graph-genesis-v2-production.ts` consumes an exact seal through its private `#consumedSealed` set and
  returns an unexported synthetic completion. Its prepared records retain private Plan3/Projection3/Envelope2 and
  private execution material; that is not a production issuer.
- The Artifact2 V2 codec accepts `local_observed` as a data value, but a codec value or digest alone is not an
  authenticating execution capability. The same holds for caller strings, raw paths, a DB handle, a process result,
  an injected `verified` callback, or an `implementationKind: 'production'` label.

## Decision and next code boundary

Do not cast, wrap, or repackage a Plan3 as a V1 plan. Do not promote synthetic execution/post-state observations to
production observations. V1 CLI and source behavior remain unchanged.

The sole future code candidate is one verifiable **dormant V2 execution-to-terminal vertical slice**: a dedicated,
session-owned V2 owner and adapter capable in principle of representing real effects, but not connected to a CLI,
barrel, public selector, or live route. Its evidence is limited to fake transport, mocked listener/Dashboard, inert
or mocked child, and test-owned disposable DB/output resources. The existing synthetic completion remains separately fixture-only. The new concrete failure owner consumes
the same session's exact seal through a private token-gated constructor, retains the launch and original listener,
and owns stop/drain and failure reconciliation. It is not connected to a CLI, barrel, or live route. No raw ledger,
phase method, caller-selected binding, approval identity, start window, deadline, or injected proof callback is
exported. This first unit is not the completed concrete vertical slice.

The implemented allowlist is exactly:

1. `src/stage/graph-genesis-v2-production.ts`
2. `src/stage/graph-genesis-v2-post-state.ts`
3. `src/stage/graph-genesis-v2-execution-production.ts` (new)
4. `test/unit/graph-genesis-v2-production.test.ts`
5. `test/unit/graph-genesis-v2-completion.test.ts`
6. `test/unit/graph-genesis-v2-execution-production.test.ts` (new)
7. `test/unit/graph-genesis-candidate-artifact-v2.test.ts`
8. this document
9. `PROJECT_STATE.md`

Reserved `graph-genesis-v2-completion.ts`, synthetic `graph-genesis-v2-execution.ts`, V1 CLI/live/network/
supervisor/cleanup/hardening, compiler/Artifact2 codec/binding contracts, audit/receipt/approval/DB schema, and
dependencies remain excluded. If this list cannot express a required invariant, stop and request an exact scope
extension rather than widening it implicitly.

## Private root, seal, and listener identity

An unexported session-owned root must retain the original snapshot's 16 roles (11 files and 5 trees), exact
Plan3/Projection3/Envelope2, private launch/environment/route material, runtime/host/containment/workspace
authorities, authenticated audit DB identity, and output descriptor. It must accept no public factory constructed
from a raw digest, DB/path/process/proof, injected callback, or claimed implementation kind. Version-neutral
low-level HTTPS/address validation may be reused only through fixed concrete collaborators, never by accepting V1
authority values.

One exact active seal is consumed synchronously, before an await, by the same private owner. Synthetic-vs-real
attempts, concurrent or reentrant calls, copied/foreign seals, cross-session values, V1 values, and replay all fail
closed. A separate V2 start lease then establishes `broker_arm -> process_spawn`; approval tokens are never exposed,
reconstructed, or regenerated.

The required order is session authority creation, owner acquisition of one original disarmed loopback listener,
profile/workspace/containment/snapshot construction using that listener's port, same-owner attachment of that opaque
listener to the private prepared tuple, then approval. The original listener/server identity and port bind into
containment, snapshot, prepared, route, and capsule identity. A numeric snapshot port or hash is insufficient: it
cannot be used to open a later server and call it equivalent. The prepare-to-approval absolute deadline never
restarts. This corrects the present V2 prepare gap, which verifies a numeric allowed port but does not carry an
opaque original listener. The public Plan3/Envelope2 schema stays unchanged; the original listener joins only
private ownership. The proposed slice models it only with mocks; opening a real listener remains outside approval.

## Required ordering, budgets, and broker limits

The private owner order is:

```text
hidden request -> durable request -> Dashboard publish -> one-time personal approval
-> exact revalidation -> opaque seal -> durable execution-start -> durable broker arm
-> durable spawn intent -> spawn
```

Metadata requests atomically reserve ordinal, active capacity, and a maximum response-byte reservation before an
await. Their durable intent precedes DNS/HTTPS. The limits remain concurrent requests <= 4, 128 names, 256 requests,
4 MiB response, 64 MiB aggregate, 10 seconds per request, `--maxsockets=4`, no queue, and no retry. At every point,
`committedBytes + outstandingReservedMaximumBytes <= 64 MiB`. Each unique response commits its actual bytes and
releases its reservation exactly once. No durable-audit await may use a stale `nextCommitted` value and lose another
completion's aggregate update; commit/release must be serially atomic or provide an equivalent proof. This is a V1
reuse risk to avoid in V2 design, not a V1 change or a claim that a real exploit occurred.

The exact launch remains bound to `<workspace>` with `--prefix`, `--package-lock-only`, `--save-exact`,
`--save-prod`, `--maxsockets=4`, `--ignore-scripts`, and every existing option/environment. The existing 120-second
prepare window, 15-second start window, and sealed absolute 120-second execution budget do not restart or extend.
Each fence rejects abort, revocation, equality at deadline, non-finite, negative, or decreasing monotonic time.
No post-approval launch, port, route, or capsule regeneration is allowed.

## One execution/terminal owner

One private owner alone advances:

```text
reserve -> revalidate -> start -> broker -> spawn -> running -> quiescing -> quiesced
-> post-state -> compile -> output -> cleanup -> terminal -> reconcile
```

The first failure latches stopping, revokes forward capability and output intent, and shares one stopping promise.
Callbacks only latch; they do not await their own handlers. Context/output access closes immediately on revocation,
while descriptor/audit custody needed for stop/reap/drain and terminal observation remains until those observations
finish.

`child attempted`, `child created`, and `child close observed` are distinct. Pre-spawn cancellation or synchronous
spawn failure is never completed-child evidence. The broker's run ledger proves no active, pending, partial, or
unclaimed failure for the same run; listener drain is once-only on the original server, not a later zero-count
re-close. Check the failure latch before and after drain. The five-second total cooperative stop budget, TERM then
KILL at two seconds, and child close at four seconds are a V2 bounded shared-stop proposal recorded in the prior
Architecture Check, not a claim about existing production behavior. After the execution deadline, grace permits only
stop/reap/drain observation; it cannot extend time for post-state, output, cleanup, or successful forward progress.
The existing process-status
schema has no `unknown` member, so a missing child observation retains a factual attempted status such as failed,
cancelled, or timed_out with `exitCode: null`, plus unknown terminal outcome (and, if needed, a private closed
observation predicate). It never fabricates completed, exit zero, or child-close evidence, and does not expand the
schema. Deadline expiry cannot become a late success.

## Post-state, output, cleanup, and terminal proof

Only after authentic quiescence may production-bound post-state capture occur. It retains protected manifest
inode/content, exact workspace-root lockfile, and rejection of legacy prefix, `node_modules`, archive, link, and
special-file state. The initial empty-workspace predicate is never reused after legitimate lock/cache mutation;
subsequent fences are immutable runtime/protected/output/DB fences. Strict compiler and peer semantics remain
unchanged. Authenticated broker committed distinct metadata names must exactly cover candidate distinct names before
output reservation; missing, extra, partial, or cross-run coverage safely fails.

Only same-owner private observations can create Artifact2 `local_observed` binding. Synthetic objects and decoded
codec payloads are not capabilities. Tests may exercise a mocked concrete adapter through the codec branch, but must
report that evidence as synthetic/module-mocked, not an execution success.

The output sequence is durable intent, exclusive `0600` `O_NOFOLLOW` write, bounded canonical readback with
inode/content check, file/parent fsync, and scoped post-state/output revalidation. It stays provisional until terminal
proof and never imports or activates automatically. Cleanup applies only an authenticated quiescent sealed exact
inventory; it has no glob or recursive fallback, preserves on any entry failure, and never rescans a deleted
workspace. Live/production cleanup is unapproved. Only disposable fixture deletion is part of the proposed future
network-free implementation scope.

If `markExecutionStarted` commits then throws, in-memory dispatch can remain false. That uncertainty performs exactly
one readonly reconciliation and becomes unknown; it never uses `finalize` or `markFailed` as a repair fallback.
Likewise, uncertain durable start has no assumed effect and no fallback terminal write guesses dispatch. Post-start
failure stops/reaps/drains first, then the single owner makes one terminal attempt and one reconciliation.
Commit-then-throw never permits a second finalization. A completed terminal requires validated metadata, process
completed with exit zero, candidate digests, cleanup complete, and a complete atomic terminal-audit batch; an
externally complete result additionally requires the separate readonly proof to succeed. Proof reopens the
owner-selected exact DB in bounded readonly/query-only mode for chain/action/receipt/envelope/output relationships.
Insufficient proof remains unknown: no repair, retry, or authority expansion.

## Implemented evidence and remaining completion criteria

Baseline-only historical evidence is typecheck/build exit 0, focused V2 111/111, later preflight+stdio 38/38, and
full single-worker 480 passed/3 skipped across 36 passed/1 skipped files. The separate nested-suite count (102) is
not a file count. Worker reports recorded `105/105` for four V2 files and `483 passed, 3 skipped` for a suite, but
they are not final acceptance evidence: commands actually used were `npm run typecheck`, `npm run build`,
`npx vitest run ...`, and `npm test -- --maxWorkers=1 --testTimeout=30000` (the latter invokes
`npm run build && vitest run`), rather than the specified direct installed commands below. External access was not
separately instrumented; this document does not assert zero attempts/credential nonaccess and does not speculate
that an install or registry access occurred. It does not establish a real effect.

The existing exact nine-file implementation approval permits the prescribed direct installed commands after
supervisor release of the current hold; it does not permit npm/npx package runners. No new implementation approval
is needed for same-scope correction. Its single dormant production-port work unit reaches mocked post-state, output,
cleanup, and terminal proof so its mocked end-to-end success can exercise the full ordering. That success is not
production completion, live-execution evidence, or a license to report a real effect. It must test mocked concrete
port success/failure ordering, synchronous
spawn/observer races, concurrent byte commit, abort halt, seal cross-consumption, output drift, partial cleanup,
audit commit-then-throw with readonly reconciliation, V1 unaffected behavior, and no CLI import linkage. It must
prove zero unauthorized effects and distinguish complete from unknown. Any unexpected architectural file need stops
work for another exact approval; no file expansion or live access is inferred.

### Current first-unit checkpoint — 2026-09-13

Supervisor independent verification matched all three submitted source/test/seam SHA256 values, ran direct
`tsc --noEmit` (exit 0), the first-unit filter (51 passed, 90 filtered, 141 total; exit 0; 4.36 seconds), and
`git diff --check` (exit 0), and confirmed no V2 import in V1 CLI/live. The supervisor accepted the stated
failure-lifecycle unit's technical boundary, not root provenance, the whole slice or live behavior.
Code/tests were frozen at that first-unit checkpoint. The following design pass changed only
this document and PROJECT_STATE.md. The supervisor subsequently completed the fixed-build full network-free
regression: exact direct installed `./node_modules/.bin/vitest run --maxWorkers=1 --testTimeout=30000`, exit 0,
534 passed / 3 skipped (537 total), 37 passed / 1 skipped files (38 total), 65.50 seconds. The three code hashes
were unchanged. Its test-owned loopback/DB fixtures are not live product evidence or whole-slice acceptance.

The sole writer changed production ownership, its unit tests, the type-only execution seam, and the two approved
state documents. The other allowed completion/post-state/Artifact2 source and tests were not changed by this unit.
Six dirty files remain inside the nine-file allowlist; prior dirty work was preserved.

Implemented first-unit behavior:

- Seal consumption and execute claim occur synchronously before any await. Copied/foreign/replayed seals and
  prepared tuples, reflective construction, concurrent execution, and synchronous spawn reentry are rejected.
- The initial DB helper is unchanged. A seal-owned snapshot retains the original exact eight authorization events,
  tool call, approval and source-parent identity. A private bounded journal accepts only the owner's expected
  append sequence. Same-action extra events, other-action appends, prefix tampering and receipt drift fail closed.
- Start, arm intent, arm, and spawn intent precede their respective effects. Start commit-then-throw and
  no-commit failure issue zero effects and no fallback finalize/markFailed writes. Uncertain appends do not retry.
- The sealed last trusted monotonic reading is retained across the phase boundary. Invalid, negative, backward,
  equality-expired readings fail closed. Both arm and spawn remain within the 15-second start window; the absolute
  120-second execution deadline derives from approval and is not renewed on progress or after spawning.
- Original listener identity includes a private instance nonce in the private capsule digest. Root lifetime,
  failed listen, failed attach, denial, real approval expiry and context close have bounded shared disposal.
  At that checkpoint root-before-snapshot order was checked; the stronger lineage was the next-unit gap below.
- A child-process object return is only an attempted dispatch. The Node `spawn` event establishes child creation;
  `close` establishes observed completion. Error-before-spawn, error, overflow, missing close and TERM ignored are
  distinguished. stdout/stderr are consumed and counters bounded; no raw child error text is persisted.
- One shared stop promise sends TERM immediately, escalates to KILL at two seconds if close is absent, observes
  close for four seconds, and bounds the combined stop/listener drain observation to five seconds. Missing close
  or drain remains unknown, not a fabricated exit. Callback failures latch state; they do not throw via `fail()`.
- Initial full snapshot revalidation remains pre-spawn. Post-child validation rechecks immutable runtime trees,
  descriptor-bound protected workspace files, output parent and DB journal without demanding an empty npm
  workspace or running initial host/runtime/containment probes again.
- Output/context cancellation immediately revokes the public capability. A single output-disposal promise retains
  the parent descriptor and namespace through stop/terminal settlement and outstanding read completion, preventing
  double disposal during concurrent output/context close.
- All concrete execution awaits for snapshot/output-parent/target absence have time/abort fences with immediate
  rejection observation. Underlying Node fs work is cooperative: an unreturned read cannot actually be cancelled.
  Execute returns bounded unknown while that read is pending. Context/output close returns failure after its own
  five-second custody wait, retains the descriptor/path reservation, and performs a single deferred release only
  if the underlying read eventually settles. This is not successful cleanup or OS preemption.
- One factual failure terminal is attempted only after a definite start. Independent original-path read-only,
  query-only SQLite reconciliation checks identity, retained durability settings/schema, bounded canonical hash
  chain, exact action/Plan/Envelope/approval and receipt/summary relationships. Post-start `proven` requires the
  terminal triple; a prefix-only journal is never terminal proof. Commit-then-throw reconciles once, without retry.
  Outcome startedAt is bounded by the actual execution-start event; readonly close failure returns unknown.
  The durability comparison reuses the initial accepted integrity evidence; it is not a new OS/SQLite attestation.

Historical first-unit command evidence on that unit's frozen source (not the later root-owned changes):

| Check | Result |
| --- | --- |
| `./node_modules/.bin/tsc -p tsconfig.json --noEmit` | exit 0 |
| `./node_modules/.bin/tsc -p tsconfig.json` | exit 0 after exact-command sandbox escalation for ignored dist writes |
| first-unit filter `-t 'concrete failure owner first unit'` | 51 passed; 90 filtered out of 141; 1 passed file; exit 0 |
| four approved targeted V2 files, after build | 156 passed; 0 skipped; 4 passed files; exit 0; 8.34 seconds |
| complete network-free suite, implementer handoff | NOT RUN by implementer; historical handoff limitation |
| subsequent independent supervisor full suite | 534 passed / 3 skipped; 37 passed / 1 skipped files; exit 0; 65.50 seconds |
| diff/allowlist review | clean whitespace check; six dirty paths, all inside the nine-file allowlist |

The targeted command was exactly:

```text
./node_modules/.bin/vitest run test/unit/graph-genesis-v2-production.test.ts test/unit/graph-genesis-v2-completion.test.ts test/unit/graph-genesis-v2-execution-production.test.ts test/unit/graph-genesis-candidate-artifact-v2.test.ts --maxWorkers=1 --testTimeout=30000
```

Red-to-green evidence includes: legitimate authorization journal rejected before spawn; denial listener leaked;
transient verify-before-finalize failure returning proven without a terminal; unresolved output-parent read not
returning after abort; and clock decrease after sealing accepted while still later than root creation.
Intermediate fixture-name/type/mock/timer-order failures were corrected and rerun. The first default-sandbox
build attempt failed with TS5033 writing ignored dist; the identical escalated direct command exited 0.
The implementer used no package-script runner, npm/npx fallback, full-suite command, actual listener/child or
public network in this unit. The subsequent supervisor direct full regression used test-owned loopback/DB
fixtures. Both evidence sets are bounded test evidence, not live execution acceptance.

Earlier reports of 105/105, 106/106, or 483/3, an uncaptured full-suite count, and the later TS2339 checkpoint
predate this unit and are not acceptance evidence for it. The original four raw-ledger security reproductions
and rejected exported launch authority remain historical reasons for the change.

### Historical first-unit design boundary and next review

The first unit's diff/evidence review is complete. Do not connect metadata, successful output or cleanup
during the code/test freeze; the next construction-lineage design below still requires its own decision.
Root-before-snapshot is not proof that profile/workspace objects were constructed by that exact opaque root:
an older profile/workspace could still be wrapped in a newer snapshot with an equal numeric port. Next
Architecture Check should define a session-owned root-to-profile/workspace/containment construction handoff,
first assessing whether it can be expressed inside the existing production source and unit test allowlist.
If it requires changing `graph-genesis-hardening.ts` or `graph-genesis-containment.ts` authority contracts, those
files are outside current scope and require an explicit exact extension before editing; no extension is assumed.

The concrete metadata ledger/coverage, successful post-state/compiler/Artifact2 path and authenticated cleanup
remain unimplemented. OS-level scheduler stalls, synchronous SQLite calls and uncooperative native I/O are not
preempted by JavaScript timers. Missing close/read/drain or DB outcomes remain unknown. There is no production
issuer/live route activation, no whole-slice acceptance, and no commit/push. Rollback would be a reviewed inverse
of this unit's scoped hunks, preserving all prior dirty work; no reset or blanket checkout was performed.

## Root-owned construction lineage — independently accepted within the network-free unit

The user approved the exact opaque-seed API and fixed child namespace in the following design, and directly
confirmed implementation with `승인할게`. The sole writer is limited to production.ts, its unit test and these
two state documents. The existing execution-production source/test remain frozen. This releases only the
construction-lineage unit; metadata, Artifact2 success, cleanup and live wiring remain unimplemented/unapproved.

Implemented boundaries:

- `captureConcreteRuntimeSeed` accepts only the closed authentic 11-file/5-tree/host/version reference record.
  Host/version ownership is checked before any field read. The returned frozen WeakMap token contains no paths,
  digests, callbacks or write authority. Structural/proxy errors become the existing closed public error.
- `prepareConcrete(root, seed, context, output)` synchronously claims its authentic original root, seed,
  context, output and exact fixed destination before the first construction await/effect. No root order counter
  or equal port/digest is a construction proof. The retained authorities create profile, exclusive workspace,
  containment evidence and snapshot in order through a lexical token-gated owner.
- Parent canonical/dev/inode/uid/mode custody, absence, no-symlink and bidirectional runtime/DB/output separation
  are checked before creation and parent linkage is rechecked after awaited construction phases. Existing
  initializer behavior remains unchanged: one nonrecursive exclusive root, private directories and protected
  canonical manifest/config/profile files. Partial files and destination claims survive failure; no retry,
  adoption, alternate destination, permission widening or production deletion is added.
- The owner's private association retains the exact original snapshot/bundle/listener/context/output tuple.
  It is required before prepared publication and authorization/sealing. Generic/synthetic snapshot preparation
  remains independent and does not acquire this association.
- The original root's monotonic deadline is not restarted. Every construction step has abort/time fences and
  immediate Promise rejection observation. The unchanged initial DB predicate runs before/between construction
  steps, then stops being used by this preparation owner after successful preparation: legitimate authorization
  appends still use the existing exact audit lifecycle/journal, not a stale initial tail.
- Output/context/root revocation stops later phases and prepared publication. Nested snapshot revalidation
  receives the construction owner's signal, so a held file read cannot resume into later file/host/version/probe
  checks after output revocation. Outstanding native promises retain output-parent descriptor custody until
  settlement. Public prepare rejects with the closed invalid error; a five-second close timeout reports failure,
  not clean shutdown. An unsettled operation means construction/cleanup remains incomplete or unknown, not OS
  cancellation or successful rollback. Tests eventually release their gates before fixture-owned cleanup.

Focused red evidence: a closed audit DB originally allowed one workspace initializer call; unauthenticated host
getter access originally leaked its private exception. Both were reproduced before their respective corrections.
The nested late-read regression passed after the construction-signal correction. An intermediate 65-case lineage
run had 64 passed and one harness condition-not-reached failure before a held probe was entered: the new test's
setup condition was still using the older five-second helper default. Only new construction waits now opt into
a 15-second setup ceiling; older tests keep five seconds and production deadlines/timeouts are unchanged.
The old clock tests now establish their synthetic decision clock at the decision callback, after the longer
construction fixture, preserving all original decrease/expiry assertions.

The required matrix now includes genuine different same-port roots with valid owned seeds/context/output,
consumed seeds/context/destinations, namespace/runtime/DB drift, each stage's failure/cancel/expiry, held native
initializer/probe and nested reads, exact success, and pre-authorization revocation. Old-snapshot `as never`
negatives establish rejection of the removed snapshot input, not additional evidence for new capability checks.

The combined focused filter subsequently reported 121 passed, two failed, 90 filtered (213 total; exit 1;
257.04 seconds). Both failures were new assertions expecting an authorization result after revocation where
the existing contract throws the closed invalid error. Correcting only those assertions gave two passed,
211 filtered (exit 0; 4.32 seconds). The following complete targeted run supersedes these intermediate results.

Source/tests are frozen for final verification. Mocks replace Node HTTP/child and
Dashboard boundaries plus host/version/containment executors; real authority objects and disposable SQLite/files
exercise ownership and bytes. These are module-mocked synthetic observations, not native probe or execution proof.

| Final frozen-source check (2026-09-13) | Captured result |
| --- | --- |
| direct `tsc -p tsconfig.json --noEmit` | exit 0 |
| direct `tsc -p tsconfig.json` | exit 0; exact-command escalation for ignored dist writes |
| exact four-file targeted command shown above | 228 passed, zero skipped; four passed files; exit 0; 103.51 seconds |
| direct `vitest run --maxWorkers=1 --testTimeout=30000` | 606 passed / 3 skipped (609 total); 37 passed / 1 skipped files (38 total); exit 0; 159.69 seconds; one post-freeze run |
| supervisor independent direct `tsc -p tsconfig.json --noEmit` | exit 0 |
| supervisor independent production test `-t 'root-owned preparation lineage' --maxWorkers=1 --testTimeout=30000` | 72 passed / 141 filtered (213 total); one passed file; exit 0; 6.37 seconds (tests 5.63 seconds) |
| CLI directory and graph-genesis-live/live-state source search for V2 imports | no matches |

All commands use `./node_modules/.bin/` directly, not npm/npx/scripts. Frozen SHA256:

```text
src/stage/graph-genesis-v2-production.ts
cc4732fd80370e72a9c6d9b22de336861dd07ed53900bc2257c1955de629d739
test/unit/graph-genesis-v2-production.test.ts
54e09b59371a8d0701f71941a2c7b9a737d16ddc58a8143902b3b44d54746132
src/stage/graph-genesis-v2-execution-production.ts (unchanged)
e51162cf3741c3ba1f9b83452eb4de3e419d4b38354ebaffb0cad7f48c614296
test/unit/graph-genesis-v2-execution-production.test.ts (unchanged)
deea2aff24b33439c31ca766523dda939849a00e6745ebd3fc306c1626a5bbe0
```

The complete suite used its existing test-owned local loopback/subprocess/SQLite fixtures. No product Dashboard,
npm operation, live V2 wiring, product DB, real candidate or past evidence/quarantine was used. No dependency/schema,
additional-file, commit/push or rollback action occurred. Six dirty paths remain from the adopted candidate; this
unit edited only the exact four-file subset and preserved both execution-production files byte-for-byte. Final
whitespace/allowlist and source-hash checks accompany the handoff. The supervisor independently matched all four
code/test hashes, reviewed the ownership/custody/seed/prepare/authorize/release diff and found no further mandatory
correction. Its independent typecheck and 72-case lineage run passed. It reused the implementer's unchanged-build
228-case targeted and 606/3 full-suite evidence without repeating the full suite. Final technical verdict:
**Root-Owned Preparation construction lineage is accepted within the network-free unit.** This is not
whole-V2-slice acceptance or native/live completion evidence; metadata/Artifact2/cleanup/live remain incomplete.

The adopted checkpoint consists of these exact six dirty paths on baseline `00bd0c9`:

- `src/stage/graph-genesis-v2-production.ts`
- `test/unit/graph-genesis-v2-production.test.ts`
- `src/stage/graph-genesis-v2-execution-production.ts`
- `test/unit/graph-genesis-v2-execution-production.test.ts`
- `docs/exact-candidate-v2-production-wiring-boundary-architecture-check.md`
- `PROJECT_STATE.md`

Source/tests stay frozen; only the two documents are updated for this verdict. The next recommended action is
an exact user-approved checkpoint commit/push of these six files by the implementation task. This recommendation
is **not** commit/push approval. No new tests/build, next metadata/Artifact2/cleanup/live implementation or model
change is made in this docs-only closeout. Any rollback remains reviewed scoped inverse hunks preserving prior
dirty work, never reset/stash/delete. Reproduction, root-cause isolation, narrow correction and fresh independent
verification guided this unit; synthetic/native and incomplete/complete evidence remain explicitly separated.

### Historical design proposal (superseded by the approval above)

The following proposal records the reviewed decision and limitations; its former approval hold is no longer current.

### One minimal recommendation and observable goal

Replace concrete acceptance of a caller-built snapshot with a session-owned construction operation. Keep generic
`ProductionGraphGenesisV2SnapshotAuthority.prepare(bundle)` unchanged for the existing synthetic path. Concrete
preparation must require a private association created by its own construction sequence; another call to generic
prepare, equal ports/digests, newer creation order, or authentic-but-foreign objects cannot establish that association.

Success is observable when a root can consume only the exact profile/workspace/containment/snapshot tuple it
constructed from authenticated runtime references, with the exact context/output/destination it reserved. Every
failure revokes publication/approval eligibility; none of the negative cases can mint a concrete prepared tuple
or reach spawn. This proposal does not add metadata, Artifact2 output or cleanup success.

### Source-based feasibility inside the current allowlist

| Existing source/API (read only in this design pass) | Finding |
| --- | --- |
| `graph-genesis-containment.ts:41-77`, profile authority `prepare` | Builds and brands a new profile from OS build, sandbox executable hash and port; those values can be derived privately from retained authenticated seed and original listener. No contract change needed. |
| `graph-genesis-hardening.ts:266-309`, finalized workspace `initialize` | Creates root with non-recursive mkdir, private directories and exclusive protected files, then brands a finalized workspace. It accepts an absolute path/profile text and has no abort/rollback API. Reuse unchanged with the limits below. |
| `graph-genesis-hardening.ts:359-409`, owned containment `observe` | Checks exact authenticated runtime/workspace references and derives evidence through its retained executor. Binding fields can be built internally from the new tuple. |
| `graph-genesis-v2-production.ts:1230-1360`, snapshot authority | Already retains the file/tree/version/host/workspace/containment/profile authorities. A private-token-gated construction method can compose them in this same file. |
| `graph-genesis-v2-production.ts:2480-2591`, ownership/relationship checks | Existing exact-key, file/tree role, distinctness and structural checks can validate a runtime-only seed; full evidence checks apply only after the new workspace/profile/containment exist. Refactoring these local helpers must preserve generic behavior. |
| `graph-genesis-containment-runner.ts:25-97`, local executor | Calling observe is potentially effectful: its real executor opens local listeners and launches sandbox/probe work. It is not a harmless data accessor; all such execution stays mocked in the proposed tests. |

No hardening, containment, runner, V1, schema or dependency change is currently needed for **cooperative,
network-free construction-lineage testing**. This is not a finding that current APIs provide atomic
descriptor-relative creation or interruptible native work; they do not.

### Proposed ownership and API boundary

The following names describe a proposed change, not a currently available or authorized API:

1. Add an opaque runtime-seed capture on the existing snapshot authority. Input is an exact closed record of
   authentic 11 file, 5 tree, host and runtime-version references owned by its retained authorities. Validate role
   identity, distinctness, structure, local-observed brands and version relationships. Return a frozen opaque
   token backed by a same-authority WeakMap, not the raw bundle. Do not accept a profile, workspace, containment
   result, snapshot, path set, digest, clock, executor, callback or proof. The seed contains no authority to write.
2. Keep original root acquisition through the session's context-bound original listener. The existing root
   deadline begins at acquisition and is never restarted. Acquire/authenticate the output intent and runtime seed
   before attempting construction; no global/new effect factory is introduced.
3. Replace the concrete prepare boundary's external-snapshot argument with that opaque seed. A single synchronous
   claim consumes the exact root and construction attempt/destination before the first await. Authenticate the
   same context and output; copied/foreign/reused values fail. This is a material API change and needs the design
   decision below. Existing generic/synthetic preparation remains available but cannot enter concrete execution.
4. The session calls a same-module token-gated construction method on its retained snapshot authority. Internal
   inputs are only the authenticated seed, retained original-root identity/port, fixed reserved destination and
   internal abort/deadline state. The method revalidates the seed, then directly invokes
   `profiles.prepare -> workspaces.initialize -> containment.observe -> snapshot.prepare`. No collaborator or
   result is supplied by the caller; no runtime implementation-kind string can authorize the operation.
5. Store the **exact object references** for root, seed, context, output/destination, profile, workspace, containment
   and final snapshot in a private same-root association only after every step passes. Bind the original listener
   nonce into the retained private capsule as now. Generic snapshot preparation does not create this association.
   Returning an authentic generic snapshot or rewrapping an old tuple must therefore be insufficient.
6. Before returning prepared material and again before authorization/sealing, require that same association,
   active context/output/root, and exact tuple. Preserve the existing full pre-spawn validation and first-unit
   failure owner. Public Plan3/Projection3/Envelope2/receipt schemas, launch flags and V1 routing stay unchanged;
   their derived digests legitimately reflect the newly owned workspace.

### Exact destination, permission change and failure custody

Recommend one fixed child directory,
`<authenticated output parent>/.apg-graph-genesis-v2-workspace`, rather than a new caller-selected raw workspace
path or a generic write authority. This **does not follow automatically** from permission to create candidate.json:
the user must explicitly approve this additional pre-approval directory/file creation boundary for implementation
tests. Before any creation, retain the canonical private parent descriptor and its device/inode/uid/mode, derive
the exact child once, prove absence/no symlink traversal and separation from input runtime trees/DB and output
file, and reserve that exact parent-identity/child-name association. No parent creation, overwrite, recursive
mkdir, arbitrary chmod/ACL, alternate destination, queue or retry is permitted.

Use the existing initializer once: exclusive root creation, cache/logs/tmp 0700, canonical exact manifest and
the existing protected config/profile files 0600. Revalidate parent linkage around awaited stages and bind the
resulting workspace descriptor identities/content digests through existing authorities. Existing paths, files,
symlinks, replacements, alternate canonical paths, used destinations or mode/identity drift fail closed.

Cancellation is cooperative. The current initializer and containment observe do not accept a per-call abort and
may finish their already-issued work after cancellation. A bounded owner rejects further phases/publication,
closes the original listener, tracks the outstanding operation and retains its destination reservation/custody.
On late completion it must never publish the tuple, observe the next phase or authorize/spawn. If the operation
does not settle, report unknown/incomplete and retain custody; do not claim that it was cancelled at the OS level.

Partial creations are preserved, not deleted, retried, adopted by another root or promoted to an authenticated
workspace. The tests' final harness may clean up its own disposable root after pending operations settle, as
already authorized; production failure handling gets no deletion authority. Because the unchanged initializer
uses path-based operations, before/after checks detect drift but cannot guarantee zero writes during a hostile
same-user parent swap. No atomic openat-style or immediate abort guarantee is claimed.

### Proposed future edit/test scope and explicit exclusions

After a user design decision and release of the code freeze, the minimal proposed implementation uses only four
of the already listed nine files:

- `src/stage/graph-genesis-v2-production.ts`: opaque seed, private construction association, destination ownership.
- `test/unit/graph-genesis-v2-production.test.ts`: mocked construction/negative fixtures, preserve the verified failure matrix.
- This Architecture Check and `PROJECT_STATE.md`: design and captured evidence.

No new file is proposed. No post-state/codec/compiler/binding/seam change is needed for this construction-only unit.
Tests use disposable private workspace/SQLite/output parents and mocked listener, Dashboard, host/version and
containment executor boundaries. Direct installed typecheck/build and related network-free tests may follow an
implementation approval; none is run by this documentation-only follow-up. The supervisor owns its separately
completed current-checkpoint full regression, so this task must not duplicate it.

Forbidden: actual npm/probe/child/listener/Dashboard/network/DNS/HTTPS execution, product DB or real candidate,
past evidence/quarantine, live imports/routes/activation, metadata/successful Artifact2/cleanup wiring, schema or
dependency changes, existing hardening/containment contracts, extra files, commit/push and rollback of frozen code.

Required negative tests for that later unit:

- Old genuine profile/workspace/containment wrapped in a fresh generic snapshot with identical port/digests;
  generic snapshot after root, copied/foreign seed/root/context/output, same-port listener substitution.
- Wrong role/count/duplicate reference, raw digest/clock/callback/proof extra field or synthetic evidence input;
  drifted seed runtime files/trees/host/version before construction.
- Reentrant/parallel/repeated construction; verify one-use claim precedes the first effect and each owned stage
  runs only once in order, with no caller-selectable collaborator.
- Existing target or symlink, parent canonical/device/inode/mode replacement, overlap with runtime/DB/output,
  and reuse after partial failure; never overwrite/remove/adopt either existing or partial content.
- Failure/cancel/expiry at every stage, including an initializer that settles late or never, and a held containment
  probe; no later stage, approval publication or spawn, bounded failure with honest retained custody.
- Exact success with original profile/workspace/containment/snapshot references, original port and deadline,
  canonical manifest/0600 protected files; all first-unit failure tests and generic synthetic behavior preserved.

### Historical decision required before the approved code work resumed

**Existing approval is sufficient for this read-only inspection and two-document proposal, not for silently
choosing the proposed public API or expanding an output intent into workspace-creation authority.** The broad
nine-file approval covers dormant code and test-owned disposable resources, so no file expansion is currently
requested. Nevertheless the external-snapshot-to-opaque-seed API and exact pre-approval creation namespace are
material authority/architecture choices. Code is frozen and these choices require the user's explicit design
approval (followed by supervisor release), not an inferred permission from technical review.

One recommendation is presented, not multiple implementations: approve the fixed child namespace and
owner-derived construction API with cooperative cancellation/preservation semantics. The unresolved decisions
are acceptance of that API/namespace and the stated same-user path-swap/non-preemptible-I/O limits. If the user
requires atomic no-write-on-swap or immediate per-step cancellation, stop and design a separate exact scope
extension; do not claim the unchanged APIs supply those properties. No actual construction/effect or source/test
edit occurred during this design pass.

## Residual risks and later approval boundaries

Local unsigned tamper-evident records are not signed attestation or hostile same-user protection; same-user swap
races remain. Seatbelt remains a deprecated/private exact-host mechanism requiring a future fresh probe. Metadata
disclosure cannot be rolled back. OS child close, cleanup, and DB outcomes can remain uncertain. Direct `npm`/`npx`
outside APG retains its existing UX warning and is not protected by this slice.

| Action | Responsible role | Required separate authority |
| --- | --- | --- |
| This Architecture Check | supervisor for design/security judgment; implementation writer for the approved edit | current nine-file network-free approval |
| Same-scope code correction or prescribed network-free validation | implementer | existing nine-file approval after supervisor hold release |
| Future scope expansion | implementer | new exact user approval for an exact allowlist |
| Diff/evidence review | supervisor | independent review and defect forwarding; never a user-approval substitute |
| Live route activation | implementer executes only after user grants separate exact activation approval | separate exact user approval |
| Fresh run root/DB/Dashboard action | implementer executes only after user grants exact execution approval | exact user approval |
| Personal Dashboard Approve once | user personally | neither supervisor approval nor review substitutes for it |
| Tarball/download/install/lifecycle/import/activation/deployment | implementer only after user approval | each separately approved user boundary |
| Commit/push | implementer only after user approval | separate exact user commit/push authority |

Before the personal one-time approval, DNS, HTTPS, and npm child work are forbidden. After it, only an exact
metadata-and-lock-only scope could be considered; supervisor review and approval-gate completion never substitute
for the user or for personal Approve once. Tarball, download, install, lifecycle, import, activation, deployment,
and commit/push remain separate. Rollback of the implementation unit is a reviewed inverse of its scoped
hunks, preserving all earlier dirty work; never a blanket reset/checkout. The later design-only update touches
two documents and does not execute that rollback or modify the frozen code.
