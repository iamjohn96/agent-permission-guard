# Exact Candidate V2 Compiler, Post-State, and Artifact Composition Architecture Check

## Status and authority

Baseline: `254890b89b0a2f736179f7f8180963dcefc765f7`. These nine dirty files are an
approved implementation candidate, not a commit or production acceptance. This correction is network-free:
mocked Dashboard, synthetic locks and test-owned disposable SQLite/workspace/Artifact2 only.
Historical 58/58, 66/66 and 422/430 suite counts are not evidence for this corrected source.

No production issuer, broker/process/start lease, live route, actual Dashboard, npm, DNS/HTTPS, product DB,
real candidate, old evidence/quarantine, import/activation, dependency/schema change, commit or push is authorized.
The existing audit/receipt/DB schemas, strict JSON parser and AuditCall terminal API are reused without modification.
Synthetic incomplete outcomes are not successful Graph Genesis runs.

## Observable success

- Only the exact session that owns prepared/sealed/Plan3/Projection3/Envelope2, approval, AuditCall, workspace,
  output descriptor and the shared candidate authority can create the dormant continuation.
- Public raw completion input/constructor/factory and injected proof callbacks remain absent.
- Every post-start error, close or cancellation reaches one failure-terminal owner; no fallback terminal writer.
- No copied, replayed, revoked or out-of-order handle can compile, reserve, write or return terminal proof.
- A successful synthetic proof requires exact, independently reopened read-only durable evidence and the original
  byte-identical output. It never confers production execution, import, retry or restart authority.

## Ownership and phases

The unexported completion implementation lives in `graph-genesis-v2-production.ts`. A module-private symbol guards
its constructor even when reflected through an instance. Runtime private fields hide all raw construction state.
The session consumes each seal once and preserves exact object identities with private maps. Its frozen facade
contains no raw DB, path, approval token or candidate-authority fields. The separate completion module has no API.

The ordered synthetic phases are:

`issued → captured → compiled → reserved → written → terminal`

A synchronous busy guard covers each asynchronous operation; no parallel reservation, queue or retry is accepted.
The original start/execution deadlines and nondecreasing finite monotonic clock are checked, including around
awaited filesystem operations. Output/context/caller abort signals revoke idle and in-flight continuations.
Closing an output removes registration before closing its descriptor. Revocation during an already issued OS
operation cannot undo that operation, but prevents further effects or success capability issuance.

Snapshot/approval code and V1 behavior are unchanged. Synthetic post-state and codec helpers are data utilities;
caller-created utility values cannot enter the session's private ownership maps.

## Post-state and compiler

The validator retains the exact session workspace, root dev/ino/uid/mode and protected file identities/digests.
No-follow descriptor reads consume expected size + 1 to detect growth, compare before/after descriptor and path
state, and close acquired handles even when a checkpoint throws. The existing duplicate-key/bounded JSON parser
and fatal UTF-8 decoder are used for lock bytes. Lock bytes and canonical lock document have separate digests.

Only package.json, package-lock.json, user.npmrc, global.npmrc, broker-profile.sb, cache, logs and tmp are allowed at
the top level. Nested node_modules, symlinks, hardlinks, special files, executable files, archive names, foreign
owners and non-exact private modes are rejected. Streaming directory traversal stops at the entry limit + 1,
checks directory identity around traversal and closes directory handles unconditionally. Inventory is sorted by
ordinal path before hashing. It is **metadata inventory**, not a digest of every unprotected cache/log/tmp file's
content. Protected files and the lock do have byte-content digests.

Caps: depth 64; 100,000 entries; 128 MiB regular aggregate; cache 64 MiB; logs 512 KiB; protected file 64 KiB;
lock 4 MiB; Artifact2 including its LF 4 MiB. Caps never expand after failure.
Root/protected/inventory checks bracket lock observation. Retained post-state is revalidated before output open
and after output write. The compiler uses only the owned strict lock document and the exact Plan3 compilation
contract, including filesystem@2026.7.10 semantics and candidate byte ceiling.

## Honest synthetic provenance

Artifact2 is explicit canonical UTF-8 JSON with exactly one terminal LF and an outer SHA-256 digest.
Binding includes action/approval/plan/session IDs, Plan/Envelope/Projection, semantic and compilation contracts,
runtime/workspace/lock/post-state/inventory, host/containment/policy/audit/output identities.
Encoding and decoding validate the candidate, exact wrapper keys, bounds, canonical bytes and outer digest.

Broker/process/listener observations do not exist in this milestone. Their three digest slots use a closed
versioned data recipe containing actionId, component, evidenceOrigin=synthetic_fixture,
observation=unavailable and productionExecutionObserved=false. That same record is included in the owned fixture
audit event. The codec rejects other synthetic digest values and rejects relabelling these unavailable sentinels
as local_observed. This recipe authenticates no real observation. A caller's arbitrary unsigned local_observed
codec payload is also not a production-issued authority; there is no production consumer here.

Audit terminal candidate digest fields use the existing `sha256:` receipt format, not internal bare hex.
Cleanup is preserve-only/incomplete; terminalAudit is unknown at write time. The synthetic-incomplete status uses
the existing API's incomplete classification and explicit synthetic error code; zero counts are fixture facts,
not claims of observed network execution, successful cleanup or a pre-proven durable terminal.

## Output and failure owner

An output requires owned post-state/compiler pairing and a durable output-intent event before exclusive
O_CREAT|O_EXCL|O_NOFOLLOW creation at 0600. Parent descriptor and linked path must match the originally captured
private parent. The writer fsyncs, performs bounded byte-identical descriptor readback, decodes Artifact2 and
rechecks file/path/parent identity. It issues the output handle only after output-written audit evidence is durable.
Finalization independently rereads the original output and checks identity, mode, size and bytes before terminal
recording and after read-only proof. Replacement, in-place edits and same-semantic byte rewrites fail closed.

One private terminal owner records the existing terminal triple at most once. Every post-start failure,
including any phase's audit append failure, routes there. Failed or partial output is preserved as an orphan;
the code does not delete it, overwrite it, reopen authority or claim cleanup. Tests remove their own fixtures.

After either a returned or thrown terminal transaction, one read-only reconciliation is attempted. A
committed-then-thrown transaction can be proven; missing, malformed or contradictory records remain unknown.
Failure to prove never causes another terminal write, retry or output promotion. There is no timer recovery or
durable restart API. If the DB rejects the terminal transaction, its row can remain forwarding; the private owner
is nevertheless terminal/unknown and rejects every continuation. That residual row is not reported as completed.

## Owner-bound read-only terminal proof

The DB path, file identity, parent identity, schema and owner authorization snapshot come from the exact session,
never a proof caller. The verifier checks canonical path and inode/owner/mode before opening, inside the read
transaction and after it. It reopens with the existing openAuditDatabaseReadOnly API and requires a distinct
readonly/query_only connection. The writable query service does not establish proof.

Before materializing rows, SQL length/count checks enforce chain 16,384 rows, total 16 MiB and each row 512 KiB;
the selected action is limited to 1,024 events, selected tool/approval rows to 512 KiB and schema SQL to 512 KiB.
The existing schema digest and migration versions are checked. A single read transaction validates the complete
bounded hash chain, canonical strict event JSON, unique IDs, sequence ordering and row/JSON field agreement.

The action must contain the retained exact eight-event authorization prefix, execution-start, the exact ordered
owner-recorded phase events, then the three terminal records. Missing, duplicate, reordered, cross-action or
rehashed changed evidence fails. Retained terminal rows bind the exact receipt identity; schemas/digests are also
validated independently. The proof recomputes action intent from the original receipt context, checks exact
Plan/Envelope arguments, policy/decision, approval principal/status/times and the original tool-call fields.
Outcome action/coverage/authorization receipt/observed result, summary, terminal status/timestamps and terminal
digest links must agree. Candidate/Artifact2 evidence derives from the owned compiler and byte-verified output.

This is an unsigned local, same-session, synthetic proof. Pre/post path and descriptor checks are not an
openat-style defense against an adversarial same-user atomic swap-and-restore race. It does not independently
prove registry honesty, metadata coverage, tarball contents, process exit, listener drain or production execution.
Full production provenance, cleanup and restart reconciliation require separate exact approval.

## Files

The original permitted set remains, with one later, explicit test-only timing hardening addition:

1. PROJECT_STATE.md
2. src/stage/graph-genesis-v2-production.ts
3. src/stage/graph-genesis-v2-post-state.ts
4. src/stage/graph-genesis-v2-completion.ts
5. src/stage/graph-genesis-candidate-artifact-v2.ts
6. test/unit/graph-genesis-v2-production.test.ts
7. test/unit/graph-genesis-v2-completion.test.ts
8. test/unit/graph-genesis-candidate-artifact-v2.test.ts
9. docs/exact-candidate-v2-compiler-post-state-artifact-composition-architecture-check.md
10. test/integration/stdio-proxy.test.ts

## Verification and handoff

Red-first evidence reproduced the absent read-only reopen, forwarding rows after four distinct audit append
failures, and idle output/context revocation failures before correction. Regression also covers reflected
constructor rejection, duplicate issue/reserve, caller cancellation, revocation across awaited work,
descriptor cleanup on cancellation, output drift, nested replacement/special files, exact synthetic success,
rehashed receipt/event/approval/summary tampering, DB path replacement, terminal rollback/orphan preservation
and committed-then-thrown reconciliation.

After the later, explicit test-only authorization, auto negotiation's default Dashboard announcement ceiling is
10 seconds while legacy remains 3 seconds. The helper accepts an explicit per-test value; the existing policy-update
test remains explicitly bounded at 10 seconds. No production timeout, Dashboard source, global Vitest setting,
security boundary, dependency, schema or runtime source changed.

Fresh evidence: the complete stdio-proxy integration file passed 28/28 (one worker, 30-second runner limit), and
the source/build-frozen full network-free run passed 465 tests with 3 skipped across 35 passed and 1 skipped files
(exit 0, 108.29 seconds). The V2/Artifact targeted set remains 101/101. Exact commands/results are recorded in
PROJECT_STATE.md. This establishes the approved test timing correction only; it does not change the dormant,
synthetic-only provenance limits or authorize live activation.
Rollback: preserve the user's pre-existing scaffold; review and reverse only this correction's hunks and the
later-authorized stdio test-only timing hunk. No persistent data migration or production rollback is involved. No rollback, deletion of user
work, commit or push was performed. Next step is supervisor review of this candidate, not live activation.
