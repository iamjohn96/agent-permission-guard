# Exact Candidate v2 Plan v3 / Execution Envelope v2 Binding Architecture Check

Status: **network-free memory-only binding foundation implemented; production wiring remains unapproved**.
Baseline remains committed `8ffd0b9a207231f0043e3cf21120f901c6941803` on `main`/`origin/main`.
The new source is isolated from every live route and has fresh typecheck/build evidence, 75/75 focused tests,
and 364 passed with 3 conditional skips (32 passed files, 1 skipped). No real npm, network, Dashboard,
product database, disk candidate, evidence, or quarantine action ran. The v14 result remains a verified safe
failure, not candidate acceptance.

## Current source boundary

The committed v2 compiler is memory-only. It defines the immutable peer contract, explicit candidate-v2
shape, descriptor-safe reconstruction, and authority-local `WeakSet` provenance in
`src/stage/exact-production-graph-v2.ts`. Its codec produces or accepts only plain frozen evidence; it never
transfers compiler authority. The peer evaluator is a pure dependency and neither module is imported by the
current live route.

Production source remains the closed v1 tuple:

| Current source | Current version and responsibility | v2 status |
| --- | --- | --- |
| `src/stage/exact-production-graph.ts` | candidate schema 1 and existing compiler authority | production candidate remains v1 |
| `src/stage/graph-genesis-hardening.ts` | plan 2, projection with `planVersion: 2`, capsule 1, capture/revalidation authorities | no Plan3 or new capsule ownership domain exists |
| `src/stage/graph-genesis-composition.ts` | envelope 1, private envelope capsule, approval/session/lease composition | no envelope 2 exists |
| `src/stage/graph-genesis-workspace.ts` | hard-coded v1 compiler identity | no v2 route or compiler selection |
| `src/stage/graph-genesis-completion.ts` | candidate/post-state/ledger/process/cleanup/terminal-audit join | no v2 completion join |
| `src/stage/graph-genesis-live.ts` | complete runtime-manifest capture plus current live composition | capture is not a v2 authorization gate |
| `src/stage/graph-genesis-candidate-artifact.ts` | separate artifact 1 and terminal-proof path | artifact 1 must not carry or downcast v2 |
| `src/stage/graph-genesis-v2-binding.ts` | closed Plan3/Projection3/Envelope2 contract and authority-local in-memory pairing | implemented but not imported by a live route |

Source wins over older prose: the present projection discriminator is its `planVersion: 2`, rather than a
separate projection-version field. A future Projection3 must introduce an explicit version discriminator.

Source-review anchors for this check are `exact-production-graph-v2.ts` lines 16-155 (contract, closed input,
and ownership), `graph-genesis-hardening.ts` lines 409-666 (Plan2/Projection2/Capsule1 authority),
`graph-genesis-composition.ts` lines 63-206 and 319-412 (Envelope1 and approval/session flow),
`graph-genesis-workspace.ts` lines 218-264 (fixed v1 compilation),
`graph-genesis-completion.ts` lines 65-95 (current completion join),
`graph-genesis-live.ts` lines 155-180 (runtime manifest), and
`graph-genesis-candidate-artifact.ts` from line 16 (Artifact1/terminal proof separation).

## Immutable candidate semantic and compilation contracts

`PEER_SEMANTICS_V2_CONTRACT` is committed exactly as candidate schema 2, peer semantics 1,
`stable-triplet-multi-u0020-v1`, `nearest-ancestor-v1`, and
`ordinary-required-peer-fixed-point-v1`, with all literal limits: candidate bytes 4 MiB, range bytes 256,
branches 8, atoms 16, comparisons 32, nodes 256, path bytes 512, path segments 32, peers per node 64,
peers 2,048, and combined requirements 4,096. No caller-provided, relaxed, or alternate contract is
accepted.

Define `semanticContractDigest` as the lowercase 64-hex SHA-256 of `canonicalJson` over that complete
literal. Existing receipt fields retain their current `sha256:` prefix convention where applicable; this
internal digest is not silently reformatted.

Define one closed `compilationContractVersion: 1` containing the literal and digest, plus:

- `profileId: filesystem-2026-7-10-candidate`, `profileVersion: 1`;
- target `@modelcontextprotocol/server-filesystem@2026.7.10` with `dist/index.js`;
- `https://registry.npmjs.org/`, darwin/arm64, node major 26, node `26.3.1`, npm `11.16.0`, lockfile 3;
- materialization rules 1, archive rules 1, archive worker protocol 2;
- all nine `PackageStageLimits`, effective lock/candidate byte caps, and the one-output rule.

Archive/materialization values are candidate-evidence commitments only. They do not authorize an archive,
materialization, installation, or package execution. Optional limits normalize once before any hash; no
compile-time default/fallback may drift between validation and hashing. Semantic hard ceilings are unchanged,
the lower applicable limit wins, and Graph Genesis broker/execution limits remain distinct from candidate and
package-stage limits. The memory-only Plan3 validator caps those limits at the current live fixed ceilings:
broker 128 unique names, 256 total requests, four concurrent requests, 4 MiB per response, 64 MiB aggregate,
and 10 seconds per request; completion 120 seconds; stdout and stderr 256 KiB each; package.json 64 KiB; and
package-lock.json 4 MiB. Lower positive budgets remain available only for synthetic evidence. A later real
adapter must supply the present exact fixed values.

## Closed Plan3 / Projection3 / Envelope2 tuple

Plan3 preserves every Plan2 capture, workspace, containment, route, launch, environment, private capsule,
limit, and consequence commitment. It additionally carries the closed compilation contract and its digest,
and an authenticated `runtimeManifestDigest`. Projection3 derives only from the authenticated Plan3 and has
an explicit `projectionVersion: 3`; it is never trusted merely because a caller supplied matching `planId` or
`planHash`. Envelope2 preserves all current audit, output, Dashboard, session, host, boot, policy, time, and
limit identity while binding Plan3/Projection3, candidate schema 2, peer semantics 1, semantic digest,
compilation-contract digest, plan hash, and the authority-derived projection digest.

The required canonical hash DAG is:

```text
full semantic literal
  -> semanticContractDigest
  -> compilationContractDigest
  -> unsigned Plan3 hash
  -> authority-derived Projection3 digest
  -> unsigned Envelope2 hash
```

Every version field participates in its unsigned canonical JSON hash. There is no blanket `>=` compatibility,
wildcard, mutable placeholder, or candidate digest in the pre-execution Plan3/Envelope2. Unknown or missing
keys, getters/accessors, invalid types including `NaN`, unsupported versions, and out-of-bound values reject
before hashing. Validated internal values are recomputed and frozen. Deserialized, copied, or merely frozen
objects never gain runtime authority.

More precisely, `compilationContractDigest` is `SHA256(canonicalJson(full closed compilation contract))`.
`planHash` and `executionEnvelopeHash` are each `SHA256(canonicalJson(unsigned exact versioned object))`,
excluding only that object's own hash field. `projectionDigest` hashes the complete authority-derived
Projection3, including `planHash`. Fresh plan/session ownership, rather than a user-supplied self-hash or
matching digest, is the authentication boundary.

Closed-data validation occurs before canonicalization: reject unknown keys, missing keys, `undefined`,
functions, symbol keys, non-JSON numerics, cycles, accessors without invoking them, and invalid bounded
descriptor depth, identifier, or text lengths. It must never silently drop an unknown/undefined property.
Ports, versions, and limits require bounded safe integers. `planDeadlineMonotonicMs` alone preserves current
runtime compatibility by accepting an exact finite, positive, safe-range fractional value such as the result
of `performance.now() + 180000`; zero, negative, non-finite, negative zero, and unsafe magnitudes reject.
The foundation's values remain descriptive and in-memory; they do not prove a real runtime capture.

A new capsule ownership domain pairs only an owned Plan3, Projection3, Envelope2, and private capsule. The
new capture-capsule format/version is a later private-adapter design decision, not a selected Capsule3. The
next pure pairing must never accept Capsule1 as production authority, broaden the old plan authority, or accept
an edited projection with matching identifiers or a recomputed digest. This does not allege an existing
live-route exploit: the current route internally derives its projection. It is a required v2 ownership property
before publication, approval, or any external effect.

## Candidate discovery and later completion binding

`candidateDigest` remains unknowable until bounded metadata and lock compilation. Initial approval therefore
authorizes exact bounded discovery and at most one local candidate output, not installation or execution of an
unknown downstream graph. Candidate schema 2 and its digest formula remain untouched. Binding the final digest
before discovery would require circular planning or a wildcard. This design instead records Graph Genesis context
in a separate completion binding. A one-way context reference need not mathematically cycle, but it would require
a separately approved candidate-schema change and is outside this check.

A later, separate, authority-owned completion binding must pair a candidate with the exact plan hash, envelope
hash, post-state digest, and compilation-contract digest. It must independently match all candidate metadata
and semantic fields against the approved contract. A valid self-consistent memory-decoded candidate remains
untrusted plain evidence. Artifact2, disk terminal proof/import, production profile/materialization consumers,
and all artifact1 changes are separate gates; v2 is neither put into artifact1 nor downcast to v1.

## Runtime, approval, and lifecycle obligations

The runtime semantic-content digest is distinct from executable integrity. Future production wiring must bind
the v2 compiler, evaluator, codec, binding module, npm runtime, and the complete existing runtime manifest
(SQLite/native files, migrations, web assets, manifest/system files). The owner must authenticate and revalidate
the complete capture rather than accept a caller digest. Current live capture includes a broad manifest, while
current Plan2 revalidation covers only a subset; this is a future wiring obligation, not a property established
by this document. It offers no same-user tamper or attestation guarantee.

Approval identity remains action/request/session plus Envelope2 hash, Plan3 hash, policy digest, audit/output
binding. Receipt 1.2, audit, and DB schemas remain unchanged. Dashboard capability is not a human cryptographic
identity. The current `GRAPH_GENESIS_POLICY` descriptor/content digest, Ask/70/high risk, and current reason
codes remain unchanged. There is no policy relaxation or audit/receipt/DB schema change. A durable request
precedes publication; one exact local approval is consumed once; durable authorization precedes broker arm and
process spawn.

The source-derived start bound is exactly
`min(planDeadlineMonotonicMs, requestedMonotonicMs + 120000, decisionMonotonicMs + 15000)`.
The existing lease then sets `executionDeadlineMonotonicMs` to `startByMonotonicMs + 120000`; it is not an
all-clocks minimum throughout execution and must not be extended after spawn or revalidation. A future v2 gate
checks cancellation and the latest applicable deadline after awaited boundaries and immediately before effects.
Tests must cover start and execution boundaries at minus-one/equal/plus-one and prove no extension. No newly
invented wider TTL and no lease API belongs in the next pure unit.

A future v2 start gate verifies the exact owned plan/envelope/session/phase tuple. `broker_arm` and
`process_spawn` occur at most once, with no retry. LeaseVersion1 shape may be reused only in a separate v2
ownership/verifier domain that also checks Envelope2 hash, supported tuple, and phase ordering. Old v1 leases,
synthetic leases, serialized tickets, or matching hashes cannot mint v2 capability.

Mixed tuples reject before audit-request exposure. Pre-effect cancellation, expiry, audit failure, or drift
means no DNS/HTTPS, child, or output. Post-start failure retains existing abort/disarm/observe semantics with
no retries and nondestructive quarantine for unknown residue. Candidate match and output max-one are not a
terminal success: the exact ledger, post-state, cleanup, terminal triple, and Outcome Receipt join remain
required. Post-effect audit uncertainty preserves existing unknown/incomplete handling and only bounded
read-only reconciliation, never replay. Direct npm/npx remains outside APG protection.

## Implemented test boundary and unverified limits

The pure unit tests closed literal and field keysets; exact and plus-one budgets; field mutation of
semantic/profile/runtime/rule/limit/output/plan/envelope identity; canonical stability; forged recomputed
hashes; copied/foreign ownership; edited projections with matching IDs; all old/mixed/unknown versions;
absence of defaults/wildcards/undefined candidate digest; synthetic-lock contract parity; and decoded evidence
that remains non-authoritative. These are in-memory tests only. The focused set combines the new binding unit
with the existing candidate-v2, codec-v2, peer-semantics, and Graph Genesis hardening suites: 75/75 passed.

Later, separately approved composition tests must cover durable request/publish/authorize/arm/spawn ordering
with fake clock/transport/inert child/in-memory audit; v1 and cross-session replay; double phase use;
cancellation at every awaited boundary; deadlines; full runtime drift; post-state mismatch; output max-one;
and partial terminal write/reconciliation. Neither group invokes real transport, child, product DB, disk
candidate, or historical evidence in this memory-only foundation stage.

Unverified and intentionally excluded: authenticated production capture/session adapters, complete-manifest
revalidation, production approval/start/lease wiring, compiler/post-state/terminal join, Artifact2/disk proof,
consumer compatibility, any real npm/registry/Dashboard/DB activity, and live acceptance. Portable digest
evidence is unsigned and cannot reverse metadata disclosure or protect against privileged same-user mutation.

## Result, next gate, risks, and rollback

The approved network-free, memory-only Plan3/Projection3/Envelope2 binding foundation is implemented in
`src/stage/graph-genesis-v2-binding.ts`,
`test/unit/graph-genesis-v2-binding.test.ts`, this document, and `PROJECT_STATE.md`.
It imports the committed v2 compiler contract as a pure dependency, does not wrap Plan2 as an authorized
Plan3, add injectable production paths, expose CLI/route changes, or authorize/start/lease. It proves only
in-memory binding consistency. No file outside the four-file boundary was changed.

Fresh verification used existing dependencies only: typecheck passed, build passed, focused tests passed
75/75, the full network-free suite passed 364 with 3 conditional skips, and diff/whitespace checks passed.
Partial production wiring remains dormant with no public v2 CLI, no auto-activation, and no fallback until
the separate compiler/post-state/terminal/artifact and live gates are approved.

Later gates are, in order: authenticated production snapshot/approval/session wiring; compiler/post-state/
terminal join plus Artifact2/disk consumer; then a fresh separately approved live acceptance. Risks include
strict-subset rejection, unknown real peer declarations, incomplete runtime revalidation until wired, unsigned
portable evidence, metadata disclosure irreversibility, and privileged same-user mutation. Rollback is removal
of the new source, unit test, design document, and only this change set's `PROJECT_STATE.md` edits, preserving
unrelated user work; there is no runtime state, migration, or approval to revoke.
