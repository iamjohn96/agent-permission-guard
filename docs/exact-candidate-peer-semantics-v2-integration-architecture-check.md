# Exact Candidate Peer Semantics v2 Integration Architecture Check

Status: **memory-only authority/codec foundation implemented and verified; production integration pending**. Baseline: `4080e64` on `main`. The pure evaluator's three regression corrections are separate existing-scope work; this document does not authorize production v2 integration, live activity, or v15 acceptance.

## Current boundary

Production remains v1: `exact-production-graph.ts` owns candidate/node schema v1, peer rejection, and name-only ordinary resolution; `graph-genesis-hardening.ts` has plan/projection v2; workspace hard-codes compiler candidate/profile/rules v1; and composition envelope v1 binds plan hash, projection, runtime, policy, audit, and output. Artifact v1 canonicalizes its top-level hash and terminal proof but has no nested full-candidate validation/recomputation. Manifest projection v1 forbids peer presence and tree validation rejects nonempty peers. Accepted production-profile authority and `VerifiedMcpGraphProfile` consumer authority are separate, never interchangeable. Baseline evidence is 339 passed and 3 skipped; the separate foundation correction then passed focused evaluator 11/11, typecheck, and canonical full suite 342 passed with 3 skipped. Network-free results do not prove live behavior.

## Versioned v2 contract

Use versioned v2: preserve v1 semantics/decoder golden cases, never strip/cast/fallback peer fields, and keep new v2 type, authority, codec, and validator memory-only until separately approved. Candidate v2 carries existing unsigned fields plus immutable semantic contract, exact root dependency, per-node ordinary edges, distinct peer declaration/meta/raw-peer-flag presence, and normalized requirements. Raw peer-flag absence remains absent; an explicit boolean must agree with recomputed R-minus-P role and is never overwritten by derived `true`. It preserves absent versus present-empty, meta absent versus `{}` versus optional false/true, and recognized raw specifiers. Requirements sort by from-install-path/name/raw specifier; contain optionality and tagged present target path+exact version or absent only if optional. Ordinary targets/ranges validate; R closes ordinary plus required peers, optional-present independently remains R-reachable, ordinary edges alone form the DAG, and every reachable node processes once. Package name/path/meta is public candidate evidence, never private diagnostic output.

The allowlisted immutable literal contract contains candidate schema v2, peer semantics v1, grammar/resolver/closure identifiers, and raw rules/maxima; caller policy cannot mutate it and drift changes digest. The corrected evaluator implements the approved one-or-more U+0020 grammar, bounds range strings at 256 bytes, and counts slash-delimited portable path segments against the 512-byte/32-segment ceiling. The v2 authority also honors lower configured candidate/lock byte limits.

Limits are current 4 MiB lock/artifact/candidate-v2 input with lower limit winning, graph 256, paths 512 bytes/32 segments, peers 64 per node/2048 global, and combined 4096 counting root ordinary, all node ordinary, and all peers including optional absent. Validate incrementally before range parse/traversal/unbounded allocation. No transport/stdout/deadline widening.

## Artifact, commitment, and consumer gates

The memory-only codec carries the complete canonical candidate v2, not nodes plus an unreconstructible hash. Its decoder rejects duplicate keys at every object depth and any noncanonical JSON bytes, validates closed nested shapes and the exact semantic-contract literal, rebuilds a lock from retained raw declarations, and recompiles ordinary edges, peer resolution/optionality/role, closure, and the candidate digest. It rejects malformed, out-of-contract, downgraded, and recomputed-but-inconsistent payloads. A self-consistent alternate valid payload can be decoded and re-encoded as plain evidence, but a self-hash or JSON cast cannot mint authority: decoded evidence is deeply frozen and remains foreign to the original authority and every other compiler authority. Provenance is the creating authority's local object identity, not the digest. A future disk artifact v2 must separately bind and verify its artifact digest and terminal proof or signing evidence.

Future commitment is plan/projection v3 plus envelope v2 binding semantic digest and plan/projection hashes; compiler requires exact supported tuple and authenticated post-state/plan match. Runtime snapshot/frozen policy digest cover versions. Pre-metadata approval binds fixed target/runtime/rules/limits/output, not unknown graph; complete candidate/artifact needs fresh approval. Receipt/audit/DB schemas stay unchanged and hashes bind versions.

| Consumer | Required v2 gate |
| --- | --- |
| Artifact/decoder | Full canonical payload, recomputation, version rejection |
| Metadata/artifact acceptance | v2 plan/evidence compatibility |
| Manifest projection | Peer/meta parity per install path including shared tarballs |
| Profiles | Separate production-profile v2 and peer-aware VerifiedMcpGraphProfile v2 |
| Tree/seal/stage identity | Peer requirements and absent/present/shadowing rechecks |
| Archive protocol | Byte-compatible only if payload/meaning unchanged and tested |

No candidate-to-profile shortcut, v2-to-v1 normalization, consumer activation, materialization, download, or startup precedes complete consumer review and version-rejection proof.

## Failure invariants, tests, and next gate

Retain exact one-time Dashboard choice, durable intent/authorization before broker/npm, cancellation, one-owner terminal, stop-and-drain, post-state-only cleanup or quarantine, and post-audit incomplete/outcome-unknown with no retry/deletion/orphan promotion. Orphans require matching terminal triple and Outcome Receipt. v2 may add one bounded authority-owned diagnostic v3 only for v2 failure: closed mapping, one claim/emit, no names/values/paths/digests/counts. Its mapping/schema is not connected by the proposed memory-codec unit and belongs to a later owned compiler step. Evaluator strings, instanceof, and copied objects are never proof; diagnostic failure never replaces terminal cause; v1 diagnostic v2 stays unchanged.

Required tests: v1 goldens; inconsistent mutation/recomputed-self-hash forgery; self-consistent foreign evidence without authority transfer; missing/extra/duplicate/reorder/overlong fields; versions/absence/false/scoped shadowing; queue order/every R edge; exact/+1 budgets; malformed retained optional; placement parity; proof denial/mismatch; cancelled/expired/replayed approval with no effects; audit failure using fake transport, inert child, disposable fixtures.

The implemented memory-only authority accepts only the explicit v1-compatible profile, top-package, registry, runtime, rule/protocol, limit and `packageLock: unknown` fields; there is no freeform metadata or graph bag. It clones descriptor-validated input, preserves artifact/runtime/security identity and raw dependency/peer/meta/peer-flag presence, uses the shared evaluator, and records tagged present/absent peer requirements. Its private WeakSet provenance authenticates only the exact object it compiled. The memory codec performs the full recompile described above and never transfers that provenance. Source SHA-256 at verification: evaluator `d350f590a879378228b90e540f5342db53aeff6cb169b37474888e6c8e0c5068`, authority `1545fc5a59d02e3708b7d7a715566d117a80061ce247cd080afec96571638911`, codec `dfc277701dbe2d644408722c2b9e0b471add09c9197035fdbb72bbf9e28dbd61`.

Fresh network-free verification passed: typecheck, 22/22 focused evaluator/authority/codec tests, canonical build plus full suite with 31 files passed and 1 skipped, and 353 tests passed with 3 conditional skips (356 total), plus `git diff --check`. Tests include authority ownership/copy/foreign rejection, exact metadata and artifact retention, lower-case-only v1 profile identity, raw absent-versus-empty binding, canonical map/node order, nearest-ancestor and optional-absent peer evidence, malformed identity/artifact/range/root/budget cases, descriptor accessors with zero getter calls, canonical byte enforcement, root and nested duplicate JSON keys, semantic-contract drift, recomputed-but-inconsistent self-hash rejection, self-consistent alternate evidence without authority transfer, forged derived evidence, version downgrade, and invalid lower byte limits.

This foundation excludes disk artifact write/import proof, live plan/envelope wiring, consumer activation, DB, real candidate, dependencies, and live actions. Follow-on gates are plan3/envelope2, disk codec/terminal-proof integration, and fail-closed consumer compatibility before v15. Risks: strict-subset valid-lock rejection, unknown v14 peer details, no publisher/runtime-containment claim. Rollback is inverse reviewed hunks; future runtime never downgrades or reuses approval. No commit/push belongs to this task.

## Superseded foundation verification

The earlier draft passed 16 focused tests and 347 with 3 skips, but did not satisfy the required field-level closed v1 metadata contract. Those results are superseded by the completed implementation and must not be used as acceptance evidence. No Graph Genesis npm child, package resolution/install, registry/network, Dashboard, DB, candidate artifact/import proof, or live action ran.
