# Exact Graph Genesis Candidate Compiler Private Diagnostics Architecture Check

Status: implemented network-free on 2026-09-11. Baseline: clean `2edb556`.

## Decision

The exact lock candidate compiler now gives every expected rejection one closed predicate while
retaining the public `graph_lock_invalid` error code. The predicates cover candidate input,
lock/root shape and identity, graph size, install paths, package shape/role/artifact identity,
dependency specifiers/resolution, target identity, and graph connectivity.

Each rejection creates a fresh `PackageStageError('graph_lock_invalid')` and a frozen,
authority-local diagnostic pair. `WeakMap(error, failure)` prevents copied or independently
created errors from gaining provenance; `WeakSet` ownership and one-time claim prevent replay.
The diagnostic contains only version and predicate, never a lock path, package name, URL,
integrity, bytes, or other candidate details.

## Graph Genesis hand-off and terminal behavior

`HardenedGraphGenesisCandidateCompiler` claims only a failure returned by its own invocation of
the exact candidate authority. It maintains a separate authority-local error/failure pairing and
offers exactly one best-effort local stderr projection per claimed failure. The fixed prefix is
`[apg] graph-genesis-candidate-diagnostic ` and the complete UTF-8 line is capped at 1 KiB.
Writer failure is inert.

The production live owner claims this compiler-paired failure in its existing catch path, after
which it attempts the existing failure terminal behavior unchanged. Only after that attempt, and
only after both npm-terminal observation and listener drain, can it emit the candidate diagnostic.
Candidate compilation failure leaves `candidate` absent, so no candidate artifact is written; the
existing cleanup, generic terminal classification and public `graph_lock_invalid` contract remain
unchanged. Audit, receipt, database schemas and approval behavior are untouched.

## Network-free verification

The targeted commands `./node_modules/.bin/tsc -p tsconfig.json --noEmit` and
`./node_modules/.bin/vitest run test/unit/exact-production-graph-read-only-acceptance.test.ts
test/unit/graph-genesis-production-hardening.test.ts test/unit/graph-genesis-live-owner.test.ts`
completed successfully with **66/66** tests. They verify all thirteen predicates, fresh/copy/forged ownership rejection, one-time claims, the exact
bounded redacted line, broken-writer inertness, compiler-only pairing, post-state-bound cleanup
after a synthetic compile failure, and static live-owner terminal ordering. The type check passed;
a separate local `./node_modules/.bin/vitest run` full safe suite passed **330 tests** with
**3 conditional skips** (28 passed files, 1 skipped file). `git diff --check` also passed.

The synthetic boundary proves candidate absence, omitted candidate evidence, authenticated cleanup,
and the unchanged pure failure/terminal classification. It deliberately does **not** claim a full
production-live terminal triple: the production owner has no test injection seam and no real
npm/Dashboard/DNS/HTTPS/live execution, product database, candidate output, evidence or quarantine
path was used. No dependency, commit or push operation occurred.
