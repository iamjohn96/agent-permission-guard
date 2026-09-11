# Exact Candidate Package Role Private Subpredicate Architecture Check

Status: implemented network-free on 2026-09-11. Baseline: clean `cc060c7`.

## Decision

The former compound private `package_role_rejected` candidate-lock rejection is replaced with
fourteen closed predicates: the seven boolean role flags, then peer dependency fields, optional
dependency fields, bundle fields, and OS/CPU selectors. Package records are still visited in
sorted install-path order, and fields are evaluated in that listed order. The first matching
condition is the sole diagnostic.

Boolean flags retain the prior `=== true` behavior: explicit `false` remains acceptable. The
dependency, bundle, and selector fields retain the prior `!== undefined` behavior: any defined
value, including `false`, is rejected. This is a vocabulary refinement only; no role policy is
relaxed.

## Private diagnostics and retained behavior

Candidate failures now use `diagnosticVersion: 2` because the predicate vocabulary has a changed
meaning. The fixed payload remains exactly `diagnosticVersion` and `predicate`; it contains no
lock content, path, package, URL, integrity, or raw field value. Existing authority-local
WeakMap/WeakSet provenance, one-time claims, one bounded local stderr projection and writer-failure
inertness remain unchanged.

The public error is still `graph_lock_invalid`. Compiler pairing, candidate absence on failure,
post-terminal emission ordering, cleanup, approval, audit/receipt/DB schemas, dependencies and
strict acceptance/rejection behavior are unchanged.

## Network-free verification

`./node_modules/.bin/tsc -p tsconfig.json --noEmit` passed. The targeted command
`./node_modules/.bin/vitest run test/unit/exact-production-graph-read-only-acceptance.test.ts
test/unit/graph-genesis-production-hardening.test.ts` passed **50/50** tests, exercising all
fourteen single fields, false-versus-defined semantics, same-record field precedence, sorted-record
precedence, private ownership/copy/foreign replay resistance, the exact bounded version-2 stderr
line, and unchanged public candidate failure. `./node_modules/.bin/vitest run` passed **331** tests
with **3 conditional skips** (28 passed files, 1 skipped file); `git diff --check` also passed.

No real npm, Dashboard, DNS/HTTPS, live execution, product DB, candidate, quarantine/evidence
access, dependency change, commit or push is used.
