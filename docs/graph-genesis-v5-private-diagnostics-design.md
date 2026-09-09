# Graph Genesis v5 private failure diagnostics

Status: network-free implementation complete locally under the user's 2026-09-09 approval; ready for supervisor review.
Baseline: `c0b48b62182c055cd2c79d1846cae0663a0e2e03`.
This checkpoint changes diagnostic source, synthetic tests and documentation. It does not run v5.

## Evidence and corrected inference

The supplied v4 evidence and the prior immutable read-only audit inspection agree on 10 metadata starts,
six validations totalling 644145 bytes, process cancellation, listener drain (15 accepted handlers), one
incomplete product outcome, and natural exit 5 with quarantine. The terminal ownership correction worked.
The first failure remains `graph_metadata_invalid`.

The earlier conclusion that the initiating failure was confined to the last four transport responses was
too strong. `metadata_request_started` is written **after** local route validation and resource reservation.
A fifth concurrent request can be rejected at the four-request limit before it gets an intent event.
That rejection aborts the four already dispatched requests. A route or listener rejection can do the same.
Listener accepted-handler counts also include disarmed/rejected requests and cannot identify which failed.

Three deterministic, network-free tests now produce the same ordered package intents, six validations,
644145 validated bytes, and first-failure counts of 10 reserved / 4 active / 6 committed:

| Synthetic initiating condition | Dispatched requests | Durable metadata starts / validations |
| --- | --- | --- |
| Fifth concurrent request rejected before reservation | 10 | 10 / 6 |
| Invalid local route rejected before reservation | 10 | 10 / 6 |
| One of four pending synthetic transports rejects | 10 | 10 / 6 |

The bodies are synthetic JSON padded with whitespace to the observed safe byte counts. No v4 response
body was retained or reused. These tests prove observational ambiguity; they do not prove the v4 cause.
They do not reproduce v4's full HTTP handler count or an actual npm child.

## Implemented diagnostic boundary

The implementation extends the existing authenticated, memory-only first-failure summary with an owner-produced diagnostic
predicate. Distinguish pre-dispatch rejection from transport and response validation before considering
any changes to concurrency, parser strictness or byte limits. No acceptance predicate or execution policy
changes in this checkpoint.

Use a module-private WeakMap from error objects to a closed diagnostic code. Every owned check site creates
and tags its own `PackageStageError` before throwing it. The broker's `#fail` and public `abort()` API accept
no predicate or caller-supplied diagnostic argument. Listener rejection passes its own module-private tagged
error into the latch. Do not trust an injected error's properties, message, stack, `cause`, or code-shaped
strings. An untagged error is wrapped at the owning boundary in a newly created and tagged `unclassified`
error; it never inherits a stage or predicate from the caller. Transport error tags propagate into the
broker's existing first-failure latch; there is no second terminal owner and no new broker audit terminal event.

The diagnostic code is one closed enum; stage is derived from it, not separately caller-supplied:

| Stage | Proposed closed predicates |
| --- | --- |
| listener | `listener_request_rejected` |
| request | `request_route_rejected` |
| reservation | `session_not_armed`, `total_request_limit`, `concurrent_request_limit`, `unique_name_limit`, `aggregate_reservation_limit` |
| audit | `request_intent_not_durable`, `response_validation_not_durable` |
| transport | `dns_result_rejected`, `dns_incomplete`, `https_incomplete`, `wire_size_rejected` |
| response | `http_status_rejected`, `redirect_or_url_rejected`, `content_type_rejected`, `content_encoding_rejected`, `response_size_rejected`, `utf8_rejected`, `json_rejected`, `identity_rejected` |
| completion | `broker_incomplete`, `unclassified` |

`json_rejected` is deliberately a parser-boundary diagnosis, not a claim that JSON was malformed:
duplicate keys, syntax, depth and key-count bounds all currently share that failure boundary. A future
parser-specific refinement must preserve every existing check and must not expose a key or input fragment.
DNS and HTTPS predicates similarly identify the owned boundary, not an unobserved remote root cause.

The implemented summary retains its current plan hash, two-valued cause code, bounded counts and digest;
adds `diagnosticVersion: 1`, `predicate`, and `requestOrdinal: number | null`; and computes its digest only
over this allowlisted safe structure. An ordinal is the already-reserved broker request ordinal, not an
`audit_events.sequence` and never an inferred "next ordinal". Pre-reservation/listener failures have `null`;
no package is blamed in that case.
Counts remain snapshots at the first latch, not final durable audit counters. `committedResponseCount`
and `committedResponseBytes` describe private ledger entries; response audit may race with abort.

First failure wins synchronously before the abort callback. Later transport cancellations, invalid routes,
`abort()` and `complete()` cannot alter its cause, predicate, counts or digest. `claimFailure()` stays one-time.
WeakSet provenance remains necessary after claim; copied, deserialized and foreign-authority summaries fail
authentication. Diagnostic values are evidence only and cannot authorize transport, spawn, retries or import.

## Implemented operator observation

A private in-memory predicate alone would be lost again on process exit. The implemented observable
surface is one bounded owner-written diagnostic line on the local CLI's stderr, after process/listener
shutdown has completed or their uncertainty has been conservatively classified, and after the existing
terminal-outcome attempt. No database migration, public receipt field, audit event, candidate field, CLI
flag, or stdout result change is needed.

The owner authenticates the claimed summary and checks its plan binding, constructs the allowlisted projection
afresh, canonicalizes it, and emits at most one line with the fixed prefix `[apg] graph-genesis-diagnostic `.
The UTF-8 encoded prefix and canonical projection together have a hard 1024-byte cap. It never stringifies an
Error, execution capsule, request, response, or arbitrary object. The projection contains only diagnostic
version, predicate, nullable request ordinal, existing safe counts and plan/failure digests. No URLs, IPs,
package names, headers, tokens, paths, raw bodies, raw-body hashes, child stdout/stderr, messages or stacks
are allowed. If a valid authenticated projection is unavailable or the capped line cannot be formed, omit the
diagnostic instead of using fallback data or a partial line.

This local diagnostic is not a durable receipt or proof of successful execution. Its emission cannot change
the result, quarantine, exit code, or terminal outcome. Broken-pipe/write failure is best-effort and cannot
retry the action, add a terminal event, or delay natural process exit indefinitely. Genuine audit-persistence
failure retains the existing conservative outcome classification regardless of any broker diagnostic.
The stderr surface remains local and is not silently placed in the audit DB.

## Implementation and verification contract

Changed source scope: `graph-genesis-network.ts` for owned tags and latch,
`graph-genesis-live.ts` for final owner emission, and `graph-genesis-diagnostics.ts` for canonical allowlist
projection. No parser source edit is required for boundary-level diagnosis.

Completed and retained verification requirements:

1. The three identical-count cases above now have distinct request/concurrency/transport predicates while
   retaining the same broad error code, durable intents and response-validation semantics.
2. Each owned predicate has an appropriate adversarial fixture: malformed route, limits at/over boundaries,
   unsafe/mixed DNS result, redirect, status/type/encoding, empty/oversized body, invalid UTF-8, JSON duplicate
   keys/syntax/depth/key count and wrong package identity. No rejected input becomes accepted.
3. At most four pending transports; first failure causes one callback, settles all pending work and cannot
   be overwritten by later cancellation or completion. No queue, automatic retry or limit increase.
4. Forged/copy/foreign errors and summaries cannot inject predicates, request ordinals, strings or payloads.
   Pre-reservation failures have no invented broker request ordinal or request-intent event.
5. The owner produces one bounded diagnostic only after termination/drain classification; success has none.
   Audit failure and unknown cleanup retain their precedence. Existing terminal atomicity remains intact.
6. A synthetic local child harness verifies natural exit and broken-pipe behavior; no production owner,
   public resolver/client, npm child, operator DB or acceptance path is used.
7. Typecheck, affected tests, build and the full safe suite pass, with changed-source checks confirming no
   new public receipt/audit schema, dependencies, approval bypass, candidate/import or activation path.

## Review and eventual v5 run boundary

The current result is a concrete local implementation and reproduction evidence, not a claim that v4's exact
cause is known or that a corrected live build has been accepted. Supervisor review should review the bounded
stderr surface before any v5 run. Any eventual v5 run must use that reviewed build,
fresh absent operator paths, and a fresh exact execution-envelope approval; no v1-v4 evidence is reused.
Do not treat the earlier generic design approval as a pre-consumed Dashboard approval or permission to
run an unspecified command against an unspecified DB/output identity.

Rollback for this checkpoint is limited to its diagnostic design document, its three synthetic test cases,
and the corrected state/readiness paragraphs. Existing evidence files remain outside this change.
