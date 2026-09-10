# Graph Genesis v7 terminal classification and post-state diagnostic checkpoint

Status: approved for network-free implementation and verification only.
Baseline: `50ee71c6b15c9b79b67828de24fa291556cc79fc`.

## Supplied v7 safe result and bounded inference

The supplied v7 evidence reports npm exit 0, 126 metadata starts and 126 validated responses, at most four active
requests, 6,792,802 aggregate validated bytes, and listener drain. The audit tail stops at
`lock_validation_started`; no candidate or Dashboard state is present, the CLI result is quarantined, audit-call
forwarding remains visible, and the normal product terminal triple is absent. The supplied evidence does not reveal
the exact post-state inspection predicate. It must not be treated as a successful candidate, cleanup, terminal
receipt, or reusable approval.

`GraphGenesisAuditGate.metadataSummary()` correctly identifies the 126/126 result as `validated`. The previous live
catch incorrectly chose `incomplete_external_read` for every state other than `not_started`. The existing recorder
rejects `validated + incomplete_external_read` before its terminal transaction, because that terminal status means
the metadata phase itself stopped part-way through. That mismatch explains the observed forwarding/no-terminal
state without reinterpreting the v7 action.

## Implemented network-free correction

The live owner now selects its existing receipt terminal using only the closed metadata summary and cancellation:

| Metadata summary | Cancelled | Terminal status |
| --- | --- | --- |
| `incomplete` | either | `incomplete_external_read` |
| `validated` or `not_started` | yes | `cancelled` |
| `validated` or `not_started` | no | `execution_error` |

The broader `externalReadMayHaveOccurred` value remains unchanged for conservative result and cleanup handling.
The audit/receipt schema and recorder assertion remain unchanged: a fully validated metadata phase followed by a
post-state failure is an `execution_error`, not a relaxed incomplete-read receipt.

Post-state inspection now produces a first-failure object that only its creating authority can claim once. Its
closed predicates are `authority_binding_rejected`, `workspace_identity_rejected`,
`protected_file_identity_rejected`, `inventory_rejected`, `manifest_rejected`, `lock_document_rejected`, and
`config_empty_rejected`. Copies, forged values, a reused thrown error, and values from a different authority fail
authentication.

After an attempted terminal outcome and only after npm terminal observation plus listener drain, the owner may emit
one best-effort local stderr line for an authenticated post-state failure. The line is capped at 1024 UTF-8 bytes and
contains only diagnostic version and fixed predicate. It excludes paths, file content, package/registry data, raw
child output, errors, stacks, file identity values, owners, and digests. A write failure cannot alter cleanup,
terminal classification, result, retry behavior, or liveness. Broker diagnostics and all receipt/audit evidence
remain separate.

## Verification boundary and next acceptance

Network-free tests cover the terminal selector, atomic `validated + execution_error` terminal events, continued
rejection of `validated + incomplete_external_read`, every synthetic post-state predicate, authority/forgery/reuse
rejection, redaction and size bounds, broken stderr, and owner catch ordering. They do not invoke the live owner,
npm, DNS, HTTPS, Dashboard, product DB, a candidate path, or any v1-v7 evidence location.

This checkpoint does not establish why v7 post-state inspection failed or that the corrected build succeeds in a
live action. Any later acceptance requires review of the changed build, fresh private paths and audit state, a new
exact command authorization, and a new Dashboard `Approve once` decision. No queue, retry, broker-limit change,
fixed npm-argument change, or schema change is authorized by this checkpoint.
