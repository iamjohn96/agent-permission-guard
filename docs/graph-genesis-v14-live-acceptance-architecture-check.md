# Graph Genesis v14 Live Acceptance Architecture Check

Status: **executed once; verified safe failure**. Baseline was clean `d3e3adeceb6588230f12a88e0fb2d5650ec7443d` before this three-file documentation-only diff.

## Current source and retained evidence

Baseline includes candidate private diagnostics `diagnosticVersion: 2` and fourteen deterministic package-role predicates. A compiler failure may provide one private diagnostic but is never successful candidate acceptance. Existing network-free evidence is reused, not reinterpreted: targeted tests passed 50/50 and the full suite passed 331 tests with 3 conditional skips. Before a future launch, verify `HEAD` is `d3e3ade` and restrict `git status`/diff to these exact three approved documentation-only edits; no staged, source, test, or dependency change is allowed. Only then use the existing-dependency `./node_modules/.bin/tsc -p tsconfig.json` build. The build is not a source-cleanliness or identity verifier.

## Historical approved one-shot boundary (consumed)

All setup happens only after explicit live approval. The proposed root is `/private/tmp/apg-graph-genesis-live-acceptance-20260911-v14`, newly created no-follow and exclusively at 0700. A pre-existing path is a collision: stop without inspection, reuse, modification, deletion, fallback root name, or manual cleanup. Verify `/private/tmp` is the canonical system temporary directory (its system ownership is expected); require the newly created v14 root and `audit.sqlite`, not `/private/tmp`, to have the current user UID. Exclusively create no-follow `audit.sqlite` at 0600 as a single-link regular file. Revalidate matching device/inode, owner, and mode before and after existing-schema initialization. Initialization permits only versions `[1,2]`, required schema, integrity/hash-chain validation, and empty action/approval tables. No existing DB or root is reusable. `candidate.json` and `dashboard.json` must be absent. No v1-v13/r1 evidence, quarantine, workspace, candidate, or root is reused or inspected.

Approved command, executed once on 2026-09-12:

```text
/opt/homebrew/bin/node /Users/jonny/Desktop/github/agent-permission-guard/dist/src/cli/main.js graph genesis filesystem --audit-db /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/audit.sqlite --output /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/candidate.json --dashboard-state /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/dashboard.json --dashboard-port 0
```

The owner revalidates Node 26.3.1, npm tree 11.16.0, and darwin arm64. One launch permits only private preparation, owned containment probe, loopback listener/Dashboard, and pending audit records. Source emits the tokenized Dashboard URL to stderr as transient launch handoff; an observer may privately provide it to actual Google Chrome, confirm title/URL and one pending action, but never echo or persist token-bearing stderr in reports or diagnostic logs. The agent never clicks Approve. Failure to open Chrome never authorizes a second launch. Hidden ticket TTL is 120 seconds; overall/local-preparation/execution ceilings are 180/60/120 seconds. Effective execution time is the lesser of the execution ceiling and the remaining 180-second overall budget; approval never grants a fresh 120 seconds.

## Approval-gated consequence

Only personal Dashboard **Approve once** permits anonymous public npm metadata and one exact lock-only child for `@modelcontextprotocol/server-filesystem@2026.7.10`. Fixed arguments remain `--prefix=<workspace>`, `--package-lock-only`, `--save-exact`, `--save-prod`, `--maxsockets=4`, and `--ignore-scripts`; envelope binding covers host, boot, runtime, launch, workspace, DB, output, and Dashboard identity. No direct npm/npx or authority reuse is allowed. Limits remain 128 unique names, 256 requests, 4 active requests, 4 MiB response, 64 MiB aggregate, 10-second request, and discarded stdout/stderr capped at 256 KiB each. No queue, retry, credential, tarball/package-body download, installation, `node_modules`, lifecycle, package-code execution, import, activation, profile, materialization, or startup is allowed.

## Read-only outcome verification

Read only the new v14 DB for hash chain, action/envelope/plan identity, Authorization and Outcome receipts, bounded metadata counts, npm close/listener drain, and authenticated cleanup. Exact post-spawn terminal order is `graph_genesis_complete` or `graph_genesis_incomplete`, then `execution_completed`, then `outcome_receipt_finalized`, in the existing atomic transaction. Pre-spawn deny/expiry uses the existing blocked/not-started path and does not require that triple.

Success proof uses only `ProductionGraphGenesisTerminalProofSource.hasCompleteTerminalProof` with safe-result action/envelope/plan/candidate/artifact IDs plus bounded descriptor-bound candidate bytes/digest comparison. No importer API is called. At most one artifact needs exact manifest/protected-file and workspace-root lock evidence, with no legacy prefix. A compiler rejection permits exactly one authority-owned version-2 closed predicate containing only `diagnosticVersion` and `predicate`; no package identity, value, path, digest, or count is exposed. Candidate absence applies specifically to compiler rejection and approval expiry. An artifact written before later audit/cleanup failure may remain orphaned or unproven: never activate, delete, or claim it absent without evidence. Do not inspect quarantine. Audit failure is unknown unless bounded terminal-proof reconciliation succeeds; never fabricate terminal records or retry. Deny, expiry, and cancellation add no external work; only the existing authenticated owner cleans up. External metadata disclosure cannot be undone. Retain the fresh acceptance DB/evidence; operators do not delete it manually or inspect quarantine.

## Historical consumed approval request

```text
v14 Graph Genesis 실행을 정확히 한 번 승인합니다. 기준은 `d3e3ade`이며, 허용된 변경은 이 v14 문서, `PROJECT_STATE.md`, readiness 문서의 3개 문서 수정뿐이고 source/tests/dependencies/staging은 변경되지 않아야 합니다. 기존 의존성만으로 `./node_modules/.bin/tsc -p tsconfig.json` build를 실행한 뒤, `/private/tmp/apg-graph-genesis-live-acceptance-20260911-v14`를 no-follow/exclusive 0700으로 만들고, 동일 root 안에서 audit.sqlite를 no-follow/exclusive 0600으로 생성·재검증·schema [1,2] 초기화/검증합니다. 실행 명령은 다음 한 개뿐입니다: `/opt/homebrew/bin/node /Users/jonny/Desktop/github/agent-permission-guard/dist/src/cli/main.js graph genesis filesystem --audit-db /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/audit.sqlite --output /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/candidate.json --dashboard-state /private/tmp/apg-graph-genesis-live-acceptance-20260911-v14/dashboard.json --dashboard-port 0`. 시작 즉시 실제 Google Chrome에 tokenized local Dashboard를 비공개로 열고, 에이전트는 Approve를 누르지 않으며 사용자 본인의 Approve once 전에는 public DNS/HTTPS/npm child가 금지됩니다. Approve once 후에만 `@modelcontextprotocol/server-filesystem@2026.7.10`의 `--prefix=<workspace> --package-lock-only --save-exact --save-prod --maxsockets=4 --ignore-scripts` lock-only child와 128 names/256 requests/active 4/4 MiB response/64 MiB aggregate/10s request 제한을 허용합니다. 성공 candidate는 최대 1개이고 새 v14 candidate의 read-only digest/proof verification 및 bounded count만 읽습니다. compiler failure에서는 version-2 predicate 하나와 candidate absence, terminal/cleanup만 확인합니다. retry, prior evidence 접근, tarball/install/lifecycle/code 실행, candidate import/activation/profile/materialization/startup, commit/push는 허용하지 않습니다.
```

## Sources

- `src/stage/graph-genesis-live.ts` — limits, timeouts, and transient Dashboard handoff.
- `src/stage/graph-genesis.ts` and `src/stage/graph-genesis-hardening.ts` — fixed launch and bindings.
- `src/stage/exact-production-graph.ts` and `src/stage/graph-genesis-workspace.ts` — compiler diagnostics.
- `src/stage/graph-genesis-cleanup.ts` and `src/stage/graph-genesis-candidate-artifact.ts` — cleanup and proof.

## Observed v14 result

The approved root name was used once on 2026-09-12. The existing-dependency TypeScript build
passed. The private Chrome handoff succeeded and one pending action was confirmed without exposing
the token; the new v14 DB records local Dashboard approval status `approved`.

APG returned `incomplete` / `incomplete_external_read` with process exit 4. The npm lock-only child
completed with exit 0, 18 stdout bytes, and 156 stderr bytes. Its single private candidate
diagnostic was `diagnosticVersion: 2` and `package_peer_dependencies_rejected`; the exact offending
package identity remains deliberately undisclosed.

Metadata evidence records 126 requests, 117 unique packages, 126 validated responses, and
6,796,352 validated bytes, within the unchanged configured bounds. Read-only verification of the
new v14 DB passed: schemas `[1,2]`, valid hash chain, 275 events, valid Authorization and Outcome
Receipt bindings, terminal receipt status `execution_error`, error code `graph_lock_invalid`, and
the exact terminal order `graph_genesis_incomplete` → `execution_completed` →
`outcome_receipt_finalized`.

`lock_validation_started` and `post_state_validated` occurred, while no `candidate_compiled` or
candidate-output event occurred. Cleanup status was complete; `candidate.json` was absent and
`dashboard.json` had been removed. The audit DB remains private mode 0600 within the private mode
0700 root. No retry or prior evidence/quarantine access occurred.

The authenticated launch and post-state evidence support the existing no-installation and
no-package-download claims; this result does not add direct observation of tarball, download, or
`node_modules` absence. v14 is a safe, fully evidenced failure and does not establish successful
candidate acceptance. Proposed next work is an **Exact Candidate Peer Dependency Semantics
Architecture Check**, network-free only, before any source change or v15 run.
