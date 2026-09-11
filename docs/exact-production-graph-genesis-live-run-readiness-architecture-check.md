# Exact Production Graph Genesis Live Run Readiness Architecture Check

Status: accepted on 2026-09-09; initial readiness foundation committed at `7c15130`; production owner and
synthetic full-flow implementation committed and pushed at `592b286`; the pre-spawn cancellation classification
correction is committed and pushed at `31fd835`. One disposable first command attempt expired at Dashboard approval before
external read, npm, candidate output or package effect; its disarmed broker listener left the process live. The committed
correction drains that listener before Dashboard teardown. A separately approved disposable v2 run observed public
metadata and a lock-only npm child, then naturally exited through the conservative quarantine path (exit 5), with no
candidate or Dashboard-state output left behind. Its immutable audit evidence has six validated metadata requests and
four further starts without validation; it has no replayed terminal outcome. The correction committed and pushed
at `c0b48b6` latches the first broker failure in a one-time authenticated private summary, never writes
`genesis_incomplete` from the broker, and leaves the live owner to observe the process terminal and listener drain before
using the existing product terminal transaction. A separately approved v4 run verified that terminal sequence: after
10 metadata request starts and six validations, it observed npm cancellation, listener drain, one incomplete product
outcome and execution completion. The remaining `graph_metadata_invalid` cannot be attributed to the final four
transports from their intent records alone. Local route validation and reservation happen before intent logging:
a fifth concurrent request at the four-request limit can abort all four without getting its own intent record.
Three synthetic tests reproduce the same 10 starts, six validations and 644145 bytes via concurrency, route and
transport failures. They establish ambiguity, not the v4 root cause. The user-approved network-free implementation in
`graph-genesis-v5-private-diagnostics-design.md` adds owned predicate tags, nullable broker request ordinals and one
bounded local stderr line after terminal observation, listener drain and terminal audit attempt. Production checks and
receipt/audit schemas remain unchanged; no v5 run occurred.
Architecture-check baseline: `6108936` (`feat: add production graph genesis composition`).
Production-owner implementation baseline: `7c15130` (`feat: add fail-closed graph genesis readiness`).

## Decision summary

Add one closed production live-run entry point that owns the already reviewed Graph Genesis authorities from
input parsing through terminal reconciliation. The next implementation checkpoint is still network-free: it
may connect the exact production classes in source, but automated tests must use synthetic/local fixtures and
must never invoke the real entry point, system DNS, public HTTPS, npm CLI, the product audit database, or an
operator candidate path.

After that implementation is reviewed, committed, and pushed, one separately approved acceptance may invoke:

```text
apg graph genesis filesystem \
  --audit-db <existing-private-apg-audit.sqlite> \
  --output <absent-candidate.json> \
  [--dashboard-port <0-or-port>] \
  [--dashboard-state <absent-private-dashboard.json>]
```

The command first performs bounded local preparation. It then presents the exact live execution-envelope hash
in the local Dashboard. Only an unexpired `Approve once` decision for that envelope may arm the broker and
spawn the fixed npm lock-only process. Command invocation does not stand in for that Dashboard decision.

The first live target remains fixed:

```text
package: @modelcontextprotocol/server-filesystem@2026.7.10
registry: https://registry.npmjs.org/
platform: darwin arm64, exact freshly observed macOS build and boot session
Node: exactly 26.3.1
npm manifest/runtime tree: exactly 11.16.0
operation: metadata-only package-lock graph genesis
```

This approval never authorizes tarball download, `node_modules`, installation, lifecycle/package code,
profile registration, materialization, MCP startup, an MCP tool action, or direct npm/npx.

## Architecture-check scope at review time

Before acceptance, this document and its repository-state references were the only authorized changes. The
accepted implementation checkpoint authorizes source/tests/docs but no real execution. It does not authorize opening the
product audit DB, creating the operator output/state file, starting the Dashboard, executing the containment
probe, resolving DNS, contacting npm, spawning npm/npx, or writing a real candidate.

## Production-owner implementation checkpoint

The approved network-free checkpoint now connects the exact CLI grammar to one non-injectable production
owner. The owner internally constructs the runtime/host snapshot authorities, local containment listener and
probe, plan and execution envelope, existing-DB audit session, action-scoped Dashboard and one-time approval,
pinned public-metadata transport, lock-only npm supervisor, post-state/candidate/output authorities,
post-state-bound cleanup, atomic terminal commit and read-only terminal-proof reconciliation.

The phase machine is a closed, one-way sequence. Candidate output must be exclusively created, read back,
synced and durably audited before cleanup; cleanup must authenticate before the product terminal transaction.
If acknowledgement of that transaction is interrupted, the owner performs at most one read-only proof check
and never reruns npm or public transport. A post-spawn tree without authenticated post-state is quarantined;
the receipt and safe result expose only a digest reference, never the temporary path.

The owner-computed comprehensive runtime-manifest digest is a direct execution-envelope field and therefore
part of the Dashboard-visible execution-envelope hash; it is not replaced by the narrower plan runtime
snapshot subset. The production audit sink accepts preparation evidence only when the runtime, containment
and plan-ready digests exactly match that envelope. These records remain bounded digest-only projections.

The containment probe is now a compiled production-owned runtime asset under `dist/src/`, rather than a test
fixture. Default tests do not import or invoke the production owner. A separate synthetic twin exercises the
same exact phase order using fake in-memory metadata, one inert child marker, disposable private SQLite and a
temporary exclusive output. The complete network-free regression result is `290 passed, 3 skipped`.

The implementation does not itself authorize or perform the first live action. That acceptance still needs a
separate exact command/path approval and a personal Dashboard `Approve once` decision. No registry request,
npm process, product audit write, candidate output, installation, tarball, package body or package code was
used during this checkpoint.

## Current readiness gaps

| Current foundation | Live-run gap | Required closure |
| --- | --- | --- |
| production resolver, pinned HTTPS client, spawn adapter and authorities exist separately | no internal owner composes the concrete production objects | one non-injectable live owner constructs every production collaborator |
| product CLI has no `graph genesis` route | no exact input boundary or operator lifecycle exists | strict parser plus one fixed `filesystem` command; unknown/repeated options fail before effects |
| local preflight owns safe preparation but hardcodes an expired source baseline and always destroys its plan | it cannot be resumed or reused for a live action | reimplement the owned preparation inside the live owner and create a fresh non-exported plan |
| execution envelope binds DB/output/Dashboard identities | no live code captures all three in one session | capture exact identities, create one envelope, and reject every substitution or drift |
| production DB opener authenticates file/schema/chain tail | durability mode, sidecar policy and immediate writer ordering are not envelope evidence | require/record exact WAL/FULL/busy settings, private sidecars, integrity, and immediate transactions |
| Dashboard has `approval_audit_only` mode | its audit endpoint can expose unrelated product audit rows | add Graph-run mode restricted to the current action and no policy capability |
| normal dashboard-state writer may replace an existing path | live command could clobber unrelated state | require an absent path and exclusive private creation for this command |
| Dashboard close does not track sockets or enforce a bounded drain | a client connection can outlive terminal cleanup | track/close connections and invalidate the token within a bounded shutdown |
| broker and supervisor require the same two-phase lease | public constructors still permit standalone assembly | real entry point keeps all low-level objects private and exposes no general transport/process API |
| supervisor result includes `output_overflow` | receipt projection omits that observed status | add the status to the closed Graph Genesis receipt projection without broadening other adapters |
| generic `AuditCall` accepts regex-valid Graph event names | live path lacks a fully closed phase/event and total-byte budget | expose a typed Graph audit facade with exact ordering, per-event and per-action ceilings |
| generic `markExecutionResult` cannot select `incomplete_external_read` with detailed observed evidence | failure receipts can lose the important disclosure state | add a Graph-only terminal API with a closed terminal status and atomic detailed Outcome Receipt |
| legacy completion joins the old cleanup type and finalizes `genesis_complete` separately | it does not bind envelope, artifact write, new cleanup, and one atomic terminal transaction | add a production completion authority over all current evidence and one terminal commit |
| candidate writer syncs file bytes but not the parent directory and does not reread the final file | acknowledged success may outrun durable directory state or unnoticed write corruption | reopen/readback/hash the final file and fsync its parent before `candidate_output_written` |
| candidate importer accepts an injected terminal-proof interface | no production DB-backed proof authority exists | add an authenticated read-only proof source bound to the same exact DB/action/envelope/artifact |
| no terminal-acknowledgement reconciliation path exists | commit success followed by an interrupted acknowledgement is ambiguous | one read-only reopen/chain/action verification; never retry the action |
| post-state cleanup covers authenticated success inventory | arbitrary post-spawn failure state may not be safely deletable | initial-only cleanup before spawn; post-state cleanup after authentication; otherwise quarantine |
| safe operator result is not defined | exit code or stdout may overclaim success | closed local result schema and nonzero exit for every non-complete terminal state |

Any one of these gaps remaining keeps the real action unavailable.

## Observable success for the implementation checkpoint

The readiness implementation is complete only when network-free evidence shows all of the following:

1. exactly one internal production function owns input validation, runtime capture, temporary workspace,
   listener, containment probe, plan/envelope, audit, Dashboard, approval, broker, transport, process,
   post-state, compiler, output, cleanup, terminal receipt, reconciliation, and shutdown;
2. that function accepts only the closed operator paths/port and an AbortSignal and accepts no runtime,
   target, registry, command, option, limit, policy, transport, resolver, client, spawn adapter, clock,
   approval provider, audit sink, proof source, workspace, or cleanup injection;
3. the public CLI rejects malformed, relative, noncanonical, duplicate, conflicting, or unknown input before
   local probing or persistent writes and `--help` remains effect-free;
4. the production function is not invoked by the default test suite and a runtime tripwire proves zero real
   DNS, public sockets, npm spawn, product DB open, or operator output;
5. a separate synthetic full-flow owner exercises the same phase rules with fake metadata, an inert child,
   disposable private SQLite, temporary output, and no production capability;
6. a fresh plan and execution envelope bind every runtime, host, boot, workspace, listener, route, command,
   environment, limit, policy, Dashboard, DB, and output identity used by the action;
7. approval is durable before visibility and denial, expiry, cancellation, Dashboard loss, DB failure,
   envelope drift, lease replay, or signal arrival cannot arm or spawn;
8. every public-read-shaped request has a committed intent before fake transport and every accepted response
   has committed validation before relay;
9. child close, listener drain, broker ledger, post-state, candidate, output readback, cleanup, and terminal
   commit all agree on the same action/envelope/plan;
10. success emits one atomic `graph_genesis_complete` plus Outcome Receipt, and every other path emits a
    precise incomplete state where storage remains available;
11. an acknowledgement interruption performs one read-only reconciliation and never reruns npm or transport;
12. an orphan or copied candidate is rejected without exact DB-backed terminal proof; and
13. build, typecheck, whitespace checks, and the full default network-free suite pass with no dependency or
    migration change.

## Exact command surface

Accepted grammar:

```text
apg graph genesis filesystem
  --audit-db <absolute-canonical-existing-file>
  --output <absolute-canonical-absent-file>
  [--dashboard-port <0..65535>]
  [--dashboard-state <absolute-canonical-absent-file>]
```

Rules:

- `graph`, `genesis`, and `filesystem` are exact lowercase literals.
- `--audit-db` and `--output` are mandatory exactly once.
- `--dashboard-port` and `--dashboard-state` are optional at most once.
- Port `0` asks the OS for a free loopback port; a nonzero port must be at least 1024.
- There is no `--`, package specifier, registry, runtime, command, cwd, npm option, policy, TTL, limit,
  workspace, cache, proxy, credential, environment, resume, force, overwrite, or retry option.
- Paths must be absolute, normalized, canonical at the parent boundary, bounded in length, free of control
  characters, pairwise distinct, and not symlinks.
- The command never discovers a default product DB or searches the home directory.
- Usage errors return exit `64` before DB open, Dashboard start, temporary root creation, probe, DNS, or spawn.

The process working directory does not become an input. Runtime assets are resolved from the compiled module
location and exact built-in paths, never from `PATH` or the caller's project.

## Two distinct human authorization acts

The live workflow intentionally has two explicit local acts:

1. Invoking the exact command authorizes bounded local preparation: read-only runtime/host inspection, one
   private temporary workspace, opening the named existing DB, starting a loopback Dashboard/listener,
   optional exclusive state-file creation, local-only containment probes, and durable pending-action rows.
   It does not authorize public traffic or npm spawn.
2. Clicking `Approve once` authorizes only the consequence identified by the fresh execution-envelope hash:
   bounded anonymous public npm packument GETs through APG, the exact local npm lock-only child, disposable
   cache/lock/log writes, persistent audit events, and at most one new candidate file.

If Codex is asked to invoke the live command, the user must first approve the exact command and paths in chat,
then personally inspect and decide the Dashboard request. If the user invokes it directly, the Dashboard
decision remains mandatory. A chat approval never substitutes for the live Dashboard capability.

## Fixed npm execution profile

The live owner reconstructs and validates the existing fixed launch vector:

```text
/usr/bin/sandbox-exec -f <owned-profile>
<exact-node-26.3.1> --permission --allow-net
--allow-fs-read=<exact-npm-runtime>
--allow-fs-read=<owned-workspace>
--allow-fs-write=<owned-workspace>
<exact-npm-11.16.0-cli>
install @modelcontextprotocol/server-filesystem@2026.7.10
--package-lock-only --save-exact --save-prod --maxsockets=4 --ignore-scripts
--audit=false --fund=false --update-notifier=false --workspaces=false --bin-links=false
--allow-directory=none --allow-file=none --allow-git=none --allow-remote=none
--replace-registry-host=never
--registry=http://127.0.0.1:<owned-port>/<secret-route>/
--cache=<owned-workspace>/cache
--userconfig=<owned-empty-file>
--globalconfig=<owned-empty-file>
--prefix=<owned-workspace>
--logs-dir=<owned-workspace>/logs
--loglevel=warn
```

The shell is disabled, stdin is closed, the child is a detached process group, and its environment is built
only from `HOME`, `TMPDIR`, `LANG`, and `LC_ALL` pointing to or describing the owned workspace. No inherited
`PATH`, npm config, proxy, auth, HOME, credential, or user/project configuration reaches the child.

This example was updated to match current source, which now binds the prefix directly to the owned workspace
root. The former nested `prefix/` example reflected earlier behavior.

The exact child working directory is the owned temporary workspace, never the invocation directory. Capture
stdout/stderr byte counts only and discard raw chunks after enforcing the 256 KiB ceilings. Raw child output
is not printed, persisted, hashed, returned, or passed through pattern redaction; stable bounded failure codes
and counts are the only projections. This avoids treating best-effort secret-pattern matching as containment.

Before preparation, inspect environment key names only and fail closed if runtime/TLS behavior could have been
altered by keys such as `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `SSL_CERT_FILE`,
`SSL_CERT_DIR`, npm config variables, or proxy variables. Never read or report their values. System trust-store
integrity remains outside the claim.

`--package-lock-only` and `--ignore-scripts` are defense-in-depth, not the sole boundary. Seatbelt must permit
only the owned loopback port and workspace. The post-state must contain no tarball, `node_modules`, executable,
package body, or unknown file. The compiler rejects `hasInstallScript`, optional/bundled/platform behavior,
unsupported lock fields, disconnected/cyclic graphs, non-public tarball URLs, and non-SHA-512 integrity.

`--maxsockets=4` is a fixed npm 11.16.0 per-origin connection cap for the one loopback registry origin. It is
part of the authenticated launch digest, plan hash and Dashboard execution envelope; omission, substitution or
duplication fails closed during plan preparation. It aligns npm connection pressure with the unchanged broker
`concurrentRequests=4` cap, but it is not a separate proof of semantic HTTP request concurrency. No queue,
retry, fallback, broker-limit increase or response/aggregate/timeout relaxation accompanies it.

## Isolated temporary project

Every action creates one unpredictable current-user 0700 session root under canonical `/private/tmp` and an
exact `workspace` child. The workspace begins with only the fixed private package manifest, empty owned
`user.npmrc` and `global.npmrc`, containment profile, and empty bounded `cache`, `logs`, `tmp`, and `prefix`
directories. The manifest declares exactly the pinned Filesystem dependency. No existing user project,
repository working tree, home directory, npm cache, or config file is adopted or modified.

The persistent audit DB, optional Dashboard state, and candidate output are outside this disposable root and
are never deleted by workspace cleanup. Before spawn, revalidate the complete initial workspace identity.
After child close and listener drain, verify every changed file and directory against the closed allowed
inventory: the exact lockfile and bounded cache/log/tmp/prefix contents only. Any `node_modules`, archive,
package body, executable, link, hardlink, special file, unknown top-level entry, ownership/mode drift, or
protected-file replacement blocks success and causes quarantine rather than broad deletion.

## Owned runtime and build identity

The production owner must capture actual bytes, not trust a source commit label. Its runtime manifest covers:

- exact Node executable and complete npm runtime tree/CLI;
- the compiled live entry point, CLI parser, composition, broker/listener/transport, supervisor, containment,
  workspace/post-state/compiler, candidate/output/cleanup, approval, Dashboard, audit/receipt/DB modules;
- Dashboard web assets;
- package manifest and lockfile;
- exact SQLite JS/native runtime and existing migration files used only for schema identity;
- containment probe fixture and `/usr/bin/sandbox-exec`;
- `/usr/bin/sw_vers` and `/usr/sbin/sysctl` observation executables.

The manifest is bounded and explicitly reviewed. It does not hash the complete OS, dynamic libraries, kernel,
certificate store, Homebrew installation, or source repository. The eventual acceptance should run from a
clean committed build and record that commit as operator evidence, but file/tree digests—not Git cleanliness—
are the runtime authorization identity.

Any version, byte, inode, mode, owner, tree, host build, architecture, boot session, profile, workspace,
listener port, or route drift invalidates the plan. There is no fallback Node/npm/provider/path and no option
widening after a permission failure.

## Audit database and durability profile

The named audit DB must already exist. The live owner must:

- require a canonical regular 0600 current-user single-link file under a canonical current-user 0700 parent;
- refuse symlinks, hardlinks, missing files, auto-creation, default discovery, and migration;
- require the exact migrations `[1,2]` and exact supported tables/SQL;
- run SQLite integrity and complete APG hash-chain verification before creating the action;
- require exact `journal_mode=WAL`, set and verify connection-local
  `synchronous=FULL`, and bind the journal/synchronous/busy-timeout profile into the envelope;
- validate any existing WAL/SHM sidecar as a private current-user regular file and never treat it as workspace;
- use bounded `busy_timeout` and immediate transactions for chain-tail read plus every append;
- authenticate the live handle, main-file identity, schema digest, DB instance ID, initial chain tail, and
  durability-profile digest; and
- fail rather than switch DBs, create an in-memory sink, retry the action, or write an unchained side log.

Other APG writers may interleave after the Graph action is created. Every immediate transaction must read the
latest committed global tail, so interleaving is valid but chain forks are not. A lock timeout blocks the next
effect. The approval request itself is not visible until its row and event commit.

The live Graph audit facade owns a closed event union, exact payload keys/types, maximum 4 KiB canonical bytes
per ordinary event, maximum 1,024 Graph events, and maximum 2 MiB ordinary Graph event bytes. Receipt events
retain their existing independent schema limits. Raw metadata bodies, stdout/stderr, paths, route tokens,
environment values, bearer tokens, and credentials are never audit payloads.

## Dashboard and state handoff

Add a `graph_run` Dashboard mode with only:

```text
approvals
current_action_audit
health
```

Policy routes are absent. Audit queries are restricted to the one Graph action ID and cannot enumerate prior
product history. Host/origin/token/instance checks remain mandatory. The Dashboard shows the exact target,
registry, host/runtime versions, envelope/plan hashes, limits, audit/output paths, approval expiry,
consequences, exclusions, development-only containment warning, and direct-bypass warning.

Because the Dashboard instance ID is part of the envelope, the server starts in health-only unbound state.
After the bound audit session creates its action ID, the live owner binds that ID exactly once; only then may
the current-action audit route and pending approval become visible. Rebinding or querying while unbound fails.

The token is memory-only unless `--dashboard-state` is explicitly supplied. For this command, the state parent
must already be private and the file must be absent; create it exclusively as 0600 and never replace an
existing file. Its path/token are not envelope or receipt data. On every terminal path, close the approval
service, invalidate the token, close/force-close tracked Dashboard connections within a bounded deadline, and
remove only the exact owned state file. A replacement or ambiguous state file is preserved and reported
privately, not deleted.

## Live state machine and deadlines

```text
INPUT_VALIDATED
  -> LOCAL_RESOURCES_CREATED
  -> RUNTIME_SNAPSHOTTED
  -> CONTAINMENT_PROBED
  -> PLAN_READY
  -> AUDIT_SESSION_READY
  -> APPROVAL_PENDING
  -> AUTHORIZED
  -> BROKER_ARMED
  -> NPM_RUNNING
  -> LISTENER_DRAINING
  -> BROKER_FINALIZED
  -> POST_STATE_VALIDATED
  -> CANDIDATE_COMPILED
  -> OUTPUT_DURABLE
  -> WORKSPACE_CLEANED
  -> TERMINAL_COMMITTED
  -> COMPLETE

deny / expiry / pre-dispatch cancel       -> NOT_STARTED
failure before public transport           -> FAILED_NO_EXTERNAL_READ
failure after request intent/transport    -> INCOMPLETE_EXTERNAL_READ
ambiguous child or listener state         -> INCOMPLETE_EXECUTION_UNKNOWN
untrusted post-state or cleanup ambiguity -> INCOMPLETE_QUARANTINE
terminal storage failure                  -> INCOMPLETE_AUDIT_FAILED
terminal commit acknowledgement unknown  -> RECONCILING -> COMPLETE | OUTCOME_UNKNOWN
```

One idempotent abort owner is registered before the first await and latches the first failure. It rechecks
after every audit, probe, revalidation, listener, approval, transport-drain, process, filesystem, fsync, and
reopen operation and immediately before broker arm, listener exposure, spawn, compile, output creation,
cleanup, and terminal commit.

Preparation is bounded to 60 seconds before the plan. The freshly captured plan has a 180-second pre-start
lifetime, the approval request has a fixed 120-second TTL, and both broker arm and spawn must occur no later
than 15 seconds after approval and before the plan/request deadline. Process execution is bounded to 120
seconds from actual spawn. Listener drain, TERM/KILL, Dashboard close, cleanup, and reconciliation each have
their own smaller bounded deadlines and cannot turn an incomplete result into success.

SIGINT/SIGTERM cancel the pending request before dispatch or trigger the same abort owner after dispatch.
There is no resume. SIGKILL, power loss, or host crash may leave temporary state and are reported as residual
limits; a later command never adopts the old plan or automatically deletes ambiguous residue.

## Exact execution and terminal ordering

Required durable action order:

```text
decision_recorded
graph_genesis_session_created
graph_genesis_runtime_snapshot_complete
graph_genesis_containment_probe_complete
graph_genesis_plan_ready
approval_requested
approval_approved | approval_denied | approval_expired | approval_cancelled
[approved] graph_genesis_approved_revalidation_complete
[approved] authorization_receipt_finalized
[approved] graph_genesis_authorization_finalized
[approved] graph_genesis_execution_authorization_finalized
[approved] graph_genesis_execution_broker_armed
[approved] graph_genesis_execution_npm_spawn_intent_recorded
[spawned] execution_start_recorded
[spawned] graph_genesis_execution_npm_spawn_started
[repeated] graph_genesis_execution_metadata_request_started
[repeated] graph_genesis_execution_metadata_response_validated
graph_genesis_execution_npm_terminal_observed
graph_genesis_execution_listener_drained
graph_genesis_execution_lock_validation_started
graph_genesis_execution_post_state_validated
graph_genesis_execution_candidate_compiled
graph_genesis_execution_candidate_output_intent
graph_genesis_execution_candidate_output_written
graph_genesis_execution_cleanup_complete
graph_genesis_complete + execution_completed + outcome_receipt_finalized  # one transaction
```

Do not call the legacy terminal `GraphGenesisAuditGate.finalizeSuccess` in the production live path if it
would emit a separate `genesis_complete`. The production completion authority first authenticates every
nonterminal result and then invokes one Graph-specific terminal transaction.

The Graph-specific terminal API accepts only a closed summary and terminal status. It must preserve request,
unique-name and response-byte counts; external-read status; child status/exit/output byte counts including
`output_overflow`; lock/candidate/artifact digests; cleanup/quarantine status; and terminal audit status.
For failures with durable storage, it atomically records `graph_genesis_incomplete`, `execution_completed`,
and the detailed Outcome Receipt. A failed terminal write never produces an alternate success record.

## Listener, transport and child composition

The live owner constructs exactly:

```text
SystemRegistryAddressResolver
  -> NodePinnedHttpsClient
  -> BoundedNpmPublicMetadataTransport
  -> HardenedMetadataBrokerAuthority
  -> HardenedLoopbackBrokerListener

NodeGraphGenesisSpawnAdapter
  -> GraphGenesisProcessSupervisor
```

No constructor input can substitute any item. The listener binds only `127.0.0.1` on its owned port and stays
disarmed until authorization. The broker alone constructs `https://registry.npmjs.org/<canonical-name>`,
rejects mixed/non-public DNS results, pins one public address while retaining npm-hostname TLS, sends fixed
anonymous headers, refuses redirect/decompression, and bounds time/bytes/concurrency.

The child can reach only its exact loopback broker under the freshly proven Seatbelt profile. A tarball URL,
unknown route, body, query, credential header, noncanonical name, excess request, or permission behavior
aborts the whole action. No request is retried under the approval.

Success requires child close, zero outstanding handlers/sockets/requests, a complete broker ledger, and exact
matching package names between ledger and compiled graph. Exit zero alone is never success.

## Candidate output durability and proof

The output parent must already exist as a canonical 0700 current-user directory; the output must be absent.
Capture the parent device/inode/owner/mode before approval and revalidate it immediately before writing.

After candidate compilation:

1. commit `candidate_output_intent`;
2. create a random same-parent pending file with exclusive no-follow 0600 semantics;
3. write bounded canonical bytes, fsync, close, and verify pending identity/length;
4. publish without overwrite only while the final name is absent and parent identity matches;
5. reopen the final file with `O_NOFOLLOW`, read it completely, verify canonical bytes and artifact digest;
6. fsync the parent directory and revalidate final link count/identity;
7. commit `candidate_output_written` with digests and byte count only.

If any later cleanup or terminal audit step fails, the file is an orphan candidate. It may remain for review
but the production importer rejects it unless the same authenticated DB contains a complete matching action,
`graph_genesis_complete`, and Outcome Receipt for action ID, envelope, plan, candidate and artifact digests.
Self-digest, filename, copied JSON, callback injection, or a receipt from another DB is insufficient.

The candidate is public dependency-graph evidence, not a trusted profile, package-safety verdict, artifact
acceptance, materialization authority, launch authority, or signed receipt.

## Cleanup and quarantine

Before spawn, cleanup may remove only the still-authenticated initial workspace inventory. After spawn,
automatic cleanup requires authenticated post-state plus a complete current inventory. Every entry and
ancestor is checked without following links immediately before unlink/rmdir. Broad recursive deletion,
foreign-root adoption, glob deletion, and cleanup of audit/output/state parents are prohibited.

If the child/listener did not terminate cleanly, post-state cannot be authenticated, or any unknown, link,
hardlink, special file, ownership, mode, inode, ancestor, or inventory drift exists, preserve the workspace as
quarantine. The portable evidence stores only a digest of the recovery reference; the exact path may be shown
only on the local terminal. Quarantine is never reported as rollback or success.

Public registry disclosure and audit/candidate persistence cannot be rolled back. No automation claims to
undo registry logs, cache exposure to another same-user process, process descendants after an unclean close,
or external effects from future package code.

## Terminal acknowledgement and reconciliation

The success transaction acknowledges only after SQLite commit. If the call returns success, close and reopen
the named DB read-only and verify the complete chain plus the exact action/envelope/artifact terminal record
before the CLI reports `complete`.

If commit acknowledgement throws or the process is interrupted around terminalization:

- never rerun transport, npm, output write, cleanup, approval, or the terminal transaction;
- close the write handle where possible;
- reopen once read-only through the authenticated Graph terminal-proof/reconciliation source;
- report `complete` only if the exact atomic success record is present and valid;
- otherwise report `outcome_unknown_after_interruption`, reject candidate import, and preserve evidence.

An unavailable or invalid DB after public disclosure is `audit_failed` locally. Absence of a durable outcome
cannot be repaired by stdout, an in-memory object, a second DB, an unsigned side file, or user assertion.

## Closed operator result and exit behavior

The command emits one bounded local result without route token, Dashboard token, raw metadata, raw output,
environment, boot identifier, file identities, child arguments, or receipt bodies. It may include:

```text
status
action ID if durably created
execution-envelope / plan / candidate / artifact digests
external-read status and bounded counts
process status, exit code and stdout/stderr byte counts
cleanup status and private recovery path only on the local terminal
terminal-audit status
candidate output path only on the local terminal
direct npm/npx bypass warning
```

Exit codes:

```text
0   complete and read-only reconciliation verified
2   not started: denied, expired or cancelled before dispatch
3   failed with no external read started
4   incomplete external read or execution state
5   cleanup quarantine
6   audit failure or outcome unknown
64  command usage/input rejection
```

Every nonzero status is non-authoritative. The CLI does not automatically retry or delete preserved evidence.

## Data-flow and privacy statement

```text
operator paths
  -> local validation and private identity digests
  -> exact local Dashboard view

fixed npm child
  -> secret loopback route
  -> APG broker
  -> anonymous HTTPS GET for canonical public package names
  -> bounded packument bytes in memory
  -> npm lockfile in private workspace
  -> strict public graph candidate
  -> private operator candidate file

safe event projections
  -> named existing local SQLite audit DB
  -> portable unsigned Authorization/Outcome Receipt
```

The npm registry can observe source IP, timing, hostname and requested public package names. APG intentionally
persists public package/version/tarball URL/integrity graph evidence in the candidate. It does not send or
persist the route token, Dashboard token, credentials, user/project config, inherited environment, raw
packuments, raw stdout/stderr, private workspace path, or file contents outside the candidate's public graph.

The product DB may already contain unrelated local audit data. Graph-run Dashboard mode must not expose it.
The DB remains local; no audit or receipt is uploaded by this action.

## Failure matrix

| Failure point | Required result | Candidate authority |
| --- | --- | --- |
| invalid input, runtime, output/audit/state identity | no Dashboard approval and no public read | none |
| containment negative probe unavailable or unexpectedly allowed | fail closed; exact workspace cleanup/quarantine | none |
| DB chain/schema/durability/lock failure before request | no visible request | none |
| Dashboard/state creation failure | no approval and no spawn | none |
| deny/expiry/cancel/Dashboard loss | blocked Authorization Receipt where possible; initial cleanup | none |
| revalidation or lease deadline failure | no arm/spawn; approval consumed | none |
| audit failure before transport/spawn | effect blocked | none |
| DNS/TLS/status/type/redirect/body/JSON/name failure | abort; external read may have occurred | none |
| unexpected tarball/route/permission or npm nonzero | abort and inspect only for quarantine decision | none |
| timeout/cancel/output overflow/child-close uncertainty | terminate group; incomplete execution | none |
| listener/handler/request drain uncertainty | incomplete; no post-state success | none |
| lock/post-state/compiler mismatch or lifecycle flag | incomplete/quarantine | none |
| output collision/write/readback/fsync failure | incomplete; preserve ambiguous file | none |
| cleanup ambiguity after valid output | orphan candidate plus quarantine | rejected without terminal proof |
| terminal commit fails | audit failed; no alternate record | rejected |
| commit acknowledgement uncertain | one read-only reconciliation | only if exact success is proven |
| SIGKILL, power loss, host crash | later manual review; no resume/adoption | rejected unless exact terminal proof exists |

## Network-free implementation test strategy

- exact CLI parsing: missing/duplicate/relative/noncanonical/overlapping paths, unknown options, ports and help;
- production entry-point source/runtime tripwires proving no collaborator injection and zero invocation in tests;
- complete synthetic full flow with one approve-once, disposable DB/output, fake transport and inert child;
- deny, expiry, cancellation, Dashboard close/rotation, copied approval and envelope/lease replay;
- cancellation before and after every await and immediately before arm, listener exposure, spawn, output,
  cleanup and terminal commit;
- runtime/build/host/boot/workspace/profile/listener/route/policy/DB/output drift and substitution;
- action-scoped Dashboard authorization, origin/host/token checks, current-action audit filter, no policy route,
  exclusive state file and bounded socket drain;
- production DB opener schema/chain/integrity/WAL/FULL/busy/sidecar checks using only disposable DBs;
- concurrent/interleaved immediate audit writes without chain fork, plus busy/full/commit/ack/reopen failures;
- typed Graph event ordering/count/byte limits and privacy canaries;
- resolver/client/transport construction guards, with injected DNS/local TLS tests only;
- supervisor authorization, exact single spawn, timeout/cancel/TERM/KILL/output-overflow/child-close cases using
  repo-owned inert children only;
- request reservation, late response, listener drain and broker ledger terminal races;
- strict post-state, lifecycle/unsupported-lock rejection, graph/ledger mismatch and candidate authority;
- output collision, symlink/hardlink/parent replacement, short write, readback mismatch, fsync failure and
  orphan cross-action/cross-DB import rejection;
- initial/post-state cleanup and quarantine under entry/ancestor replacement;
- success/failure Outcome Receipt 1.2 golden fixtures, `output_overflow`, incomplete external read, quarantine,
  audit failure and acknowledgement reconciliation;
- safe result/exit-code mapping and direct-bypass disclosure; and
- full build/typecheck/network-free regression with a static guard against product DB, public network, npm/npx,
  package download/install/code, real candidate output, publish, push, or credential/config reads.

Automated tests may use local loopback and disposable private files. They must not resolve a public hostname,
connect to a public/LAN address, invoke real npm/npx, open the user's product audit DB, or write the eventual
operator output.

## Exact one-time acceptance strategy after implementation

The later acceptance is not included in implementation approval. Before it:

1. review the exact implementation diff and commit it;
2. require clean `main` equal to `origin/main` and record the commit;
3. run the unchanged full network-free suite and typecheck;
4. choose and display the exact existing audit DB, absent output path and optional absent state path without
   reading credential/config contents;
5. verify only path ownership/mode/existence and current runtime versions;
6. present the exact command for separate approval;
7. start the command once, open only its tokenized loopback Dashboard, and let the user inspect the live
   envelope and click `Approve once` or Deny;
8. do not retry a failed or expired action; create a fresh plan and seek a new decision;
9. preserve the product audit and successful candidate; clean only authenticated temporary state; and
10. verify the returned status, full chain, action-scoped Authorization/Outcome Receipt and candidate terminal
    proof without downloading artifacts or starting package code.

The acceptance report must include exact commit, action/envelope/plan/candidate/artifact digests, safe bounded
counts, exit status, cleanup status, terminal proof, and any quarantine/recovery reference. It must explicitly
state whether an external read may have occurred.

## Approval boundaries

| Boundary | Authority | Permitted consequence | Explicitly excluded |
| --- | --- | --- | --- |
| this Architecture Check | current conversation approval | repository analysis and docs | implementation or execution |
| readiness implementation | separate architecture acceptance | source/tests/docs; disposable DB/output; fake transport/inert child/local-only probes | product DB, public DNS/registry, real npm, real candidate |
| command invocation | exact local operator action or exact chat command approval | bounded local preparation, named DB pending rows, loopback Dashboard/listener, private temp/state | broker arm, public read, npm spawn |
| live `Approve once` | exact envelope hash in current Dashboard | bounded public packument GETs, fixed lock-only npm process, named audit/output consequences | tarball, install, code, profile, stage, startup |
| candidate review | explicit later review | inspect public graph evidence | metadata refresh or download |
| exact metadata confirmation | separate candidate-bound approval | listed metadata GETs | graph resolution change or artifact bytes |
| artifact acceptance | separate graph/artifact-bound approval | exact tarball downloads and bounded read-only inspection | materialization or code |
| profile registration | reviewed source change | repository profile data | download, materialization or startup |
| materialization | exact accepted artifacts/stage approval | private stage writes | startup |
| startup | exact sealed-stage approval | one MCP process | MCP action or download |
| MCP action | existing APG-routed policy/approval | one exact tool call | direct bypass or restart |

Actual installation has no approval in this Architecture Check or live Graph Genesis. Package download and
registry metadata access remain separate boundaries. Direct npm/npx bypasses APG and receives none of these
protections or receipts.

## Risks, mitigations and residual limits

| Risk | Mitigation | Residual limit / release blocker |
| --- | --- | --- |
| approval applies to changed execution | complete envelope plus repeated authority revalidation and one-use lease | any unbound behavior blocks live run |
| standalone production adapter bypasses owner | no injectable live constructor; private composition and runtime tripwires | exported low-level classes remain internal-building blocks, not user authority |
| approval token exposes unrelated audit | action-scoped Graph Dashboard mode | same-user bearer theft remains possible during short lifetime |
| audit chain forks or terminal outcome is ambiguous | immediate transactions, FULL durability profile, read-only reconciliation | disk/controller failure and DB-owner rewrite remain possible |
| output survives without terminal audit | final readback/fsync plus DB-backed terminal-proof importer | orphan file can remain and needs manual review |
| cleanup deletes foreign state | initial/post-state inventories, ancestor identity checks, quarantine | hostile same-user races are outside the guarantee |
| public metadata is malicious | strict byte/JSON/name/lock/compiler bounds and no code/tarball | registry and publisher honesty are not proven |
| npm changes request/file behavior | exact runtime/args and abort on every unexpected effect | compatibility is unknown until the one live acceptance |
| deprecated/private Seatbelt changes | exact host/provider snapshot and fresh complete negative probe; no fallback | unsupported provider or failed negative test blocks the run |
| DNS/TLS destination substitution | reject any mixed/non-public set, pin address, retain npm-hostname TLS | compromised public DNS/registry/trusted root remains outside proof |
| output contains secrets | empty-built child env, no user/project config, public-graph-only schema | arbitrary same-user memory inspection remains outside scope |
| lifecycle risk is understated | no tarball, `--ignore-scripts`, post-state no package bytes, compiler rejects install-script evidence | later artifact/materialization/startup require independent reviews |
| receipt sounds cryptographically final | `portable_unsigned_local_candidate` and explicit limitations | signing, attestation and external anchor remain future work |
| interruption leaves state | no resume/adoption, bounded shutdown, proof-gated candidate, manual quarantine | SIGKILL/power loss may leave private residue |

The strongest claim after a successful live acceptance is narrow: this exact local APG build observed and
recorded one bounded public metadata graph under one fresh local approval. It does not prove package safety,
publisher identity, source/build equivalence, future artifact bytes, kernel integrity, verified human identity,
hostile same-user containment, independent audit immutability, or install/startup safety.

Apple Feedback and macOS notarization investigation remain independent and are neither blocked nor changed by
this work.

## Readiness implementation scope requested

After explicit acceptance, implement only:

1. exact CLI parser and closed production live owner;
2. owned live preparation/runtime manifest and private temporary-session root;
3. exact audit durability profile, typed Graph facade, detailed terminal API and read-only reconciliation;
4. action-scoped/bounded Dashboard and exclusive state handoff;
5. full broker/listener/transport/supervisor/post-state/candidate/output/cleanup/completion composition;
6. candidate final readback/parent fsync and production DB-backed terminal-proof source;
7. safe result/exit mapping, signal/shutdown handling and documentation; and
8. network-free synthetic/adversarial tests only.

Do not add dependencies or migrations. Do not run the new production entry point. Do not open the user's
product DB, resolve public DNS, contact npm, spawn real npm/npx, create a real candidate/state file, download
an artifact, install a package, run package code, register a profile, materialize a stage, publish, or push.
Commit/push remains a later explicit approval.

## Implemented network-free readiness foundation

The first accepted implementation tranche now closes the effect-free public boundary and the reusable
durability/evidence primitives needed by the later owner:

- the exact `apg graph genesis filesystem` grammar rejects duplicate, unknown, relative, non-normalized,
  colliding and invalid-port inputs before effects;
- at the `7c15130` readiness-foundation checkpoint, the public route performed private-path and
  environment-key readiness checks and then returned a stable nonzero `live_execution_not_enabled` result,
  with zero DB open, file creation, listener, DNS, registry or process capability; the later local owner
  connection described above supersedes that temporary route while remaining uninvoked and separately
  approval-gated for any live action;
- the existing audit DB profile now requires WAL, connection-local FULL synchronous mode, a bounded busy
  timeout, integrity success and private sidecars, and binds a durability digest into the envelope;
- Graph writes use immediate transactions; the typed Graph audit gate enforces the exact event schema plus
  4 KiB per-event, 1,024-event and 2 MiB total ceilings;
- Graph terminalization has a closed status/summary API that atomically writes one complete/incomplete event,
  detailed execution evidence and one Outcome Receipt; generic terminalization is rejected for this boundary;
- receipt 1.2 represents `output_overflow` and preserves incomplete-external-read state;
- `graph_run` Dashboard mode is health-only before one immutable action binding, restricts audit and approval
  read/decision access to that action's envelope, exposes no policy route, invalidates its token and bounds
  connection shutdown;
- optional Graph Dashboard state uses exclusive 0600 creation under an existing canonical 0700 parent and
  never replaces a path;
- candidate publication rereads and parses the final no-follow file, revalidates its descriptor and parent,
  fsyncs the parent directory, and only then acknowledges the write; and
- the production terminal-proof source reopens the exact private DB read-only, verifies the complete hash
  chain, action/envelope binding, unique ordered terminal events, Outcome Receipt digest and candidate/artifact
  digests before accepting a candidate.

This foundation was committed at `7c15130`; the subsequent approved local checkpoint joins its runtime/host/
workspace capture, Dashboard/audit session, approval, concrete broker/transport/supervisor,
post-state/compiler/output/cleanup, terminal commit and acknowledgement reconciliation behind one
non-injectable public route. The owner has not been invoked, so this is still not a live acceptance and does
not authorize the real action.

Suggested acceptance:

```text
Exact Production Graph Genesis Live Run Readiness Architecture Check 승인 — network-free live composition 및 fail-closed readiness 구현 진행
```

## Rollback

Before implementation acceptance, remove this document and restore its scoped `ARCHITECTURE.md` and
`PROJECT_STATE.md` references. No runtime, dependency, DB, Dashboard, output, network, package, credential,
external service, commit, or remote state changed in this Architecture Check.

## Next

Review the exact local production-owner diff, tests and residual risks, then request separate commit/push
approval. Only after a clean pushed checkpoint may an exact one-time live acceptance command and Dashboard
decision be proposed.
