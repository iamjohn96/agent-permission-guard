# Exact Real Metadata-only Graph Genesis Plan Architecture Check

Status: accepted on 2026-09-08. The approved network-free production-adapter hardening is implemented and
verified locally. No real npm/npx execution, public DNS or registry request, artifact byte, package
installation, materialization, production-profile registration, package startup, dependency change,
database migration, commit, or push occurred.

## Decision summary

Do not connect the current network-free foundation directly to a real npm process. Insert one additional
network-free hardening checkpoint that creates production-shaped but still inert adapters, closes the known
authority and concurrency gaps, and proves the complete state machine against repo-owned local fixtures.

Only after that checkpoint is reviewed may APG prepare a fresh, concrete one-time plan for:

```text
target: @modelcontextprotocol/server-filesystem@2026.7.10
generator: npm 11.16.0 under Node 26.3.1
external consequence: bounded anonymous public packument GETs
local consequence: disposable metadata-only package-lock/cache/log writes
explicitly prohibited: tarball, node_modules, lifecycle/package execution, installation, materialization
```

The later real approval must identify the exact plan hash and displayed safe projection. It expires if any
runtime, OS, provider, workspace, listener, route, transport, command, limit, or self-test evidence changes.

## Network-free implementation result

The accepted checkpoint now provides separate safe-plan/private-capsule authority, authority-owned file and
tree snapshots, owned Node/npm version observation, a finalized private workspace, a real local-only
Seatbelt probe runner, a disarmed exact-loopback listener, pinned-address bounded HTTPS transport, atomic
broker reservations with session-wide abort, a bounded process-group supervisor, strict post-state
inspection, lock-bound candidate compilation, no-follow cleanup evidence, durable ordered audit gating, and
a final all-authorities-must-agree completion join.

Synthetic adapters are fixed when their owning authorities are constructed and cannot be substituted into a
production-mode broker or plan. The full network-free suite passes 242 tests with 3 skips; the focused
hardening suite passes 16 tests, including the real local-only host, containment, and memory-only TLS probes.
The production audit sink, fresh exact host plan, public DNS/registry read, and real npm launch remain
deliberately unimplemented or unexecuted pending their separately named approvals.

## Why a hardening checkpoint is mandatory

Commit `3d5bbd5` establishes the intended schemas and network-free proof shape. It deliberately has no public
listener, HTTPS adapter, process supervisor, or durable product audit integration. Review for real-run
readiness also identified these release blockers:

| Gap | Why it blocks a real run | Required closure |
| --- | --- | --- |
| raw route token occurs in the internal launch argument array held by the plan | the architecture promised digest-only plan/public evidence | separate public immutable plan from private execution capsule; never log/export the token |
| broker runtime digest and `sandbox-exec` hash are caller-provided strings | a self-consistent caller can assert an unobserved runtime | authority-owned regular-file/tree snapshots only |
| containment observations are accepted as booleans | a caller can claim a probe ran | probe runner owns execution and authenticates exact observed transcript |
| approval/audit implementations are synthetic concrete classes | they cannot establish production authority | narrow production interfaces plus separately named synthetic implementations |
| broker request and unique-name ceilings are checked before concurrent reservations | concurrent requests can oversubscribe limits | atomically reserve request/name/byte budgets before transport |
| one failed request does not abort all outstanding transports | bytes may arrive after terminal failure | session-wide abort controller, generation check, and terminal latch |
| ledger records only successful responses | durable evidence is absent before external reads | audit `metadata_request_started` before transport; failure blocks the request |
| no loopback HTTP server exists | npm cannot use the authority-owned grammar | exact `127.0.0.1`, random high port, disarmed-by-default listener with bounded parser |
| no bounded production HTTPS transport exists | a full in-memory body could be allocated before validation | streaming byte ceiling, deadline, exact status/type/final URL, redirect refusal |
| registry DNS destination is not pinned and classified | exact hostname alone does not prove the socket avoided local/private targets | authority-owned lookup, reject non-public addresses, connect to the selected address with npm hostname SNI/Host |
| no graph-genesis process supervisor exists | timeout/cancel/output overflow/descendants are not tied to broker failure | detached process group, bounded streams, terminal latch, TERM/KILL, child-close requirement |
| workspace cleanup uses a broad recursive primitive after only root revalidation | unexpected residue/replacement can make deletion ambiguous | descriptor-oriented inventory, child termination first, no-follow leaf cleanup, quarantine on ambiguity |

These are not reasons to discard the foundation. They are the exact boundary between a useful model and an
authorized real external read.

## Observable success for the next network-free checkpoint

The hardening implementation is complete only when all of the following are demonstrated without contacting
DNS, npm, a registry, a LAN peer, or any public address:

1. a public `GraphGenesisPlanProjection` contains no route token, private path, raw output, file identity,
   package metadata body, credential, or environment value;
2. a private `GraphGenesisExecutionCapsule` owns the token and absolute paths, is memory-only, is
   authority-authenticated, and matches the public plan digests;
3. Node, npm tree, broker runtime, containment fixture, and `sandbox-exec` identities come only from owned
   snapshot authorities and are revalidated before probe and spawn;
4. an owned probe runner, not caller-provided booleans, produces the containment evidence;
5. the loopback listener rejects before authorization and accepts only exact canonical GETs after a one-time
   authorization has been durably recorded;
6. request/name/concurrency/body/aggregate/time/output/file budgets cannot be exceeded through concurrent
   scheduling or replay;
7. the first failure disarms the listener, aborts every outstanding fake transport, prevents further ledger
   commits, terminates the inert child group, and produces one terminal state;
8. every external-read-shaped fake request has a durable pre-request event before the injected transport is
   called and a validated-response event before bytes are relayed;
9. production-shaped transport tests use only local TLS fixtures and injected DNS results, including private,
   loopback, link-local, multicast, unspecified, documentation, and mixed-address rejection;
10. the process supervisor runs only an inert repo-owned fixture under the exact private capsule, including
    timeout, cancel, TERM/KILL, stdout/stderr overflow, permission denial, and spawn failure;
11. workspace validation and no-follow cleanup reject substitution, archive/package content, executable or
    linked residue, unknown roots, lock replacement, and audit/cleanup ambiguity; and
12. default full tests remain network-free and the real npm executable is never spawned.

## Authority model

Use interfaces at the real orchestration boundary:

```text
RuntimeSnapshotAuthority
  -> Node/npm/broker/probe/provider authenticated identities

ContainmentProbeAuthority
  -> exact locally observed probe evidence

GraphGenesisPlanAuthority
  -> public plan + matching private execution capsule

GraphGenesisApprovalAuthority
  -> one-time production authorization for one plan hash

GraphGenesisAuditAuthority
  -> durable ordered pre/post evidence and terminal result

MetadataBrokerAuthority
  -> listener session + validated terminal ledger

GraphGenesisProcessAuthority
  -> exact supervised npm terminal observation

GraphGenesisWorkspaceAuthority
  -> exact post-state + cleanup/quarantine evidence

ExactGraphCandidateAuthority
  -> closed lock compiler result

ControlledGraphGenesisAuthority
  -> final candidate/report only when every preceding authority agrees
```

Synthetic providers implement the same narrow interfaces but remain explicitly test-only. A production
orchestrator constructor must reject a synthetic provider through an implementation-kind brand. Tests may
exercise synthetic orchestration; no synthetic result can be passed to a real execution entry point.

## Public plan and private capsule

The immutable public plan binds only safe values and digests:

```text
plan version and random plan ID
exact target name/version
registry origin
darwin/arm64, macOS build, Node/npm/provider versions
Node/npm/broker/provider/probe/profile/workspace/launch/environment digests
broker address + port + route-token digest
all resource ceilings
consequence = bounded_public_metadata_graph_genesis
plan hash
```

The safe approval projection additionally displays:

```text
public package target
public registry origin
metadata-only statement
maximum package names, requests, bytes, concurrency, request time, total time
private temporary file classes
explicit no-artifact/no-install/no-execution statement
direct npm/npx bypass statement
development-only containment statement
```

The private capsule contains the route token and exact absolute paths required for launch. It is never
serialized into audit, Dashboard state, receipt, report, docs, stdout/stderr, or error text. The plan hash
binds capsule field digests, not the raw token or private paths. The child necessarily receives the token in
its local registry URL; this is a same-host ephemeral capability and remains visible to sufficiently
privileged process inspection. Same-user hostile inspection is outside v0 containment and must be disclosed.

## Runtime and provider snapshots

Capture and authenticate:

- exact Node executable regular-file identity and SHA-256;
- complete bounded npm runtime tree and exact CLI entrypoint;
- graph-genesis broker/listener/transport/orchestrator compiled runtime files;
- containment probe fixture/runtime files;
- `/usr/bin/sandbox-exec` identity and SHA-256;
- exact macOS build and architecture; and
- diagnostic Node linked-library list, clearly outside the complete provenance claim.

Caller-supplied digests are never accepted. Snapshot errors contain only stable codes. Revalidate before the
containment probe and immediately before child spawn. Any drift destroys the capsule and requires a new plan.

Current read-only diagnostics, not reusable plan evidence:

```text
macOS 26.6.2 build 25G83, arm64
Node 26.3.1
Node SHA-256 56694c81b093cc8da273fa017cf91765b3653e5f64f16727976ffaa87b2b6b31
npm 11.16.0
npm CLI SHA-256 8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7
sandbox-exec SHA-256 abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a
repository commit 3d5bbd5
```

## Containment probe

The owned probe runner executes the repo fixture itself and parses one closed bounded result. It binds the
exact Node executable, probe file, workspace, profile, port, macOS build, and provider snapshot. Required
observations remain:

- approved IPv4 loopback port connects;
- another IPv4 loopback port is denied;
- current non-loopback local-interface listener is denied;
- IPv6 loopback is denied;
- outside-root write, child process, worker, and addon grants are denied; and
- no DNS, public, or LAN destination is attempted.

If no non-loopback interface is available, the exact real plan is unavailable. A test-only synthetic result
cannot replace this observation. Probe success is single-plan and expires on reboot, OS/build/runtime/profile/
port/workspace change or any later snapshot drift.

## Loopback listener

The server must:

- bind an OS-selected high port on exact `127.0.0.1`, never wildcard or IPv6;
- start listening while disarmed so its port can be planned and tested;
- use a random 128-bit route token, constant-time exact route comparison where practical, and no route hints;
- set strict header count/size, request-line, socket, keep-alive, headers, and request timeouts;
- reject bodies, upgrades, CONNECT, absolute-form URLs, duplicate security-sensitive headers, queries, and
  every method/endpoint outside the canonical grammar;
- never forward arbitrary inbound headers;
- return bounded generic local errors without reflecting the route or request; and
- close idle/active connections before terminal ledger authentication.

The route token is defense against accidental/same-user local cross-talk, not process identity. The exact
Seatbelt destination restriction is the primary npm egress boundary.

## Broker reservations and session-wide failure

Before transport invocation, reserve atomically within the single event loop:

```text
request sequence
unique package name slot
concurrency slot
maximum possible response-byte budget
```

Use started/reserved counters rather than completed-ledger length. A package-name reservation is rolled into
the terminal ledger only after response validation but remains consumed after an external attempt. Every
request receives the session AbortSignal. Any rejection, timeout, transport error, audit error, response
validation error, output/file limit, npm terminal failure, or cancellation performs one idempotent transition:

```text
ARMED -> FAILING -> DISARMED_INCOMPLETE
```

It aborts all controllers, refuses new local requests, ignores late responses, closes listener sockets, and
asks the process supervisor to terminate the group. There is no retry under the same approval.

## Public HTTPS transport

Use Node standard library only; add no dependency. The transport accepts only the broker-created exact npm
registry URL and explicit safe headers. It must:

1. perform an authority-owned lookup for `registry.npmjs.org`;
2. reject loopback, private, shared-address, link-local, multicast, unspecified, documentation, benchmark,
   reserved, and IPv4-mapped-private IPv6 results;
3. select and pin one accepted address for the socket while retaining `registry.npmjs.org` for TLS SNI,
   certificate verification, and `Host`;
4. send no Authorization, cookie, referrer, proxy, client certificate, user path, token, or parent headers;
5. disable redirects and content decompression, request identity encoding, and require status 200 plus exact
   JSON content type;
6. enforce content-length when present and stream into a bounded buffer that aborts on the first excess byte;
7. require exact final origin/path identity; and
8. zero references to raw response buffers after relay/terminal handling and never persist them.

Injected DNS and local TLS fixtures exercise this code without public resolution. A custom/system proxy is
not used. The later real run will disclose source IP, timing, registry host, and requested public package
names to npm's infrastructure.

## Durable audit ordering

The production audit adapter uses the existing append-only SQLite chain without schema migration if its
closed safe event payload fits the current generic event mechanism. Architecture acceptance does not itself
authorize persistent writes; the later real-run approval must name the exact temporary or product audit sink.

Required ordering:

```text
runtime_snapshot_complete
containment_probe_complete
plan_ready
approval_requested
approval_approved
authorization_finalized
broker_armed
npm_spawn_intent_recorded       # durable before spawn
npm_spawn_started
metadata_request_started        # durable before every public transport call
metadata_response_validated
npm_terminal_observed
lock_validation_started
candidate_compiled
cleanup_complete | cleanup_incomplete
genesis_complete | genesis_incomplete
```

Concurrent request events may interleave, but every response must reference a prior request sequence and all
started requests must terminate before success. Audit failure before an external call blocks it. Audit failure
after a public read marks the session incomplete, aborts work, preserves the failure fact where possible, and
never retries or authenticates a candidate.

## Process supervisor

Implement a dedicated graph-genesis supervisor; do not reuse the project-mutating Install Guard runner.
It launches only the exact private capsule with `shell: false`, closed stdin, detached process group, empty-
built environment, and bounded stdout/stderr. It has no general command API.

The supervisor couples to broker failure and enforces:

- complete 120-second deadline and external cancellation;
- 256 KiB total stdout and 256 KiB total stderr, with overflow terminating rather than merely truncating;
- TERM then bounded grace then KILL for the complete process group;
- child `close`, no outstanding broker request, and closed listener before post-state validation;
- exit zero as necessary but insufficient; and
- no raw output persistence. Only stable code, byte counts, signal, exit code, and redaction status may enter
  the safe report.

The exact real command remains the accepted shell-free npm lock-only vector. No additional flag or filesystem
allowlist is added in reaction to a permission error; such a failure returns to Architecture Check.

## Workspace, post-state, and cleanup

Strengthen the workspace authority before a real run:

- bind full initial contents and identities, including the profile file after final write;
- retain no-follow descriptors for root, manifest, configs, profile, and expected lock creation boundary;
- cap every subtree independently and relate cache growth to validated broker response bytes;
- reject all archive signatures/extensions, `node_modules`, package content, executable/link/special/hardlink
  state, unrecognized top-level roots, and file replacement;
- parse package and lock JSON as strict UTF-8 with duplicate-key/depth/key/byte bounds;
- compile the lock only after broker/process terminal success; and
- clean only the exact revalidated inventory without following links.

If inventory or identity is ambiguous, rename is not attempted and broad recursive deletion is prohibited.
Record `GENESIS_INCOMPLETE_QUARANTINE` with the exact private residue root retained for explicit manual review.
No candidate authority is created.

## State machine

```text
SNAPSHOTTING
  -> LOCAL_CONTAINMENT_PROBING
  -> PLAN_READY
  -> APPROVAL_PENDING
  -> AUTHORIZED
  -> BROKER_ARMED
  -> NPM_RUNNING
  -> LOCK_VALIDATING
  -> CANDIDATE_PENDING_CLEANUP
  -> CLEANUP_PENDING
  -> COMPLETE

denied/expired/replayed approval -> NOT_STARTED
failure before first public GET  -> FAILED_NO_EXTERNAL_READ
failure after first public GET   -> INCOMPLETE_EXTERNAL_READ_OCCURRED
cleanup ambiguity                -> INCOMPLETE_QUARANTINE
```

Every transition is monotonic and owned by the orchestrator. A successful npm exit, lock compile, digest,
ledger, or cleanup alone cannot skip another authority.

## Approval boundaries

| Boundary | Current authorization | Consequence |
| --- | --- | --- |
| this Architecture Check | preparation only | docs/read-only diagnostics |
| network-free hardening implementation | requires explicit acceptance | local source/tests; fake DNS/TLS/broker; inert child and local sockets only |
| exact real-plan capture | later preparation approval if it launches exact local probe/npm preflight | private temporary files and local-only processes; no public DNS/registry |
| real metadata-only genesis | exact one-time approval | bounded public packument GETs plus disposable lock/cache/log writes |
| exact metadata confirmation | separate later approval | listed exact package/version metadata GETs |
| artifact acceptance | separate later approval | exact tarball downloads and private read-only Pass A |
| production registration | separate later approval | reviewed repository profile data |
| materialization/startup/MCP action | independent approvals | only the consequence named at each boundary |

Direct npm/npx remains outside APG protection. No approval in this table authorizes another row.

## Network-free hardening test strategy

Add tests for:

- public projection/private capsule separation, token/path/output non-retention, mutation and cross-plan use;
- real-vs-synthetic provider-kind rejection and caller-supplied digest/observation forgery;
- listener bind identity, disarmed behavior, route/method/header/body/upgrade/timeout limits;
- concurrent request/name/byte reservation races, replay, late response, session abort, and terminal idempotence;
- audit failure immediately before transport, after response, after npm exit, and during terminalization;
- injected DNS classification for all IPv4/IPv6 non-public categories and pinned local TLS behavior;
- bounded streaming, misleading content-length, chunk overflow, redirect/status/type/UTF-8/JSON/name failures;
- inert process spawn, timeout, cancellation, signal escalation, group close, stdout/stderr overflow;
- runtime/provider/probe/workspace drift at every revalidation point;
- exact post-state, cache-to-ledger bounds, strict lock read, compiler failure, no-follow cleanup/quarantine; and
- static/runtime guards proving no test invokes the real npm CLI, resolves public DNS, opens a public socket,
  downloads an artifact, mutates a project, writes the product database, or starts package code.

## Known risks and mitigations

| Risk | Mitigation | Release blocker |
| --- | --- | --- |
| deprecated/private Seatbelt | exact-build binding, owned fresh probe, development-only wording, no fallback | any negative probe unavailable or succeeds unexpectedly |
| same-user process can inspect/attack local state | 128-bit ephemeral route, 0700/0600 state, short lifetime, exact identity checks; disclose limitation | evidence of cross-session adoption or token persistence |
| broker APG process has general host network capability | closed URL construction, pinned public destination, strict transport, durable request gate | arbitrary URL/header/proxy input reaches transport |
| DNS or local trusted MITM | public-address classification, pinned socket address, npm hostname TLS verification | private/reserved address or certificate bypass accepted |
| concurrent budget oversubscription | reserve before dispatch, terminal latch, session abort, adversarial scheduling tests | any run exceeds approved names/requests/bytes/concurrency |
| npm behavior differs from expected | exact runtime/args, fail on unexpected request/file/permission; do not widen | tarball/unknown request, node_modules, archive, child helper |
| output may contain unknown secrets | empty-built environment, no user/project reads, overflow terminates, no raw persistence | inherited credential/config/path or persisted output |
| cleanup cannot undo public reads | no retry, external-read status, quarantine on local ambiguity | candidate authenticated after cleanup/audit uncertainty |
| local hash evidence is owner-recomputable | precise local assurance wording; later signing/anchor architecture | claim of third-party cryptographic proof |

Residual risk after mitigation: the workflow can prove the reviewed software path observed a bounded graph
generation under one development host. It cannot prove registry/publisher honesty, package safety, source/build
equivalence, kernel integrity, hostile same-user containment, or future Seatbelt stability.

## Architecture acceptance requested

Accept only the network-free hardening scope described above. Acceptance permits production-shaped source,
interfaces, loopback/local TLS fixtures, injected DNS, inert process supervision, docs, and tests. It does not
permit real npm/npx, public DNS/registry access, product audit writes, artifact bytes, dependency changes,
production registration, materialization, package execution, commit, or push.

Suggested approval phrase:

```text
Exact Real Metadata-only Graph Genesis Plan Architecture Check 승인 — network-free production-adapter hardening 구현 진행
```

## Rollback

This Architecture Check is documentation only. Before acceptance, remove this file and restore
`PROJECT_STATE.md`; no runtime, dependency, external service, credential, database, package, or user project
has changed.

## Next

After acceptance, implement and verify the network-free hardening checkpoint. Then present its diff and test
evidence. Do not prepare or execute the real metadata-only plan until that checkpoint is separately accepted
and the exact later consequence is displayed for one-time approval.
