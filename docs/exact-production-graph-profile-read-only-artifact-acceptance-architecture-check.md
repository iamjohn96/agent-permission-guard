# Exact Production Graph Profile & Read-only Artifact Acceptance Architecture Check

Status: accepted on 2026-09-08 for the network-free schema/adapter foundation only. This acceptance does
not authorize registry access, npm graph generation, real artifact download, materialization, persistent
staging, receipt/database changes, package startup, commit, or push.

## Decision summary

Use `@modelcontextprotocol/server-filesystem@2026.7.10` as the only first candidate. Keep an untrusted,
reviewable graph candidate distinct from an APG-authenticated production graph profile. A candidate may
be derived in a separately approved, credential-free temporary npm workspace whose npm process can
reach only an APG-owned loopback metadata broker. It becomes a production profile only after the
discovered complete graph is shown to the user, every graph node has separately confirmed exact registry
metadata, and every exact artifact has passed bounded integrity verification, two independent
write-free archive inspections, and package-manifest projection checks.

The first real artifact acceptance is read-only with respect to archive contents, user projects, and
package execution. It is not consequence-free: it performs public registry GET requests and writes
untrusted bytes to private disposable quarantine files. Those consequences require a separate exact
approval. It performs no Pass B, no extracted file write, no persistent stage, no npm installation, and
no package startup.

The first accepted profile is intentionally narrow:

- top package: `@modelcontextprotocol/server-filesystem@2026.7.10`, never a tag or range;
- platform evidence: `darwin-arm64`;
- archive worker: Node 26 only for the first real acceptance;
- graph genesis: exact Node `26.3.1`, npm `11.16.0`, and the resulting exact lock format, subject to
  re-observation in the separately approved run;
- registry: public anonymous `https://registry.npmjs.org/` only;
- archive grammar: the already accepted bounded single-member gzip/USTAR contract; and
- no optional, peer, bundled, link, native-build, install-script-required, alias, git, file, workspace,
  or remote-URL graph behavior.

Any required unsupported behavior rejects the candidate. It does not silently broaden the profile.

## Observable success

This architecture is ready for a later implementation checkpoint only when:

1. a graph candidate cannot enter the production profile authority by having a valid self-digest;
2. exact npm graph generation is development evidence only and runtime APG never resolves or hoists;
3. every node's exact install path, package/version, registry URL, SHA-512, and runtime dependency
   resolution are closed, canonical, connected, and complete;
4. one complete metadata observation set matches the candidate before an artifact approval can exist;
5. artifact approval binds the complete ordered URL/integrity set, limits, runtime identity, private
   quarantine-root identity, metadata expiry, and candidate digest;
6. each response is streamed to an exclusive private file and authenticated before parser access;
7. two fresh Pass-A workers over independently reopened exact files produce the same complete transcript;
8. package.json identity, dependency semantics, lifecycle names, and forbidden graph features match the
   candidate without executing or materializing any package bytes;
9. partial graph success, cleanup failure, audit failure, timeout, cancellation, or any mismatch cannot
   produce an authenticated production profile; and
10. no default test contacts a registry, invokes npm/npx, downloads a package, reads user configuration,
    or executes package code.

## Scope

In scope:

- candidate versus accepted-profile authority;
- graph genesis and exact install-layout validation;
- batch metadata confirmation and freshness;
- exact artifact approval identity;
- anonymous artifact transport and private quarantine files;
- retained-descriptor identity and two independent Pass-A inspections;
- bounded package-manifest evidence without materialization;
- failure, cleanup, privacy, audit, and approval boundaries; and
- network-free implementation tests plus a later separately approved real acceptance strategy.

Out of scope:

- Pass B or any archive materialization;
- a persistent stage, seal consumer, recovery coordinator, or stage deletion command;
- package startup, MCP schema preflight, or MCP tool calls;
- project installation or reuse of the Install Guard runner;
- receipt schema 1.2 or a persistent audit database migration;
- npm signatures, Sigstore provenance, publisher identity, reproducible builds, malware detection,
  sandboxing, or remote attestation;
- Windows and Linux production profiles; and
- Node 24 real archive parsing without a separately reviewed no-network containment provider.

## Claims and non-claims

A successful controlled acceptance may establish only:

```text
package_identity: exact_registry_version
artifact_integrity: complete_for_accepted_graph
dependency_graph: reviewed_exact_graph
archive_compatibility: accepted_write_free
materialized_tree: unverified
publisher_identity: unverified
build_reproducibility: unverified
runtime_containment: none
```

It must not claim `complete_for_materialized_stage`, `sealed_local_snapshot`, or
`prelaunch_revalidated`, because no graph tree exists yet. Registry integrity identifies exact bytes;
it does not prove who authored them, whether source corresponds to them, or whether they are safe.

Permitted UX:

```text
Exact registry artifacts for the reviewed graph passed bounded read-only archive inspection.
No package was installed, materialized, or executed.
Publisher, source/build equivalence, runtime behavior, and containment are not verified.
```

Forbidden UX includes “official server verified,” “safe package,” “malware-free,” “publisher verified,”
“installed,” “sandboxed,” “attested,” and “ready to run.”

## Candidate and production profile split

The existing profile authority authenticates constructor-owned objects after schema and digest checks.
That is sufficient for synthetic tests but too broad for the first production registry. A digest proves
internal consistency, not that artifacts were observed. Production registration therefore requires a
separate build-owned allowlist of acceptance-complete definitions.

Two distinct objects are required:

```text
ExactGraphCandidateV1
  candidate_schema_version
  profile_id + profile_version
  target package/version/entrypoint
  registry origin
  platform and graph-generator identity
  exact lockfile format
  graph nodes and dependency-resolution edges
  archive/materialization/worker contract versions
  fixed limits
  candidate_digest

AcceptedProductionGraphProfileV1
  all candidate fields and candidate_digest
  per-node artifact acceptance records
  accepted graph completeness
  production_profile_digest
```

Per-node acceptance fields are deterministic and timestamp-free:

```text
install_path
package_name + exact_version
tarball_url + sha512_integrity
compressed_bytes
expanded_bytes
archive_entry_count
archive_transcript_digest
package_json_body_sha256
package_manifest_projection_digest
```

Run timestamps, local file identities, temporary paths, HTTP diagnostics, and cleanup outcomes belong to
the non-portable acceptance report, not the production profile digest. A partial acceptance report can
explain failure but can never be registered as a production profile.

The current profile schema must be revised before the first real profile. No compatibility migration is
needed because no production graph definition is currently shipped. Existing synthetic fixtures may be
kept under an explicitly synthetic schema or migrated mechanically after the architecture is accepted.

## Exact graph genesis

Graph genesis is a controlled development workflow, not a runtime resolver. The complete transitive
package list cannot be known before discovery, so the discovery approval binds the fixed top-level
target, registry, allowed metadata request class, graph/byte/time ceilings, exact Node/npm identities,
and private workspace rather than pretending to bind unknown names. Under that later approval it may:

1. create a new private temporary directory;
2. create an intentionally empty package manifest plus empty user/global npm configs;
3. start an APG-owned loopback broker that forwards only bounded anonymous package-metadata GETs to the
   fixed public registry and rejects tarball paths, redirects, writes, security/audit endpoints, and
   every unknown request class;
4. invoke the exact discovered npm executable through a separately validated launch contract that
   permits network access only to that loopback broker and denies direct public egress;
5. request only `@modelcontextprotocol/server-filesystem@2026.7.10` with `--package-lock-only`,
   `--save-exact`, `--ignore-scripts`, audit/fund/update messages disabled, a private empty cache/HOME,
   and the loopback registry endpoint;
6. require the broker log to show only permitted metadata requests and assert that no `node_modules`,
   tarball request, or package content was created;
7. convert the exact lock into a candidate through a network-free closed-schema compiler; and
8. remove the exact owned temporary workspace after recording a bounded summary.

The generator must forward no npm login, proxy, custom CA, certificate, token, `NODE_OPTIONS`, project
path, or user configuration. It must never inspect user `.npmrc` or cache contents. If non-loopback
egress denial or the metadata-only broker cannot be demonstrated on the host, graph genesis is blocked;
it does not fall back to direct npm registry access.

The candidate compiler rejects:

- tags, ranges at the top-level request, missing exact resolution, or a non-lockfile source;
- non-public or cross-origin resolved URLs, credentials, query, fragment, and redirects;
- missing/non-canonical SHA-512, duplicate/case-colliding install paths, unreachable nodes, or cycles;
- dev-only nodes in the materialized graph, optional/peer/bundled/link/workspace/file/git/remote
  dependencies, native/prebuilt/build requirements, and install-script-required nodes;
- unsupported OS/CPU conditions or a runtime constraint not equal to the approved profile target; and
- any lock field or npm layout behavior the compiler does not explicitly understand.

For each dependency edge, validation must model the exact Node `node_modules` ancestor lookup from the
declaring node. The first matching package path must equal the edge's declared target. Merely pointing an
edge at any same-named graph node is insufficient.

Generated output is reviewed and committed as source only after real artifact acceptance. Runtime APG
does not invoke npm to reconstruct or reinterpret this layout.

## Metadata confirmation

Metadata confirmation is a second, separate public read boundary after discovery. Product planning
invocation or a developer acceptance approval must disclose the registry origin and the now-complete
package-name/version set before these requests. Discovery evidence is not reused as exact confirmation.

A new batch authority, not the general Install Guard resolution result, constructs one
`GraphMetadataObservationSet`:

- one bounded response per unique exact package/version identity;
- exact name/version, registry origin, tarball URL, and SHA-512 matching the candidate;
- canonical selected-field records only; raw packuments are not persisted;
- per-response and aggregate byte limits, per-request and total deadlines, and sequential first-run
  operation;
- no Authorization, cookie, referrer, prompt, policy, audit data, project path, or telemetry;
- no redirect, credential URL, query, fragment, unsupported content type, or alternate origin; and
- one common expiry equal to the earliest observation expiry in the complete set.

Missing, contradictory, expired, or partial evidence produces no artifact plan. Metadata does not
authenticate publisher identity and cannot replace artifact SHA-512 verification.

## Read-only artifact acceptance plan

Only a complete fresh metadata observation set can produce a runtime-authenticated
`ReadOnlyArtifactAcceptancePlan`:

```text
plan_version
random acceptance_session_id
candidate_digest
metadata_observation_digest + expires_at
ordered artifact identities[]
  install_path
  exact URL
  SHA-512
approved registry origin/host
fixed per-artifact and aggregate limits
worker/runtime/parser/protocol identities
private quarantine-root binding
consequence = exact_artifact_download_and_read_only_inspection
plan_hash
```

The approval is one-time and binds the complete plan. It does not authorize a subset, metadata refresh,
changed URL, retry after consumed side effects, extraction, stage writes, package installation, or code
execution. A changed candidate, observation, runtime, root, limit, or implementation contract requires
a new plan and approval.

## Artifact transport and quarantine

The first transport uses a direct Node HTTPS adapter behind an injectable interface. It uses only URLs
from the authenticated plan and does not use npm, npx, a shell, a package-manager cache, or proxy
environment variables.

For every artifact, sequentially:

1. revalidate the private `0700` quarantine root identity;
2. create a random `0600` file with `O_CREAT | O_EXCL | O_NOFOLLOW`;
3. request the exact HTTPS URL with an explicit minimal header set;
4. require status 200, no redirect, exact origin/final URL, and no unsupported content encoding;
5. enforce declared content length when present plus streaming per-file and aggregate ceilings;
6. stream raw bytes once to the retained file handle while independently hashing SHA-512;
7. sync, fstat, and require regular file, owner, mode, one link, exact byte count, and unchanged identity;
8. compare SHA-512 in constant time before any parser worker receives bytes; and
9. close and reopen with `O_RDONLY | O_NOFOLLOW` for inspection authority.

The adapter never logs response bodies or request headers. TLS and the system trust store protect
transport; the committed SHA-512 is the content-selection control. A compromised registry that serves
different bytes fails integrity. Matching malicious bytes remain possible and are not called safe.

On failure, only the exact process-owned partial file is unlinked after identity checks. Failure to
clean up is reported as quarantined residue and blocks retry/adoption; no broad recursive deletion is
performed.

## Descriptor-backed double Pass A

The current bounded worker accepts an in-memory `Uint8Array`; that API is synthetic-only. Real artifact
acceptance requires a parent-owned descriptor authority that never hands a path to the child and never
buffers the complete artifact solely to satisfy the worker API.

For each artifact the parent:

1. authenticates the downloader-produced file authority;
2. records device, inode, owner, mode, link count, size, and expected SHA-512;
3. streams exactly the recorded size from the retained descriptor into a fresh Pass-A child;
4. hashes the complete stream again, rejects short/extra reads, and fstats after EOF and worker exit;
5. closes and independently reopens the same path with no-follow semantics;
6. requires the same identity and SHA-512, then runs a second fresh Pass-A child; and
7. requires complete canonical transcript equality, including runtime/configuration identity.

The child keeps the existing empty environment, exact runtime-file manifest, fixed V8 limits, bounded
protocol, deadline/cancellation, and no filesystem-write/child/worker/addon grant. Real acceptance is
Node 26 only. Node 24 remains blocked because its Permission Model cannot deny child network access;
Node 25 requires a later compatibility run before receiving a profile.

No Pass B event is accepted in this workflow. No pending materialization root or seal is created.

## Package manifest projection

Graph completeness cannot be inferred from archive paths and hashes alone. Each artifact must contain
exactly one bounded `package/package.json` regular-file entry. The worker may stream only that exact body
to the parent under a separate bounded frame. The parent verifies its SHA-256 against the transcript,
parses it under a strict size/depth/key-count contract, and retains only a canonical safe projection:

- exact name and version;
- ordinary runtime dependency names and exact declared specifier strings;
- presence of optional, peer, bundled, workspace, link, native-build, or platform selectors;
- lifecycle script names, not script bodies;
- package type plus entrypoint-relevant `main`, `exports`, and `bin` shapes; and
- raw package.json body SHA-256.

Duplicate behavior-determining JSON keys are rejected rather than accepted with last-key-wins
ambiguity. Unknown fields remain covered by the body hash but do not silently affect graph acceptance.
The projection must equal the candidate's node/edge/lifecycle expectations. The top-level reviewed
entrypoint must exist as an ordinary transcript file. No script value or package code is executed.

Manifest body bytes and raw archive paths are not persisted or exported. Only bounded public package
identity, selected public graph fields, and digests enter the acceptance report.

## State and authority

```text
GRAPH_DISCOVERY_APPROVAL_PENDING
  -> GRAPH_DISCOVERING
  -> CANDIDATE_READY
  -> METADATA_CONFIRMATION_APPROVAL_PENDING
  -> METADATA_CONFIRMING
  -> METADATA_CONFIRMED
  -> ARTIFACT_ACCEPTANCE_APPROVAL_PENDING
  -> DOWNLOADING_READ_ONLY
  -> ARTIFACTS_VERIFIED
  -> PASS_A_ACCEPTING
  -> ACCEPTANCE_COMPLETE
  -> HUMAN_PROFILE_REVIEW_PENDING
  -> PRODUCTION_PROFILE_ACCEPTED

Any failure after external reads -> ACCEPTANCE_INCOMPLETE_QUARANTINE
Any metadata expiry before first artifact byte -> METADATA_EXPIRED
```

`PRODUCTION_PROFILE_ACCEPTED` is never an automatic runtime transition. It means a human reviewed the
complete deterministic evidence and explicitly approved adding that exact definition to the built-in
production registry. Approval cannot convert an incomplete or failed object.

The candidate authority, metadata authority, artifact-file authority, transcript authority, acceptance
authority, and production-profile registry use distinct owning brands. Structurally similar objects are
not interchangeable.

## Audit and evidence ordering

The later controlled real acceptance records, at minimum:

```text
graph_discovery_authorized
graph_discovery_started          # before the broker's first public request
candidate_ready
metadata_confirmation_authorized
metadata_confirmation_started
metadata_confirmed
artifact_acceptance_authorized
artifact_download_started       # before each first response byte
artifact_integrity_verified
artifact_pass_a_verified
artifact_second_pass_a_verified
acceptance_complete | acceptance_incomplete
cleanup_complete | cleanup_incomplete
```

An audit/evidence failure before the first external request blocks that request. A failure after a GET
does not retry or pretend that the read did not occur. Terminal evidence failure leaves the session
incomplete and cannot authenticate a production profile.

This Architecture Check does not authorize a persistent database schema change. The first controlled
acceptance may use an isolated temporary report/audit database and export only deterministic safe
evidence for review. Durable product integration and receipt schema 1.2 remain later checkpoints.

## Approval boundaries

| Boundary | Required authority | Permitted consequence | Not permitted |
| --- | --- | --- | --- |
| network-free foundation | architecture acceptance | local source/tests/docs using fakes and fixture bytes | registry or artifact request |
| graph discovery | bounded approval naming top target, registry, metadata request class/ceilings, Node/npm, broker, and command | recursively discovered anonymous metadata GETs plus private temporary lock/report files | tarball GET, direct npm egress, install, materialization, code startup |
| exact metadata confirmation | exact approval after complete graph disclosure | anonymous metadata GETs for the listed package/version set | new resolution, tarball GET, install, materialization, code startup |
| artifact acceptance | one-time exact plan approval after graph disclosure | exact tarball GETs, private temp files, double Pass A | Pass B, extracted tree, persistent stage, code startup |
| production profile registration | human review plus repository-change approval | add exact accepted manifest to built-in source | network or runtime side effect |
| persistent materialization | later stage approval | Pass B and exact APG-private stage writes | package startup or tool calls |
| package startup | separate launch approval | one exact staged process | download, install, or tool approval |
| MCP action | existing action policy/approval | one exact routed tool call | direct bypass or server restart |
| project install | existing Install Guard approval | exact approved project mutation | MCP stage or startup authority |

No row grants another. Direct npm/npx and MCP execution outside APG remain outside APG protection.

## Failure and cleanup

| Failure | Required result |
| --- | --- |
| candidate/schema/graph invalid | fail before registry access |
| npm generator or metadata mismatch | no artifact plan |
| metadata expiry | no first artifact byte; rebuild plan |
| approval denied/expired/replayed | no artifact GET |
| redirect/origin/status/encoding/size failure | stop, close, verify exact partial identity, unlink or report residue |
| SHA-512 mismatch | no worker access; entire acceptance incomplete |
| descriptor/path/owner/mode/link drift | terminate worker; no authenticated artifact |
| worker timeout/crash/protocol overflow | kill process group; entire acceptance incomplete |
| Pass-A differential | reject candidate; never widen parser automatically |
| manifest/graph/entrypoint mismatch | reject complete profile |
| terminal audit/report failure | incomplete; no automatic GET retry or profile promotion |
| cleanup uncertainty | quarantine residue, manual review; no broad deletion |

One node failure invalidates the complete graph acceptance. Earlier per-node success is diagnostic only
and cannot be combined with a later run unless a future resumable-session architecture is separately
approved.

## Data flow and privacy

```text
fixed public target + isolated exact lock generation
  -> closed graph candidate
  -> anonymous exact registry metadata
  -> complete metadata observation digest
  -> one-time artifact acceptance approval
  -> exact public tarball bytes into private disposable files
  -> SHA-512 verified descriptors
  -> two bounded write-free Pass-A workers
  -> package manifest safe projections + transcript digests
  -> deterministic acceptance evidence
  -> human production-profile review
```

Disclosed externally: client IP, request time, registry origin, and exact public package names/versions.

Never sent or read: npm login state, token, key, certificate file, `.npmrc`, `.env`, project path,
prompt, policy, audit contents, private stage path, or telemetry.

Never committed: tarballs, raw packuments, package bodies, temporary paths, headers, stdout/stderr, or
private environment values.

## Network-free implementation strategy

After explicit architecture acceptance, the next checkpoint may implement only:

1. candidate and accepted-profile schemas with separate authorities;
2. graph compiler/validator over checked-in synthetic lock fixtures;
3. exact Node-resolution edge validation and forbidden lock-feature checks;
4. batch metadata authority behind fake transports;
5. read-only acceptance-plan and one-time synthetic approval identities;
6. private artifact-file authority behind fake byte streams;
7. descriptor-backed worker input and double-Pass-A orchestration over repository fixtures;
8. bounded package.json projection and duplicate behavior-key rejection;
9. monotonic synthetic state/audit/report types;
10. cleanup identity tests and documentation/state updates.

It must not ship the actual Filesystem graph, run npm/npx, contact a registry, download a real artifact,
perform Pass B, create a persistent stage, change the audit schema, add a CLI, or start package code.

## Test strategy

Default tests remain network-free and cover:

- candidate versus production authority forgery and partial-evidence rejection;
- exact lock schema/version, unsupported flags, graph reachability, cycles, hoist/resolution-path errors,
  duplicate/case collisions, and all behavior-determining digest mutations;
- metadata order independence with canonical output, partial freshness, duplicate responses, origin/URL/
  integrity mismatch, redirect, body/aggregate limits, timeout, and forbidden-header checks;
- one-time acceptance approval replay and cross-candidate/runtime/root/limit substitution;
- exclusive private artifact creation, partial writes, short/extra body, content-length mismatch,
  SHA-512 mismatch, fsync/close/reopen failure, symlink/hardlink/owner/mode/inode replacement, and exact
  cleanup refusal on ambiguity;
- no parser access before integrity authority, exact descriptor byte counts, post-read fstat, two fresh
  child processes, transcript equality, timeout/cancel/crash, and no Pass B frame;
- package.json absence/duplication/oversize/depth/key limits, duplicate behavior keys, malformed JSON,
  identity/dependency/lifecycle/entrypoint mismatch, and forbidden graph features;
- no full-artifact parent buffering, unbounded output, raw body persistence, private-path evidence, or
  production assurance escalation; and
- unchanged receipt 1.0/1.1, gateway, Install Guard, Dashboard, and default network-free behavior.

Before a real acceptance, run the existing archive corpus on every runtime claimed by the profile. The
first candidate may claim only the locally evidenced Node 26/darwin-arm64 combination.

## Later real acceptance strategy

Real work is split into three separately approved runs:

### A. Bounded metadata-only graph discovery

- target only `@modelcontextprotocol/server-filesystem@2026.7.10`;
- exact Node/npm identity disclosed before execution;
- private disposable HOME/cache/TMP/prefix/workspace and empty npm configs;
- package-lock-only, scripts/audit/fund/update disabled;
- npm reaches only an APG-owned loopback broker; non-loopback npm egress is denied;
- the broker permits bounded public package metadata GETs only and rejects tarball/unknown endpoints;
- no `node_modules`, tarball request, package content, or package startup;
- report exact node count, public names/versions/origins/integrities, unsupported features, cleanup, and
  candidate digest for human review.

### B. Exact metadata confirmation

- begin only after the user reviews the discovered complete graph;
- disclose the complete package/version list, registry origin, request/byte limits, and expiry;
- request only the listed exact metadata and require complete canonical equality with the candidate;
- emit the authenticated observation digest and artifact-plan preview; and
- perform no tarball GET, npm resolution, materialization, or package execution.

### C. Complete graph read-only artifact acceptance

- begin only after the user reviews B and approves the complete artifact plan;
- direct exact HTTPS GETs, sequentially, under fixed aggregate limits;
- private disposable files, exact SHA-512, two Pass-A workers, no Pass B;
- fail the entire graph on the first mismatch;
- delete exact owned artifact files and workspace after the result;
- report only safe deterministic evidence plus any cleanup residue; and
- do not register the production profile, commit, or push until separately approved.

## Alternatives considered

### Trust the package-lock and metadata only

Rejected. They describe registry intent but do not prove that strict archive parsing accepts every exact
artifact or that archive package manifests agree with the graph.

### Accept only the top-level package artifact

Rejected for a complete-graph claim. A transitive artifact can drift, violate archive policy, or carry
different dependency semantics.

### Materialize while performing acceptance

Deferred. It would combine artifact GETs with a larger persistent filesystem consequence and make the
read-only compatibility checkpoint harder to reason about.

### Reuse the prior npx cache or user npm cache

Rejected. Those paths are mutable, credential-adjacent, package-manager-owned, and not an exact APG
quarantine authority.

### Automatically promote a successful run into production

Rejected. Production registration is a human-reviewed repository decision, not a runtime state change.

## Known risks and mitigations

| Residual risk | Current mitigation | Release-blocking condition |
| --- | --- | --- |
| exact bytes may still be malicious | no safety/publisher claim; no execution; later separate startup approval | any safety claim based on integrity |
| npm graph generator bug, compromise, or unexpected request | exact Node/npm, private env, loopback metadata-only broker, direct-egress denial, closed compiler, later metadata/artifact cross-check | unsupported lock field, graph ambiguity, tarball/unknown request, or egress escape |
| registry/TLS compromise | committed SHA-512 and exact origin/URL; no redirects | artifact accepted without exact integrity |
| parser zero-day | exact runtime graph, fresh bounded children, narrow USTAR, double Pass A | parser warning/recovery/differential or unbounded work |
| package.json interpretation ambiguity | bounded projection and duplicate behavior-key rejection | graph accepted with ambiguous manifest semantics |
| resource/disk exhaustion | sequential downloads and fixed per/aggregate ceilings | any unbounded stream, buffer, or retry |
| same-user file race | private roots, no-follow/exclusive files, descriptor identity and post-read fstat | profile accepted after identity drift |
| Node Permission Model is not a sandbox | precise non-claim; no package execution; Node 26-only first run | hostile-code containment claim |
| Node 24 cannot deny worker network | real parsing blocked without approved OS containment | Node 24 real acceptance using Permission Model alone |
| cleanup may fail | exact owned identity, quarantine report, no broad deletion/adoption | silent residue or ambiguous deletion |
| “read-only” may hide network/disk effects | explicit UX and separate metadata/artifact approvals | approval text omits GETs or temp writes |
| profile becomes stale | immutable versioned profile; any node/origin/integrity/runtime change requires new acceptance | mutable profile or silent refresh |

## Accepted decision

Accept the candidate-to-production split, exact Filesystem target, full-graph rather than top-level-only
artifact evidence, separate metadata and artifact approvals, descriptor-backed double Pass A, bounded
manifest projection, Node 26/darwin-arm64 first profile, and network-free-only next implementation scope.

Acceptance of this document still does not authorize any registry request, npm command, artifact
download, persistent stage, package execution, commit, or push.

## Rollback

This Architecture Check changes documentation only. Rollback is deletion of this document and reversal
of its state reference. No external request, artifact, stage, database, or package process was created.

## Next

Complete the network-free candidate/profile, metadata, artifact-file, descriptor-worker, double-Pass-A,
manifest-projection, and synthetic evidence foundation and its tests. Then review and approve bounded
metadata-only graph genesis separately before any real registry request or npm invocation.
