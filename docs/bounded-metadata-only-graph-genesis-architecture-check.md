# Bounded Metadata-only Graph Genesis Architecture Check

Status: accepted on 2026-09-08 for the network-free foundation, which is now implemented locally. This
acceptance authorized no npm execution, registry request, broker egress, package download, artifact
acceptance, materialization, production-profile registration, package startup, dependency change,
database migration, commit, or push. Those consequences remain separately gated.

## Decision summary

Generate the first exact npm dependency-layout candidate only through a separately approved development
workflow whose single target is:

```text
@modelcontextprotocol/server-filesystem@2026.7.10
```

The workflow may use exact npm `11.16.0` as the layout generator, but npm must see only an APG-owned
loopback metadata broker. The broker may perform bounded anonymous HTTPS GETs for syntactically valid
public package packuments at `https://registry.npmjs.org/`. It must never fetch a tarball or forward npm
credentials, cookies, proxy settings, project data, or telemetry.

Node `26.3.1` cannot itself enforce “loopback only.” Its current Permission Model exposes `--allow-net`
as a Boolean capability, not a host/port allowlist. Therefore the npm child cannot be granted network on
the strength of Node permissions alone. The recommended first provider is a macOS development-only
`sandbox-exec`/Seatbelt network profile layered with Node's filesystem/process Permission Model:

- Seatbelt limits npm outbound connections to the exact broker loopback port;
- Node permits network generally only because Seatbelt supplies destination scoping;
- Node separately limits filesystem reads/writes and grants no child process, worker, addon, FFI, WASI,
  inspector, or other optional execution capability; and
- the provider is eligible only after exact local positive and negative containment self-tests.

`sandbox-exec` is deprecated and its profile language is an Apple private interface. APG must describe it
as a one-host development capability provider, never as a supported production sandbox. The exact macOS
build, `sandbox-exec` identity, generated profile digest, and self-test evidence are bound into the genesis
plan. If the provider is unavailable, its self-test fails, or npm requires a broader capability, graph
genesis blocks. It never falls back to unsandboxed/direct npm networking.

## Observable success

The architecture is ready for a later network-free implementation checkpoint only when:

1. plan preparation identifies and hashes the exact Node executable, npm CLI entrypoint and bounded npm
   runtime tree, APG broker/runtime files, `sandbox-exec`, OS build, workspace root, generated Seatbelt
   profile, target, command array, environment, broker port/route digest, and every resource ceiling;
2. no self-consistent plan or lockfile can forge completed genesis authority;
3. the containment provider proves the exact approved loopback port succeeds while another loopback port
   and a locally hosted non-loopback destination fail, without contacting the public internet;
4. npm receives no environment or config inherited from the user and cannot read project, home, `.npmrc`,
   `.env`, token, key, certificate, proxy, or prior cache state;
5. the broker accepts only bounded anonymous packument GETs, constructs the public registry URL itself,
   rejects redirects and all tarball/unknown endpoints, and validates each bounded JSON body before relay;
6. audit evidence is recorded before arming broker egress and before spawning npm;
7. npm exits successfully under the exact command and creates only the allowed temporary package manifest,
   lockfile, bounded metadata cache/logs, and other predeclared npm bookkeeping;
8. no `node_modules`, tarball, extracted package, executable package content, lifecycle subprocess, or
   unexpected socket/request/file appears;
9. the exact package-lock is accepted by the existing network-free closed compiler and the complete safe
   graph summary is produced for human review;
10. cleanup and terminal audit succeed before a production genesis authority authenticates the candidate;
    and
11. default tests remain network-free and never launch real npm or contact a registry.

## Scope

In scope:

- exact graph-genesis plan and one-time approval identity;
- exact Node/npm/broker/containment/workspace snapshots;
- a provider interface and macOS Seatbelt loopback-only development provider;
- broker request/response grammar and bounded public metadata relay;
- exact npm launch contract and credential-free environment;
- file/network/process observations, failure handling, cleanup, safe report, and audit ordering;
- network-free fake transports and repo-owned containment fixtures; and
- a later separately approved real metadata-only genesis run.

Out of scope:

- artifact/tarball GETs or package content;
- exact metadata confirmation after the graph is known;
- read-only artifact acceptance;
- Pass A, Pass B, materialization, persistent stage, startup, or MCP calls;
- changes to production policy, approval semantics, Dashboard, receipt schema, or persistent database;
- npm publish, project installation, npx, user npm cache/configuration, or authenticated registries;
- a general dependency resolver or runtime npm invocation;
- production support for deprecated Seatbelt profiles; and
- Linux, Windows, a second Mac, Network Extension, VM, or remote build infrastructure.

## Facts established for this host

Read-only checks on 2026-09-08 observed:

```text
macOS: 26.6.2 (25G83), arm64 host
Node: 26.3.1
npm package: 11.16.0
Node executable: /opt/homebrew/Cellar/node/26.3.1/bin/node
npm CLI: /opt/homebrew/lib/node_modules/npm/bin/npm-cli.js
sandbox-exec: /usr/bin/sandbox-exec
npm runtime inventory: about 1,934 regular files, 9 internal .bin symlinks, about 16 MiB
```

These observations are diagnostics, not accepted plan values. The later plan must re-resolve, snapshot,
and hash them. Homebrew paths, file identities, runtime contents, OS build, and counts may change.

The local `node --help` exposes `--allow-net` without an allowlist value. The Node 26 permissions
documentation likewise models `allow-net` as Boolean. Node permissions can deny all network or permit all
network; they cannot express only `127.0.0.1:PORT`. See the official
[Node Permission Model documentation](https://nodejs.org/api/permissions.html).

The npm documentation confirms `--package-lock-only` updates the lock instead of downloading dependencies,
`--ignore-scripts` disables package scripts, and `--save-exact` writes an exact top-level dependency. It
also documents that `replace-registry-host` otherwise may replace public npm dist URLs with the configured
registry host, so genesis must set it to `never`. See the official
[npm install](https://docs.npmjs.com/cli/v11/commands/npm-install/) and
[npm configuration](https://docs.npmjs.com/cli/v11/using-npm/config/) documentation.

## Trust and non-claims

Successful genesis establishes only:

```text
graph_generator: exact_local_runtime_snapshot
network_route: exact_loopback_broker_observed_under_local_provider
request_class: bounded_anonymous_packument_get
lock_layout: npm_generated_and_closed_compiler_accepted
artifact_integrity: declared_only
publisher_identity: unverified
package_safety: unverified
runtime_containment: development_provider_only
```

It does not prove:

- that npm, Node, Homebrew, macOS, the registry, or the package publisher is trustworthy;
- that registry SHA-512 values match downloaded bytes;
- that package manifests or tarballs agree with the lock;
- that any package is safe, official, malware-free, reproducible, installed, or launchable;
- that deprecated Seatbelt behavior remains stable across OS builds; or
- that APG contains a compromised kernel, root user, APG process, or same-user attacker.

Permitted UX:

```text
APG generated an exact dependency-layout candidate using the displayed local Node/npm runtime.
The approved run allowed bounded anonymous package-metadata reads through one loopback broker.
No package artifact was downloaded, installed, materialized, or executed.
```

Forbidden UX includes “sandboxed npm,” “verified dependency,” “safe graph,” “official package,” “artifact
verified,” “installed,” “ready to run,” and “production profile accepted.”

## Authority separation

Introduce distinct owners:

```text
GraphGenesisPlanAuthority
  -> authenticates exact prepared plans only

GraphGenesisApprovalAuthority
  -> one-time approval bound to the complete plan hash

ContainmentProviderAuthority
  -> authenticates exact provider snapshot + same-build self-test evidence

MetadataBrokerAuthority
  -> authenticates bounded request ledger + terminal broker result

ControlledGraphGenesisAuthority
  -> owns completed candidate + report only after compiler, cleanup, and terminal audit
```

The existing `ExactGraphCandidateAuthority` remains the closed-schema lock compiler. A candidate object it
creates is necessary but not sufficient for the real workflow. The next real metadata-confirmation boundary
must require a `ControlledGraphGenesisEvidence` brand in addition to candidate authentication. This prevents
an arbitrary caller with a structurally valid synthetic lock from entering the production acceptance path.

No constructor or digest can mint another authority's result. Test-only providers remain explicitly named
synthetic and cannot authenticate production evidence.

## Exact genesis plan

`GraphGenesisPlanV1` binds:

```text
plan_version
random_session_id
target_name + exact_target_version
public_registry_origin
platform: darwin + arm64 + exact OS build
node_runtime_snapshot_digest
npm_runtime_tree_digest + exact npm version + CLI realpath
broker_runtime_digest + broker_contract_version
containment_provider_id + provider_binary_digest
generated_containment_profile_digest
containment_self_test_digest + tested broker port
private_workspace_binding
broker_loopback_address + port + route_token_digest
exact command + argument vector digest
exact allowlisted environment digest
limits
consequence = bounded_public_metadata_graph_genesis
plan_hash
```

The actual random route token and private paths remain memory-only. The plan binds their digests and owned
root identities. Approval displays the public target, Node/npm/OS/provider versions, registry, metadata-only
consequence, maximum package names/requests/bytes/time, and the fact that private temporary files are written.

A changed executable, npm tree, APG broker, OS build, provider, profile, port, route, command, environment,
workspace, limit, or target invalidates the plan and requires a new approval.

## Runtime snapshot

The runtime snapshot must:

- resolve the exact Node binary and npm CLI without `PATH` dispatch at execution time;
- require regular non-world-writable files and record owner, mode, device, inode, size, mtime, ctime, and
  SHA-256;
- enumerate the npm runtime root with a maximum of 4,096 entries and 64 MiB total regular-file bytes;
- reject devices, sockets, FIFOs, hard links, path escapes, case collisions, mutable replacement, and any
  symlink whose target escapes the runtime root;
- bind relative path, type, link target when present, mode, size, and SHA-256 into an ordered tree digest;
- record the exact Node-linked native library list as diagnostic evidence without claiming full dynamic
  loader closure; and
- revalidate the complete snapshot before containment testing and immediately before npm launch.

If npm needs a file outside the approved runtime and private workspace, execution fails. The architecture is
not broadened automatically in response to a permission error.

## Private workspace

Use one newly created APG-owned `0700` directory outside any project. Bind its canonical path, device,
inode, owner, and mode. Pre-create exact `0600` files and private subdirectories for:

```text
package.json
user.npmrc             # empty, never copied from the user
global.npmrc           # empty, never copied from the user
package-lock.json      # absent before launch; exclusive expected output
cache/
logs/
tmp/
prefix/
broker-profile.sb
```

The initial package manifest contains only a fixed synthetic workspace name/version and no scripts,
workspaces, package-manager declaration, config, or prior dependencies. npm may update only this manifest,
create the lock, and write bounded metadata cache/log/bookkeeping beneath the listed roots.

Before launch, capture a complete tree manifest. After exit, reject:

- `node_modules` at any depth;
- `.npmrc` other than the two owned empty files;
- tar/gzip/zip magic, `.tgz`, extracted package trees, executable files, symlinks, special files, hard links,
  unknown top-level paths, or files outside the root;
- cache growth inconsistent with the broker's bounded metadata-byte ledger;
- package or lock files above 4 MiB; or
- any replacement of the workspace root or pre-created files.

Raw cache, logs, lockfile, manifest, Seatbelt profile, and route token are temporary. Only the compiled safe
candidate and bounded report may leave the workspace after successful cleanup.

## Containment provider

### Why Node alone is rejected

The npm process needs a TCP connection to the loopback broker. On this Node build, omitting `--allow-net`
denies that connection, while adding it permits arbitrary network destinations. Monkey-patching `net`, DNS,
or npm fetch code is not a security boundary and changes the generator being measured. Proxy variables also
do not prevent bypass. None qualifies.

### macOS Seatbelt development provider

The generated profile must deny network by default and allow only outbound TCP to the exact
`127.0.0.1:PORT`. It must deny inbound/bind, Unix-domain network paths not explicitly required, every other
loopback port, local-interface destination, DNS socket, IPv6 destination, and public destination. The
implementation may use a permissive non-network base only if Node's separate Permission Model supplies the
accepted filesystem/process restrictions and the generated Seatbelt network profile has no inherited broad
network macro.

Launch without a shell:

```text
/usr/bin/sandbox-exec
  -f <exact generated profile>
  <exact node realpath>
  --permission
  --allow-net
  --allow-fs-read=<exact npm runtime root>
  --allow-fs-read=<exact private workspace>
  --allow-fs-write=<exact private workspace>
  <exact npm-cli.js realpath>
  <exact npm arguments>
```

Do not pass `--allow-child-process`, `--allow-worker`, `--allow-addons`, `--allow-ffi`, `--allow-wasi`, or
`--allow-inspector`. The Seatbelt process tree inherits its network restriction. Any npm attempt to spawn a
helper is independently denied by Node.

Before approval, a repo-owned inert fixture must run under the exact generated profile and prove:

1. the approved broker port accepts a TCP connection;
2. another loopback listener on a different random port is denied;
3. a listener bound to a current non-loopback local interface is denied;
4. IPv6 loopback is denied;
5. DNS/public access is not attempted during the test;
6. child spawn, worker creation, addon loading, and a write outside the private root are denied by Node; and
7. profile/binary/workspace identity is unchanged after the test.

Self-tests use only local repo-owned fixtures and sockets. They do not contact Apple, npm, DNS, a LAN peer,
or the public internet. If the host has no non-loopback interface, that one negative test is unavailable and
the provider is not accepted for a real run.

Because Seatbelt is deprecated/private, this evidence is valid only for the exact local OS build and plan.
It is not cached across reboot, OS update, binary change, profile change, or port change. A future supported
provider must receive a new Architecture Check.

## Metadata broker

The broker binds only `127.0.0.1` on one random high port and begins disarmed. Before approval it rejects
every request and has no public-network authority. The plan binds the actual listener identity, port, random
128-bit session route digest, broker runtime digest, and limits.

After durable authorization evidence, arming permits only:

```text
GET /<session-route>/<encoded-package-name>
```

Package names must parse canonically as either one unscoped name or one scoped name. Percent-encoding must
have one accepted canonical form. The broker rejects version subpaths, `/-/`, `.tgz`, search, ping, audit,
security, bulk, replication, CouchDB, write, owner, token, dist-tag, query, fragment, CONNECT, upgrade,
WebSocket, and every method other than GET.

For an accepted package name the broker constructs, rather than forwards, the outbound URL:

```text
https://registry.npmjs.org/<canonical encoded package name>
```

Outbound requests use TLS verification, no redirects, no proxy environment, and a minimal explicit header
set. They send no Authorization, cookie, referrer, npm token, user path, prompt, policy, audit record, or
telemetry. Incoming npm headers are not forwarded except an allowlisted public packument `Accept` value;
outbound encoding is `identity`.

Each response is buffered only up to 8 MiB before relay, parsed as strict UTF-8 JSON with duplicate-key and
depth/key limits, and required to have status 200, JSON content type, exact final URL/origin, and a matching
top-level package name. Every relayed response is counted atomically before its body is exposed to npm. Raw
packuments are not written by APG or retained in the report; npm's own temporary cache remains inside the
workspace and is deleted.

Initial ceilings:

```text
unique package names: 256
total broker requests: 512
concurrent public requests: 8
per response: 8 MiB
aggregate response bodies: 128 MiB
per request: 15 seconds
complete genesis: 120 seconds
npm stdout: 256 KiB
npm stderr: 256 KiB
package.json/package-lock.json: 4 MiB each
```

The first exceeded limit disarms the broker, aborts outstanding public requests, terminates npm's process
group, and makes the session incomplete. Retries require a new plan and approval because public GET side
effects may already have occurred.

## Exact npm launch

Invoke the exact npm CLI with an argument array, no shell, no wrapper, and no `npx`:

```text
install
@modelcontextprotocol/server-filesystem@2026.7.10
--package-lock-only
--save-exact
--ignore-scripts
--audit=false
--fund=false
--update-notifier=false
--workspaces=false
--bin-links=false
--allow-directory=none
--allow-file=none
--allow-git=none
--allow-remote=none
--replace-registry-host=never
--registry=http://127.0.0.1:<port>/<session-route>/
--cache=<private cache>
--userconfig=<empty private user config>
--globalconfig=<empty private global config>
--prefix=<private prefix>
--logs-dir=<private logs>
--loglevel=warn
```

The implementation must verify every flag against the exact snapshotted npm `11.16.0` config definitions
before creating the plan. It must reject npm aliases, tags, ranges, alternate registries, configuration
files, positional extras, pass-through arguments, and environment-derived config.

The child environment is built from empty and contains only exact private HOME/TMP/cache/config/prefix
values plus a deterministic UTF-8 locale if required. Do not forward PATH, NODE_OPTIONS, npm_config values,
HOME, proxies, NO_PROXY, CA/certificate variables, auth variables, CI variables, editor/shell values, or
telemetry identifiers. The exact Node executable directly loads the exact npm CLI, so PATH is unnecessary.

stdin is closed. stdout/stderr are bounded and consumed only for a sanitized in-memory diagnostic. Raw
output and private paths are not persisted. Timeout/cancel terminates the complete process group. Exit zero
is necessary but never sufficient.

## Post-run validation and compiler handoff

After npm exit and broker disarm:

1. require a zero exit with no timeout, cancellation, permission denial, or output overflow;
2. require the broker ledger to contain only accepted metadata GETs and no rejected/unknown request;
3. require no open/outstanding broker request and no npm descendant process;
4. verify the exact workspace post-state and absence of package/archive/materialized content;
5. require `package.json` to contain only the synthetic root fields and the one exact target dependency;
6. read the bounded lock through a retained no-follow descriptor and reject replacement during read;
7. pass the parsed lock plus exact runtime identity to `ExactGraphCandidateAuthority`;
8. create a deterministic safe graph report listing only public names, exact versions, public origins,
   SHA-512 values, install paths, node/edge counts, compiler result, provider ID, and digests;
9. delete the complete exact owned workspace without following links and verify absence; and
10. record terminal cleanup/audit evidence before `ControlledGraphGenesisAuthority` authenticates the
    candidate/report pair.

The compiler is authoritative about supported lock semantics. Optional, peer, bundled, link, file, git,
remote, workspace, install-script-required, platform-selector, unsupported key, path, reachability, cycle,
integrity, or URL behavior rejects the candidate even if npm exits zero.

## State and audit ordering

```text
RUNTIME_SNAPSHOTTING
  -> CONTAINMENT_SELF_TESTING
  -> PLAN_READY
  -> GRAPH_GENESIS_APPROVAL_PENDING
  -> AUTHORIZED
  -> BROKER_ARMING
  -> GRAPH_GENERATING
  -> LOCK_VALIDATING
  -> CANDIDATE_COMPILED_PENDING_CLEANUP
  -> CLEANUP_PENDING
  -> GENESIS_COMPLETE

Denied/expired/replayed approval -> GENESIS_NOT_STARTED
Failure before first public GET -> GENESIS_FAILED_NO_EXTERNAL_READ
Failure after first public GET -> GENESIS_INCOMPLETE
Cleanup ambiguity -> GENESIS_INCOMPLETE_QUARANTINE
```

Minimum evidence order:

```text
runtime_snapshot_complete
containment_self_test_complete
graph_genesis_plan_ready
graph_genesis_authorized
broker_armed                    # before first public GET
npm_spawn_started               # before process creation
metadata_request_started        # before each public request
metadata_response_validated
npm_terminal_observed
lock_validation_started
candidate_compiled
cleanup_complete | cleanup_incomplete
genesis_complete | genesis_incomplete
```

An audit failure before arming blocks egress. A failure after a public request never retries, conceals the
read, or authenticates a candidate. This checkpoint does not authorize a persistent audit schema change;
the first controlled run may use an isolated temporary report/audit sink and export only safe deterministic
evidence.

## Approval boundaries

| Boundary | Approval required | Permitted consequence | Not permitted |
| --- | --- | --- | --- |
| Architecture Check | current approval | design/read-only diagnostics/docs | implementation, npm, broker, registry |
| network-free foundation | architecture acceptance | local source/tests, fake registry, local sockets, inert Seatbelt fixtures | npm launch or public request |
| real graph genesis | exact one-time plan approval | bounded anonymous packument GETs and private temporary lock/cache/log writes | tarball, install, materialization, startup |
| exact metadata confirmation | later complete graph approval | listed exact package/version metadata GETs | graph resolution or tarball |
| artifact acceptance | later full-artifact approval | exact tarball GETs and private read-only inspection files | Pass B or execution |
| production registration | later repository-change approval | add reviewed accepted profile source | runtime side effect |
| materialization | later stage approval | exact private Pass-B stage writes | startup |
| startup | later launch approval | one exact staged MCP process | download or tool action |
| MCP action | existing policy/approval | one exact routed tool call | direct bypass |

No row grants another. Direct npm/npx remains outside APG protection.

## Failure and cleanup

| Failure | Required result |
| --- | --- |
| runtime/profile/workspace drift | fail before approval or broker arm |
| provider unavailable or self-test failure | block; no fallback |
| denied/expired/replayed approval | no npm, no public GET |
| unexpected npm request | reject, disarm, terminate, incomplete |
| tarball or non-packument request | reject before public forwarding |
| registry redirect/status/type/size/JSON/name failure | do not relay body; incomplete |
| request/byte/time/output/file limit | abort broker, terminate group, incomplete |
| npm permission request outside contract | fail; do not widen automatically |
| npm nonzero/timeout/cancel | no candidate authority |
| `node_modules`, archive, executable, symlink, unknown file | quarantine; no candidate authority |
| compiler rejection | safe diagnostic only; no next phase |
| terminal audit failure | incomplete even if lock/compiler succeeded |
| cleanup ambiguity | retain exact residue identity for manual review; no broad deletion |

Cleanup only removes the exact captured workspace and descendants whose identities and containment are
revalidated. It never follows a symlink, adopts an unknown path, deletes a parent, or sweeps npm/user cache.

## Privacy

Externally disclosed: source IP, request timing, registry origin, and recursively requested public package
names. The registry naturally learns the graph metadata set.

Never read or sent: user `.npmrc`, `.env`, token, key, certificate, login state, proxy, prior cache, project
path/content, prompt, policy, approval body, audit database, Google Drive, Apple credentials, or telemetry.

Never committed: raw packuments, npm cache/logs, package-lock genesis workspace, Seatbelt profile containing
private paths, route token, private absolute paths, stdout/stderr, or local file identities.

## Network-free implementation strategy

After explicit architecture acceptance, the next checkpoint may implement only:

1. plan, approval, controlled-genesis evidence, safe report, and state schemas;
2. exact runtime-tree and workspace snapshot authorities without launching npm;
3. broker request grammar, packument validator, ceilings, and fake public transport;
4. a containment-provider interface and fake provider;
5. a generated Seatbelt profile plus repo-owned local-only positive/negative fixture tests;
6. exact npm argument/environment builder without spawning npm;
7. post-state/lock handoff using synthetic fixtures;
8. cleanup and audit-failure tests; and
9. documentation/state updates.

It must not contact the registry, launch real npm/npx, download an artifact, modify a user project, add a
dependency, register a profile, perform Pass A/B, materialize a stage, change the database, or start MCP code.

The actual Seatbelt self-test result from foundation tests is not reusable as real-run evidence; the exact
real plan must repeat it before approval because its port, profile, workspace, binary, and OS state differ.

## Test strategy

Default network-free tests cover:

- authority forgery, plan mutation, replay, expiry, runtime/profile/port/root/limit substitution;
- runtime enumeration bounds, escaping symlinks, special files, hardlinks, case collisions, byte/count
  overflow, executable/tree drift, and private-path-safe errors;
- broker canonical package parsing, scoped encoding, route isolation, methods, tarball/endpoint rejection,
  redirects, status/type/length/UTF-8/JSON/duplicate/depth/key/name failures, concurrency, request/body/time
  ceilings, and header non-forwarding;
- local Seatbelt exact-port success plus alternate-loopback/non-loopback/IPv6 denial, Node write/child/
  worker/addon denial, provider identity drift, unsupported host, and no broad-network fallback;
- exact command/environment golden values, unknown flags, pass-through args, inherited npm/proxy/auth/CA/
  NODE_OPTIONS rejection, closed stdin, output bounds, timeout/cancel/process-group termination using inert
  fixtures only;
- workspace pre/post manifests, unexpected files, `node_modules`, archive magic, executable/symlink/hardlink,
  lock replacement, compiler rejection, exact cleanup, cleanup ambiguity, and audit failures before/after
  the synthetic external-read boundary; and
- no real npm/npx launch, registry host resolution, public socket, artifact byte, production authority,
  materialization, package code, or persistent DB write in default tests.

Before a real run, review the generated plan and self-test report. After the run, independently inspect the
safe graph summary and broker request ledger before considering exact metadata confirmation.

## Alternatives considered

### Node Permission Model alone

Rejected. `--allow-net` is not host/port scoped on the exact Node build. It would permit npm to bypass the
broker and reach any destination.

### Proxy environment variables or HTTP monkey patching

Rejected. A process can bypass proxy settings, and monkey patching npm/Node networking is neither complete
containment nor the exact generator being reviewed.

### Deprecated Seatbelt as a production product feature

Rejected. The tool and profile language are deprecated/private and may change without notice. V0 limits it
to one exact development host/build with a fresh fail-closed self-test.

### Docker internal network

Rejected for the first darwin-arm64 profile. A Linux container changes platform resolution evidence, the
Docker daemon is not currently an accepted dependency, and image acquisition adds another network/artifact
boundary.

### Direct npm with credential stripping but no egress containment

Rejected under the accepted architecture. Credential stripping reduces disclosure but cannot prove that
tarball/unknown requests did not bypass the broker.

### Implement APG's own npm dependency resolver

Rejected. Reproducing Arborist's selection/hoisting behavior would create a second resolver and would not
establish the exact npm layout intended by this milestone.

### Reuse an existing lockfile or npm cache

Rejected. Existing files may contain stale, project-specific, authenticated, or previously fetched state
and do not prove the exact controlled genesis.

## Known risks and mitigations

| Risk | Mitigation | Release-blocking condition |
| --- | --- | --- |
| Seatbelt is deprecated/private | one-host development provider, exact OS/binary/profile binding, fresh self-test, no fallback | missing/changed provider or any negative-test escape |
| Node network grant is broad internally | Seatbelt exact destination is mandatory; Node still denies process/filesystem capabilities | npm runs with `--allow-net` outside authenticated provider |
| exact npm runtime may be compromised | bounded complete JS-tree snapshot and revalidation; no trust/safety claim; later metadata/artifact checks | runtime drift or incomplete tree enumeration |
| npm may request an unexpected endpoint | broker closed grammar and fail-first termination | request is forwarded before classification |
| registry metadata may be malicious | byte/time limits, strict JSON validation, no code execution, compiler rejects unsupported selected behavior | unbounded/body-before-validation relay |
| package-lock-only behavior may drift | exact npm version/args, workspace post-state, no artifact/node_modules assertion | any content download/materialized output |
| same-user race | private roots, no-follow descriptors, identity snapshots, immediate revalidation | ambiguous replacement or cleanup |
| raw metadata cache/log residue | exact private workspace, bounded inventory, verified cleanup | cleanup uncertainty |
| graph may be platform-specific | bind darwin-arm64, exact OS/Node/npm, reject optional/platform selectors | claim reused on another platform/runtime |
| metadata reads remain externally observable | explicit approval disclosure and public-name-only requests | undisclosed registry or package request |
| direct npm remains possible outside workflow | explicit UX: APG protects only this controlled invocation | claim that APG intercepts terminal npm/npx |

## Decision requested

Approve the bounded genesis plan, exact runtime/workspace/broker boundaries, separate controlled-genesis
authority, credential-free exact npm contract, closed metadata request grammar, and the development-only
macOS Seatbelt provider with a fresh exact-build fail-closed self-test.

Acceptance authorizes only the network-free implementation strategy above. It does not authorize running
npm, contacting the public registry, arming a real broker, or creating the actual Filesystem candidate.

## Rollback

This Architecture Check changes documentation/state only. Rollback is deletion of this document and reversal
of its state reference. No broker, socket, npm process, external request, lock, cache, artifact, database, or
package process was created.

## Next

Prepare the exact real genesis plan from fresh runtime, workspace, broker-listener, provider-binary, and OS
snapshots. Repeat the complete local-only containment probe with that plan's exact port, profile, workspace,
and binaries. Present the safe plan summary for separate one-time approval before starting real npm or
allowing the broker to make any public registry request.

## Network-free foundation result

The accepted foundation now provides separate runtime-tree, workspace, containment, plan, synthetic
approval, broker-ledger, audit, compiler-handoff, and controlled-completion authorities. The broker uses an
injected transport only; no production HTTP server or HTTPS transport exists. It accepts one canonical
packument route, constructs the public URL itself, validates bounded strict JSON before returning bytes,
keeps only a safe digest ledger, and disarms on rejection, timeout, or authorization replay.

The exact launch builder emits the reviewed shell-free argument vector and an environment built from empty.
The workspace validator binds protected-file identities and rejects unexpected roots, `node_modules`, links,
special/hard-linked/executable files, archive magic, oversized state, and exact manifest/lock mismatch. The
closed lock compiler can produce a candidate from synthetic fixture state, but controlled authority requires
the genuine one-time authorization, terminal broker ledger, exact cleanup, and ordered synthetic audit.

On the current Mac, a repo-owned local-only fixture also demonstrated that the generated Seatbelt profile
allowed only its chosen IPv4 loopback port while rejecting another loopback port, a listener on the current
non-loopback interface, and IPv6 loopback. Layered Node permissions denied a write outside the private root,
child process, worker, and addon grants. The probe contacted no DNS, LAN peer, or public address. It is not
reusable evidence for a real run and does not change the development-only/private-interface limitation.
