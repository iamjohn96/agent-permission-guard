# Upstream Provenance v0 Architecture Check

Status: accepted by Jonny on 2026-09-07. The network-free Upstream Launch Integrity Foundation is
committed and pushed at `1fee336`. No production launch profile,
package download, registry access, external package execution, dependency change, database migration,
receipt schema change, or stronger public provenance claim was added.

## Decision summary

APG should not upgrade `configured_label_only` merely because it can hash `node`, `npx`, a wrapper, or a
command string. Those observations do not establish which JavaScript package bytes or transitive
dependencies execute.

The recommended v0 is an **Upstream Launch Integrity Foundation**:

- prepare one immutable upstream launch snapshot before process creation
- resolve the configured command once to an absolute local executable
- bind a bounded local file snapshot and exact argument vector in memory
- revalidate the same launch snapshot immediately before spawn
- make the prepared snapshot the only source accepted by the STDIO transport
- introduce a trusted launch-profile interface and synthetic tests, but no production provenance profile
- retain `server_provenance_assurance: configured_label_only` in all production receipts

This reduces accidental command substitution and creates a safe foundation for later evidence. It does
not authenticate an npm publisher, registry response, package tarball, installed dependency tree,
running process, or official server build.

A production package-provenance upgrade requires a later, separately approved **Verified MCP Package
Stage**. That design must separate metadata read, package download/staging, and package startup as three
distinct consequence boundaries and must verify code before any package code executes.

## Problem

The first production Exact MCP Identity profile proves that APG routed an exact zero-parameter
`list_allowed_directories` request under a reviewed schema. It intentionally does not prove which
upstream implementation received the request.

Today the proxy accepts an arbitrary command and arguments:

```text
apg proxy ... -- <upstream-command> [args...]
```

The MCP client library resolves and spawns that command after APG opens policy and audit state. APG does
not currently create a trusted launch identity, independently bind the executable selected from `PATH`,
or attach launch evidence to the action identity.

Several shortcuts look stronger than they are:

- hashing `node` proves only the interpreter file, not the script or imported modules
- hashing `npx` proves only the launcher, not the downloaded package
- recording `package@version` proves configured intent, not package bytes
- trusting a lockfile proves local metadata content, not that every executed byte was independently
  verified before startup
- matching `tools/list` proves an advertised interface, not implementation identity
- hashing arbitrary arguments can expose low-entropy private paths or secrets to offline guessing

The architecture must therefore separate launch configuration, locally observed artifacts, registry
artifacts, publisher identity, dependency-graph identity, and runtime attestation.

## Vocabulary and assurance ladder

These dimensions must not be collapsed into one green “verified” label.

| Dimension | Meaning | v0 status |
| --- | --- | --- |
| configured server label | APG used the configured logical server ID | existing |
| launch configuration | command, arguments, cwd, and environment contract selected for spawn | prepared locally in v0 |
| local executable snapshot | APG observed a local executable file before spawn | internal evidence only in v0 |
| interpreted entrypoint | script/module selected by an interpreter or launcher | not generally covered |
| top-level package artifact | exact registry tarball bytes match a reviewed integrity value | deferred |
| dependency graph | every transitive artifact is resolved and verified | deferred |
| publisher identity | a trusted publisher or signing identity produced the artifact | deferred |
| runtime attestation | reviewed code is the code running in an isolated environment | out of scope |

Reserved technical values should evolve independently:

```text
server_provenance_assurance:
  configured_label_only
  local_code_snapshot          # future, only after a qualifying production profile
  registry_artifact_verified   # future
  signed_build_verified        # future
  runtime_attested             # future

launch_configuration_assurance:
  unbound
  prepared_snapshot
  profile_scoped
  complete_code_selection      # future and profile-specific
```

`prepared_snapshot` is not server provenance. Production receipts remain
`configured_label_only` during v0.

## Claims and non-claims

### V0 may claim internally

- APG cloned and froze one configured upstream launch request.
- APG resolved one local executable before spawn without invoking a shell.
- APG observed a bounded file identity for that executable.
- APG revalidated the prepared launch immediately before asking the transport to spawn it.
- The transport received the same immutable command, argument vector, cwd, and environment snapshot.
- A mismatch failed before upstream process creation.

### V0 must not claim publicly

- the server is official, authentic, safe, or publisher-verified
- a `node` or `npx` hash identifies the executed package
- a package name and version identify downloaded bytes
- the top-level package integrity covers transitive dependencies
- the process could not change after the final check
- loaded dynamic libraries, imported modules, child processes, or network effects were covered
- the upstream process was sandboxed or remotely attested
- an unsigned APG receipt authenticates its issuer

## Threat model

### In scope

- accidental `PATH` substitution between configuration and spawn
- replacement or mutation of the resolved executable before spawn
- mutable command/argument objects inside APG
- shell interpretation or argument reconstruction drift
- assurance inflation from a launcher hash or package string
- unsafe persistence of raw command arguments, paths, or environment values
- receipt-version confusion if future launch evidence is added
- profile failure silently downgrading a required launch guarantee

### Out of scope for v0

- compromised APG process, kernel, root account, or package manager
- malicious same-user process racing after the final validation
- atomic execute-from-verified-file-descriptor guarantees
- complete dynamic-library or interpreted-module closure
- npm publisher identity or registry transparency
- complete transitive package verification
- OS sandboxing, code signing, notarization, or confidential-compute attestation
- startup side-effect containment

## Proposed architecture

```text
parsed proxy configuration
  -> trusted Launch Authority
  -> resolve command without a shell
  -> inspect bounded local executable
  -> clone + deep-freeze PreparedUpstreamLaunch
  -> immediate pre-spawn revalidation
  -> STDIO transport accepts PreparedUpstreamLaunch only
  -> upstream process starts
  -> existing tools/list + Exact MCP Identity preflight
  -> existing policy / approval / receipt flow
```

### PreparedUpstreamLaunch

Conceptually:

```text
PreparedUpstreamLaunch
  server_id
  executable
    resolved_path              # memory only
    sha256                     # memory only in v0 production
    device
    inode
    size
    mode
  arguments                    # exact frozen array, memory only
  cwd                          # resolved path, memory only
  working_directory_identity   # device/inode/mode, memory only
  environment                  # exact frozen allowlisted map, memory only
  snapshot_format
  launch_profile_result?       # trusted result; synthetic only in v0
```

The raw parsed configuration must not remain an alternate dispatch source. The transport interface
should accept only the prepared object.

### Command resolution

- Reject an empty command, NUL, and unsupported platform forms.
- When the command contains a path separator, resolve it against the prepared cwd and then use
  `realpath`.
- Otherwise search the exact prepared `PATH`; ignore empty entries instead of treating them as cwd.
- Require a regular executable file and impose a bounded size before hashing.
- Do not follow a second resolution path in the transport.
- Preserve `shell: false` and the exact argument array.
- Sanitize errors so local paths and arguments are not echoed.

Executable ownership and mode may be recorded locally as diagnostic evidence. They are not proof of
publisher identity, and world-writable or unexpected-owner handling should remain profile-specific until
cross-platform semantics are reviewed.

### Revalidation and TOCTOU

Immediately before spawn, compare:

- canonical working-directory path, device, inode, and mode
- realpath
- device and inode where meaningful
- regular-file type
- size and mode
- SHA-256 bytes
- canonical prepared launch digest

Any mismatch fails before spawn. The final transport call must use the already resolved absolute path.

This narrows but does not close the race between the final file read and the operating system loading the
file. Node does not provide a portable execute-from-open-file-descriptor primitive for this path. The UX
must say “pre-spawn local snapshot,” not “immutable executable.”

### Interpreter and launcher boundary

Executable hashing alone is insufficient when arguments select code. Examples include:

- `node server.js`
- `python -m package`
- `sh script.sh`
- `npx package@version`
- `npm exec --package=...`

A future production launch profile must understand and bind every code-selecting argument and referenced
entrypoint. A generic denylist of interpreter names is not a trustworthy completeness mechanism. Without
a qualifying built-in profile, APG must retain `configured_label_only` regardless of the outer executable
hash.

### Trusted launch profiles

The launch-profile model should mirror Exact MCP Identity:

- APG-shipped and explicitly selected
- versioned immutable manifest
- closed command/argument grammar
- typed public code selectors only
- declared private or unbound configuration categories
- bounded file-set rules
- runtime-authenticated result that generic callers cannot forge
- required-profile failure closes startup before spawn

User-authored selectors and automatic inference from command strings are deferred. A profile can describe
what was checked; it cannot grant an Allow decision or strengthen tool-action identity.

V0 should implement this interface only with synthetic profiles. Shipping a Filesystem npm launch profile
before package staging would encourage users to misread configured `npx` intent as verified package code.

## Package provenance boundary

### Why arbitrary npx cannot qualify

`npx` combines resolution, download, installation, and execution. APG can bind the `npx` file and exact
package string, but package code may be selected and fetched after the last APG pre-spawn check. The
existing acceptance harness therefore remains valid compatibility evidence only.

It must not be reclassified as provenance evidence.

### Required future staged flow

A later Verified MCP Package Stage should use explicit phases:

```text
1. metadata read
   exact package + version + registry + integrity

2. package stage
   private credential-free environment
   download without executing package code
   lifecycle scripts disabled
   verify top-level tarball before extraction
   bounded safe extraction
   resolve entrypoint and dependency graph
   produce immutable stage manifest

3. package launch
   revalidate stage manifest and code tree
   finalize launch evidence before startup
   launch exact staged entrypoint without npx resolution
```

Metadata read, download/staging, and startup/execution require separate user-visible boundaries. Staging
must not silently authorize execution, and execution must not silently permit new registry access.

Top-level SHA-512 integrity alone supports at most `registry_artifact_verified` for that top-level tarball.
It does not authenticate the publisher and must declare transitive dependencies unverified until every
executed artifact is covered.

## Receipt and persistence strategy

V0 should not change production receipt bytes or add a stronger production assurance value.

The foundation can keep the prepared launch snapshot in memory and exercise trusted launch results only
in network-free tests. This avoids stabilizing a receipt claim before a qualifying production profile
exists.

When the first production launch profile is separately accepted:

- add a distinct `serverEvidence` object rather than overloading MCP action parameter evidence
- use receipt schema 1.2 while retaining strict 1.0 and 1.1 verification
- attach the same immutable server evidence to every action handled by one upstream process
- keep action assurance and server provenance orthogonal
- avoid a database migration by carrying additive evidence in receipt-finalization events if possible
- stop for a separate migration Architecture Check if additive events are insufficient

No raw executable path, cwd, full arguments, environment values, private directory, token, `.env`,
`.npmrc`, or low-entropy sensitive hash may enter portable evidence. A private executable digest can also
identify proprietary software; disclosure requires an explicit production-profile privacy decision.

## STATE / PERMISSION / FAILURE / DATA

### State

- parsed launch configuration: short-lived input
- prepared launch snapshot: immutable process memory
- resolved executable evidence: immutable process memory in v0
- launch profile registry: immutable APG code; synthetic only in v0
- upstream schema snapshot: existing process-lifetime state
- receipts: unchanged in production during v0
- package cache or stage: none in v0

### Permission

- normal proxy users keep current behavior and claims
- launch evidence never changes Allow, Ask, Deny, or risk score
- a future explicit launch profile may require its own assurance but cannot auto-select itself
- profile mismatch cannot be repaired by human approval
- registry metadata, package download, stage creation, and package startup remain separate approvals
- direct MCP, node, npm, and npx commands remain outside APG coverage

### Failure

| Failure | Required behavior |
| --- | --- |
| empty or unresolved command | fail before upstream spawn |
| non-regular or oversized executable | fail before upstream spawn |
| snapshot or hash failure | fail before upstream spawn |
| prepared configuration mutation | reject; no alternate raw dispatch path |
| pre-spawn revalidation mismatch | fail before upstream spawn |
| unknown required launch profile | fail before database/upstream initialization where possible |
| launch profile mismatch | fail before upstream spawn; no downgrade when required |
| upstream startup failure | close resources; no tool-action receipt fabricated |
| tool schema/profile mismatch | preserve existing post-start fail-closed behavior |
| process changes after final check | outside atomic guarantee; do not claim immutability |
| receipt write failure for a later tool call | preserve existing no-dispatch behavior |

Errors use stable reason codes and must not include command arguments, absolute paths, environment values,
or observed file bytes.

### Data

```text
command + args + cwd + allowlisted environment
  -> local-only preparation and file reads
  -> immutable PreparedUpstreamLaunch
  -> local-only revalidation
  -> exact shell-free spawn
  -> existing MCP protocol flow
```

V0 performs no registry request, package download, credential lookup, external write, telemetry, or new
persistent data operation.

## Policy, approval, and UX

Launch evidence is not authorization. It must not lower an existing policy decision or risk score.

V0 user-facing production wording remains:

```text
Server provenance: Configured label only
Launch preparation: Local pre-spawn checks applied
Package, publisher, dependencies, and runtime are not verified.
Protected only when MCP calls are routed through APG.
```

Do not use:

- Official server verified
- Package verified
- Trusted executable
- Tamper-proof launch
- Attested runtime
- Complete dependency integrity

The existing Filesystem profile remains exact only for the adapter request. Its result, allowed-directory
state, server code, and child effects remain separate limitations.

## Options considered

### A. Hash the configured command string

Rejected. It binds text, not PATH resolution or executed bytes, and may expose private arguments through
guessable digests.

### B. Hash only node or npx

Rejected as provenance. Interpreters and launchers select code through arguments and later package
resolution.

### C. Treat package@version and lockfile integrity as pre-execution proof

Rejected. They are metadata unless APG independently verifies the artifact that will execute. Existing
Install Guard lockfile verification occurs after npm execution and cannot establish MCP startup
provenance.

### D. Add generic local executable snapshot claims immediately

Rejected for production v0. Dynamic libraries, interpreters, private binary fingerprints, and the final
load race make a generic green claim easy to misunderstand.

### E. Build the immutable launch foundation without strengthening production claims

Recommended. It closes internal configuration drift, enables fail-closed revalidation, and creates a
reviewable seam for future launch profiles without claiming unavailable package evidence.

### F. Implement complete verified package staging now

Deferred. It needs download, safe extraction, persistent-stage lifecycle, transitive resolution,
integrity verification, cleanup, disk limits, concurrency, upgrade, and startup approval decisions.

### G. Use OS code signing or remote attestation

Deferred and not portable. Code signing, notarization, signer trust, sandboxing, and attestation solve
different layers and require separate architecture.

## Risk register and mitigation

| Risk | Preventive mitigation | Detection/recovery | Residual risk |
| --- | --- | --- | --- |
| wrong PATH executable | resolve once; ignore empty PATH entries; spawn absolute path | snapshot/revalidation mismatch | malicious same-user race remains |
| executable mutation | bounded SHA-256 plus dev/inode/size/mode; recheck before spawn | fail before startup | no atomic execute-from-snapshot |
| mutable APG launch object | deep clone/freeze; transport accepts prepared object only | mutation and alternate-source tests | in-process compromise out of scope |
| launcher hash overclaim | separate launch configuration from provenance | invariant and UX tests | users may ignore limitations |
| interpreter selects other code | require built-in closed profile before stronger assurance | profile rejects unbound selectors | imported/dynamic code may remain incomplete |
| package version substitution | no production package claim in v0 | retain configured-label wording | current npm-launched server remains unauthenticated |
| transitive dependency substitution | defer package assurance until staged graph design | explicit unverified-graph limitation | package startup risk remains |
| secret/path disclosure | memory-only raw values; no arbitrary argument digest/export | forbidden-value tests | safe public metadata may identify software |
| private binary fingerprint disclosure | no production digest export in v0 | receipt byte fixtures | future profile needs explicit privacy review |
| launch evidence changes policy | keep evidence orthogonal to risk/decision | Allow/Ask/Deny regression matrix | internal integration bug remains possible |
| startup side effects | no package execution in v0 tests | synthetic spawn adapter | later real server startup remains uncontained |
| direct bypass | retain routed-through-APG warning | receipt/UX assertions | APG cannot discover bypasses |
| schema/receipt fragmentation | defer 1.2 until first real profile | 1.0/1.1 golden tests unchanged | future migration complexity remains |

Release-blocking v0 controls are immutable prepared launch, one dispatch source, absolute shell-free
spawn, immediate revalidation, sanitized failures, no production provenance upgrade, no raw launch data
persistence, and fully network-free tests.

## Network-free implementation scope requiring approval

If this Architecture Check is accepted, the first implementation is limited to:

1. add immutable `PreparedUpstreamLaunch` and local snapshot types
2. add a centralized launch authority with runtime-trusted synthetic profile results
3. resolve a command deterministically and inspect a bounded regular executable
4. revalidate the snapshot immediately before spawn
5. make the STDIO transport accept only the prepared snapshot
6. preserve `shell: false`, exact arguments, cwd, and allowlisted environment
7. add sanitized failure codes and no-path/no-argument error tests
8. add unit and synthetic integration tests for mutation, PATH drift, file drift, interpreter overclaim,
   and unchanged proxy behavior
9. update architecture/state documentation

The implementation must not:

- add a production launch profile or stronger production receipt assurance
- change Allow, Ask, Deny, approval, or risk semantics
- add a CLI option until a production profile has its own Architecture Check
- add receipt schema 1.2 or change existing receipt bytes
- access a registry, download or install a package, or execute an external MCP package
- read `.npmrc`, `.env`, tokens, keys, credentials, or signing material
- add a dependency or database migration
- create a persistent package stage or cache
- add code signing, sandboxing, telemetry, external writes, publish, deploy, commit, or push authority

## Test strategy

### Unit

- path command and PATH command resolve deterministically
- empty PATH entries cannot select cwd
- relative cwd is canonicalized once
- symlink resolution is explicit and stable
- non-file, non-executable, oversized, missing, and changing targets fail safely
- each command/argument/cwd/environment mutation changes internal launch identity
- private values never appear in error text or persisted evidence
- unknown or untrusted launch profiles cannot elevate assurance
- interpreter and launcher fixtures cannot claim package provenance

### Synthetic integration

- gateway starts only from `PreparedUpstreamLaunch`
- validated absolute path is the path passed to the transport
- file drift between preparation and revalidation prevents spawn
- mutation after preparation cannot affect the child configuration
- normal proxy behavior, policy decisions, approvals, audit, and receipts remain unchanged
- production receipt fixtures remain byte-identical at schemas 1.0 and 1.1
- default suite makes no network request and starts no external package

### Later real acceptance

No real acceptance is part of v0. The first production launch profile must receive a separate Architecture
Check and explicit execution approval that names:

- the exact executable or package/version
- whether registry metadata is read
- whether a tarball or dependencies are downloaded
- whether package code starts
- writable directories and cleanup behavior
- the exact assurance and residual limitations to be recorded

## Acceptance criteria

- Current production receipts still say `configured_label_only`.
- Current Exact MCP action identity and policy semantics are unchanged.
- Only one immutable prepared launch object can reach the transport.
- Command resolution does not use a shell and cannot reinterpret empty PATH entries as cwd.
- Executable drift detected before spawn fails closed.
- No generic interpreter or launcher is represented as package or server provenance.
- No raw launch arguments, paths, environment values, or unsupported sensitive hashes are persisted.
- Existing receipt schemas and golden bytes remain unchanged.
- All default tests remain network-free.
- No dependency, database migration, registry access, package operation, credential access, or external
  write is introduced.

## Decision checkpoint

Accepted decision: implement only the network-free Upstream Launch Integrity Foundation and keep all
production server provenance at `configured_label_only`.

Implementation checkpoint:

- `PreparedUpstreamLaunch` is runtime-authenticated, cloned, and deeply frozen.
- Command resolution ignores empty PATH entries, canonicalizes explicit paths, and uses no shell.
- A bounded regular executable snapshot includes local file identity, timestamps, mode, and SHA-256.
- The same snapshot and internal launch digest are revalidated immediately before transport connection.
- The STDIO transport accepts only an authenticated prepared launch and uses its absolute executable,
  exact arguments, canonical cwd, and allowlisted environment.
- Synthetic launch-profile results are authenticated by their owning in-memory authority only.
- Production receipts, policy semantics, dependencies, and database schema are unchanged.
- Full network-free suite: 176 passed, 3 skipped on 2026-09-07.

Next, conduct a separate Verified MCP Package Stage Architecture Check before designing a Filesystem npm
launch profile or any `registry_artifact_verified` claim.
