# Verified MCP Package Stage Architecture Check

Status: accepted by Jonny on 2026-09-07. The approved network-free foundation is committed and pushed
at `92553b3`. This acceptance authorizes no registry request, package download, real archive extraction,
package installation, package startup, dependency change, database migration, receipt schema change,
or later external write.

## Decision summary

APG should not begin with a general-purpose npm resolver or reuse `npx` as a verified MCP launch path.
The first production stage must accept only an **APG-shipped, explicitly selected, exact graph profile**
for one package/version and one supported runtime platform.

The recommended architecture is:

```text
explicit profile selection
  -> metadata-only graph confirmation
  -> immutable stage plan
  -> one-time package-download/stage approval
  -> direct bounded tarball downloads into quarantine
  -> verify every compressed artifact against its bound SHA-512
  -> inspect every archive before extraction
  -> materialize the exact reviewed node_modules layout with scripts disabled
  -> validate package identities, dependency edges, entrypoint, and complete file tree
  -> atomically seal an APG-owned stage
  -> separate one-time startup approval
  -> revalidate sealed tree immediately before launch
  -> launch exact staged entrypoint without npm/npx resolution
  -> existing MCP schema preflight and per-action policy/approval
```

This can support the precise claim that staged bytes matched registry integrity evidence for the
reviewed materialized graph. It does not prove that the publisher is trustworthy, that source and build
output match, that the code is safe, or that runtime effects are contained.

The first implementation checkpoint should remain network-free. It should build only immutable types,
validators, state transitions, hashing, runtime-authenticated synthetic stage results, and fake archive/
download adapters. Real archive handling, registry access, downloads, persistence, a production profile,
receipt 1.2, and package startup remain later approval checkpoints inside this architecture.

## Product boundary

A verified MCP package stage is not a user-project installation.

```text
APG private stage
  purpose: hold reviewed MCP server code for an APG-routed launch
  project package.json: unchanged
  project lockfile: unchanged
  project node_modules: unchanged

apg install npm ...
  purpose: mutate a user-selected project
  approval and audit: existing Install Guard path
```

Stage approval must never authorize project installation. Project-install approval must never authorize
an MCP server launch. Direct npm, npx, node, or MCP execution remains outside APG coverage.

## Requirements

- Bind exact package, version, artifact, dependency graph, materialized layout, entrypoint, runtime
  platform, and stage limits before package download.
- Verify every downloaded artifact before extraction or package-code startup.
- Execute no package lifecycle script while resolving or materializing a stage.
- Reject dynamic package sources, redirects, credentials, arbitrary registries, and graph drift.
- Prevent archive traversal, link escape, special-file creation, decompression bombs, duplicate-path
  ambiguity, and case-fold collisions.
- Keep partial and failed work outside the runnable stage namespace.
- Require a separate startup approval after a stage becomes ready.
- Revalidate the complete staged tree immediately before startup.
- Keep tool-action identity, package evidence, launch configuration, and runtime containment as separate
  assurance dimensions.
- Preserve existing Allow/Ask/Deny semantics for MCP tool calls.
- Preserve current receipt bytes until a production stage profile is separately approved.

## Non-goals

- arbitrary npm package support
- semver or peer-dependency resolution implemented by APG
- authenticated/private registries
- lifecycle-script execution or native compilation
- git, file, workspace, alias, or arbitrary URL dependencies
- npm publisher trust, malware detection, or source reproducibility proof
- npm provenance/Sigstore verification
- OS sandboxing, network containment, or runtime attestation
- automatic rollback of package-code effects
- Windows support in the first profile

## Evidence from current npm behavior

The npm CLI is useful as a development-time graph generator, but it is not an adequate production trust
boundary by itself:

- npm documents `package-lock.json` as an exact representation of a generated dependency tree and says
  modern lockfiles contain enough information to describe that tree.
- `npm ci` treats a matching lockfile as frozen and does not rewrite the project manifests, but install
  shape still depends on npm version and graph-affecting flags.
- `--ignore-scripts` suppresses package scripts; it must still be a fixed defense-in-depth setting, not
  the only archive-safety control.
- npm offline mode prevents install-time network requests, but npm's cache is explicitly a cache rather
  than a guaranteed persistent artifact store.
- npm provenance can connect a package to supported build/publish infrastructure, but npm states that it
  does not establish that package code is non-malicious.

References:

- <https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/>
- <https://docs.npmjs.com/cli/v11/commands/npm-ci/>
- <https://docs.npmjs.com/cli/v11/using-npm/config/>
- <https://docs.npmjs.com/cli/cache/>
- <https://docs.npmjs.com/generating-provenance-statements/>

The current development host uses Node `v26.3.1` and npm `11.16.0`. Those values are diagnostic only.
A production profile must declare and test its supported Node major, OS, architecture, libc where
relevant, and graph-generator version. It must not silently inherit whatever npm version is on PATH.

## Assurance model

One green `verified` flag would overstate the evidence. Server evidence should expose independent
dimensions:

```text
package_identity:
  configured | exact_registry_version

artifact_integrity:
  unverified | top_level_verified | complete_for_staged_graph

dependency_graph:
  unbound | reviewed_exact_graph | complete_for_materialized_stage

materialized_tree:
  unverified | sealed_local_snapshot | prelaunch_revalidated

publisher_identity:
  unverified | registry_signature_verified | provenance_attestation_verified

build_reproducibility:
  unverified | reproducible_build_verified

runtime_containment:
  none | os_sandboxed | remotely_attested
```

For the first production profile, the maximum honest claim is:

```text
package_identity: exact_registry_version
artifact_integrity: complete_for_staged_graph
dependency_graph: complete_for_materialized_stage
materialized_tree: prelaunch_revalidated
publisher_identity: unverified
build_reproducibility: unverified
runtime_containment: none
```

The existing top-level `server_provenance_assurance` may advance to
`registry_artifact_verified` only when these dimensions accompany it. It must not imply publisher,
build, safety, or containment assurance.

## Closed production graph profile

The first profile is an immutable APG-shipped manifest, not user-authored JSON and not inferred from an
upstream command.

Conceptually:

```text
VerifiedMcpGraphProfile
  profile_id
  profile_version
  top_package
    name
    exact_version
    exact_entrypoint_relative_path
  registry_origin
  runtime_constraint
    os
    architecture
    node_major
    npm_graph_generator_version
  graph_nodes[]
    install_path
    package_name
    exact_version
    tarball_url
    sha512_integrity
    dependency_edges[]
    expected_lifecycle_script_names[]
  materialization_rules_version
  archive_rules_version
  fixed_resource_limits
  manifest_digest
```

Every list is canonically ordered and every field is closed. Unknown fields, duplicate package paths,
duplicate node identities, missing integrity, invalid URL, graph cycle/layout contradiction, unsupported
platform, or manifest digest mismatch rejects the profile before registry access.

The profile may be generated from a pinned development lockfile, but generated output must be reviewed,
committed, and tested as APG source. Runtime APG does not ask npm to choose versions or layout again.

The first profile rejects:

- bundled dependencies or an archive-contained `node_modules`
- symlink, hardlink, device, FIFO, socket, or sparse archive entries
- non-registry, alias, git, file, workspace, and remote URL dependency specs
- missing SHA-512 integrity
- undeclared or extra runtime dependency edges
- packages that require lifecycle output to produce the reviewed entrypoint
- native build requirements such as an unapproved `binding.gyp`
- non-portable or case-colliding archive paths

Unsupported is safer than silently broadening the graph.

## Immutable stage plan

After metadata-only confirmation, APG creates one runtime-authenticated `PackageStagePlan`:

```text
PackageStagePlan
  plan_version
  stage_id                 # random local ID; not content-derived
  graph_profile_id
  graph_profile_digest
  exact registry origin
  metadata observation set and expiry
  canonical graph nodes
  approved network hosts
  compressed/uncompressed/file/count limits
  package scripts: disabled
  target stage-root identity
  stage_plan_hash
```

The plan hash covers every public behavior-determining field and a private local binding for the stage
root. It is held in memory and recorded locally. A portable receipt must not export absolute stage paths,
private environment values, or a low-entropy digest that permits path guessing.

Changed metadata, graph, URL, integrity, platform, Node runtime, limits, stage root, or implementation
version requires a new plan and approval.

## Phase 1: metadata-only graph confirmation

The user explicitly invokes a future planning command and selects one built-in profile. That invocation
is the affirmative boundary for anonymous registry metadata reads; it does not authorize tarball
downloads.

Required behavior:

- show the registry origin and package-name disclosure before the request
- use anonymous HTTPS only
- send no Authorization, cookie, project path, prompt, policy, audit content, or telemetry
- reject credentials, query, fragment, redirects, unexpected content type, timeout, and oversized body
- request every unique package in the reviewed graph at its exact version
- require exact name, version, tarball URL, and SHA-512 integrity to match the shipped profile
- expire the complete observation set together; partial freshness cannot create a stage plan
- write only bounded private temporary planning state

The existing registry adapter is a useful primitive but requires a batch/exact-profile layer. No
general semver resolver is added.

## Phase 2: package download into quarantine

Package download is an explicit one-time Ask decision over the complete stage plan. Approval authorizes
only the exact bounded artifact set and approved registry origin.

The downloader:

- uses direct Node HTTPS/fetch transport behind an injectable interface
- sends no credentials, cookies, proxy variables, client certificates, or parent headers
- rejects redirects and any final URL/origin mismatch
- writes each response to an exclusive `0600` quarantine file
- streams bytes through SHA-512 while enforcing compressed per-file and aggregate limits
- fsyncs and closes the quarantine file before marking the artifact verified
- deletes an owned partial file after timeout, cancellation, size failure, or integrity mismatch
- never passes unverified bytes to the archive inspector
- retries only the same URL/integrity inside the same bounded stage session; metadata refresh requires a
  new plan and approval

Suggested first-profile hard ceilings, subject to validation against the pinned graph:

| Resource | Ceiling |
| --- | ---: |
| graph nodes | 256 |
| one compressed artifact | 50 MiB |
| aggregate compressed bytes | 512 MiB |
| one uncompressed artifact | 256 MiB |
| aggregate uncompressed bytes | 1 GiB |
| one regular file | 64 MiB |
| aggregate archive entries | 100,000 |
| relative path bytes | 512 |
| path depth | 32 |

These are non-configurable safety ceilings in the first production profile. Raising them requires a
profile review, not a command-line override.

## Phase 3: archive inspection and materialization

APG must not implement a casual tar parser or invoke a system `tar` command. Real extraction is blocked
until a maintained archive library is selected under a separate dependency/security approval.

The archive adapter must support a preflight pass before any extraction:

- validate gzip and tar structure under compressed and expanded limits
- require every entry under one literal `package/` prefix
- normalize separators and reject absolute paths, `..`, `.`, empty segments, NUL, control characters,
  Unicode normalization ambiguity, and case-fold collision
- reject duplicate paths regardless of type
- allow only regular files and directories
- reject symlink/hardlink targets, devices, FIFOs, sockets, sparse entries, setuid/setgid bits, extended
  attributes, and archive-owned numeric identities
- reject nested `node_modules`, `.npmrc`, and extraction outside the assigned package directory
- normalize output permissions; never preserve ownership or privileged mode bits

Only a fully preflighted artifact may be extracted into its exact profile-declared `install_path` under
the quarantine stage. Extraction uses exclusive creation and no-follow semantics where available.

After extraction APG recursively uses `lstat`, never follows links, and validates:

- package directory realpath remains inside the quarantine root
- package.json is a bounded regular file with exact name/version
- runtime dependency declarations agree with the reviewed graph
- lifecycle script names agree with the profile and none ran
- the exact top-level entrypoint is a regular in-tree file
- no unexpected file type, hardlink count, nested package tree, or case collision exists

The first production stage creates no `.bin` links. APG launches the reviewed entrypoint through the
exact prepared Node executable instead.

## Lifecycle-script policy

Lifecycle execution is always disabled during planning and staging. There is no v0 override.

- No `preinstall`, `install`, `postinstall`, `prepare`, `prepack`, or package-defined command runs.
- `binding.gyp` and packages requiring generated native output are rejected for the first profile.
- Declared lifecycle script names are evidence and warning material, not executable authority.
- A profile may include a package with dormant scripts only when its reviewed entrypoint and runtime
  graph are already present in published artifacts and a scripts-disabled acceptance succeeds.
- Failure caused by skipped scripts is an unsupported-profile result. APG must not retry with scripts
  enabled.

Official npm documentation says `--ignore-scripts` disables package.json scripts, while commands that
explicitly run a named script remain capable of running that command. APG therefore never invokes
`npm run`, `npm test`, `npm start`, or another script command during staging.

## Phase 4: seal and stage persistence

The stage is built in an APG-owned private temporary sibling directory. It becomes addressable only
after complete validation.

`SealedPackageStageManifest` contains:

```text
manifest_version
stage_id
profile_id + profile_digest
stage_plan_hash
top package identity
artifact records and verified integrity
exact materialized package paths
exact entrypoint relative path + file hash
canonical file records[]
  relative path
  type
  normalized mode
  size
  sha256
tree_digest
platform/runtime constraints
lifecycle scripts disabled
created_at
assurance dimensions and explicit limitations
```

The manifest excludes absolute user paths, credentials, environment values, output, and archive bytes.
File records are sorted by portable relative-path bytes before canonical hashing.

Commit protocol:

1. build and validate in quarantine
2. write manifest with exclusive private creation
3. fsync stage files, manifest, and containing directories where supported
4. record durable `stage_ready_to_commit`
5. atomically rename quarantine to a never-before-used random final stage ID
6. record durable `stage_committed`
7. expose the stage as `READY` only when filesystem marker, manifest, and matching audit event agree

SQLite and filesystem rename are not one transaction. A crash between steps 5 and 6 creates an
unindexed quarantine stage, never a runnable stage. Startup recovery may inventory it, but automatic
acceptance or deletion is deferred; cleanup is explicit except for process-owned unfinished temporary
directories.

Stages are append-only by product contract, not tamper-proof. Read-only permissions reduce accidents;
same-user mutation remains possible and is handled by full revalidation. Upgrade creates a new stage ID
and never edits an existing one.

## Phase 5: separate startup approval and launch

Stage creation does not authorize package-code execution.

Before startup APG prepares a separate immutable launch plan binding:

- exact stage ID, profile ID/version, manifest digest, and tree digest
- exact Node executable identity
- exact in-stage entrypoint
- exact private launch arguments, working directory, and minimal environment
- startup timeout and expected MCP schema profile
- explicit no-sandbox/no-runtime-attestation limitations

The human sees the package/version, graph size, dormant lifecycle warnings, launch target, private local
arguments where needed, and worst credible startup effects. Approval is consumed once per new process.

Immediately before spawn:

- require a runtime-authenticated stage result from the owning stage authority
- reopen and validate the manifest
- lstat and hash the complete materialized tree against the sealed manifest
- revalidate Node, cwd, entrypoint, arguments, and environment through the existing launch foundation
- reject new files, missing files, changed bytes/modes, links, or stage-root replacement
- record durable execution-start evidence before spawn

Launch uses exact `node <absolute-staged-entrypoint> ...` arguments. It never invokes npm, npx, a shell,
PATH package resolution, package exports resolution, or a `.bin` link.

After spawn, existing MCP tool-schema preflight runs before APG serves downstream calls. Startup approval
does not lower per-tool Allow/Ask/Deny. A startup process may still read files, create child processes,
or use the network because runtime containment is not part of this architecture.

## Approval boundaries

| Boundary | User authority | Permitted consequence | Not permitted |
| --- | --- | --- | --- |
| profile selection | explicit local selection | choose reviewed graph | registry or disk action |
| registry metadata | explicit planning invocation with disclosure | anonymous exact metadata GETs | tarball download or code startup |
| package download/stage | one-time Ask over exact stage plan | bounded tarball GETs and APG-private stage writes | project install or code startup |
| project installation | existing separate `apg install` Ask | approved project mutation | stage launch authority |
| package startup | separate one-time Ask over sealed stage/launch plan | one exact MCP server process | metadata refresh, download, install, or tool approval |
| MCP tool action | existing per-action policy/approval | exact routed tool call | server restart or direct bypass |
| stage deletion | explicit stage-management action | delete exact APG-owned stage | broad cache/home deletion |

No approval is transitive across rows.

## State machine

```text
PROFILE_SELECTED
  -> METADATA_CONFIRMING
  -> PLAN_READY
  -> STAGE_APPROVAL_PENDING
  -> DOWNLOADING
  -> ARTIFACTS_VERIFIED
  -> ARCHIVES_PREFLIGHTED
  -> MATERIALIZING
  -> TREE_VERIFIED
  -> READY_TO_COMMIT
  -> READY
  -> STARTUP_APPROVAL_PENDING
  -> STARTING
  -> ACTIVE
  -> STOPPED

Any pre-READY failure -> FAILED_QUARANTINE
Any READY revalidation failure -> INVALID
Any post-start evidence failure -> ACTIVE_UNKNOWN or TERMINATED_INCOMPLETE
```

State transitions are monotonic. `FAILED_QUARANTINE` and `INVALID` cannot be human-approved back to
`READY`; rebuild a new stage from a fresh plan.

## Receipt and evidence strategy

The network-free foundation does not change production receipts.

When the first production stage and launch profile are separately accepted, receipt schema 1.2 adds a
distinct `serverEvidence` object. It does not overload MCP action parameter identity.

Portable safe fields may include:

- graph profile ID/version/digest
- exact top package name/version/integrity
- stage manifest and tree digests
- artifact/package counts and completeness
- exact public entrypoint relative path and hash
- platform/runtime constraint
- lifecycle execution `disabled`
- assurance dimensions
- direct-bypass, publisher, build, containment, and runtime limitations

Portable evidence omits stage-root path, absolute entrypoint, HOME, cwd, private arguments, environment,
temporary paths, registry request headers, and raw package contents. A private launch binding may be
represented only as an opaque local linkage with an explicit non-disclosure limitation.

All actions handled by one process reference the same immutable `serverEvidence`. Action identity stays
`structural_only`, `adapter_scoped`, or `adapter_action_exact` independently.

Permitted UX:

```text
Registry artifacts verified for the reviewed staged graph.
Staged file tree revalidated before launch.
Publisher, source/build equivalence, runtime behavior, and containment are not verified.
Protected only when launched and called through APG.
```

Forbidden UX:

- official server verified
- safe or malware-free package
- publisher verified
- reproducible build verified
- tamper-proof stage
- sandboxed or attested runtime
- complete downstream-effect verification

## Credential, privacy, and network boundary

- Public anonymous HTTPS registry only.
- No `.npmrc`, npm login state, tokens, keys, client certificates, proxy variables, or credential files.
- Project `.npmrc` is irrelevant because planning/staging occurs only in an APG-owned private workspace;
  its contents are never read.
- Registry origin, exact package names, client IP, and request time are disclosed during metadata and
  artifact requests.
- No APG telemetry or hosted service.
- Metadata and artifact transport reject redirects.
- Runtime package network activity is not covered; a later OS sandbox/network policy is required to
  restrict it.

## Failure and recovery

| Failure | Required behavior |
| --- | --- |
| profile/manifest invalid | fail before registry access |
| metadata mismatch or expiry | no stage plan; no download |
| approval denied/expired/cancelled | no artifact request or stage write |
| pre-download audit failure | fail closed before first artifact request |
| timeout/redirect/size/integrity failure | abort; delete owned partial; quarantine unusable |
| archive structural violation | no extraction for that artifact; stage unusable |
| extraction or post-scan violation | quarantine unusable; never expose as READY |
| tree/entrypoint/graph mismatch | quarantine unusable |
| crash before final rename | unfinished private temporary state only |
| crash after rename before committed audit | unindexed quarantine; never launch automatically |
| post-stage audit failure | stage unavailable; do not infer success or retry downloads automatically |
| pre-start revalidation failure | mark INVALID; no process spawn |
| pre-start audit failure | no process spawn |
| startup timeout/schema mismatch | terminate process; no downstream tool dispatch |
| post-spawn audit failure | terminate best-effort; mark incomplete; never auto-retry startup |
| package runtime side effect | no rollback promise; preserve evidence and require manual recovery |

Cleanup failures are explicit. Never recursively delete a broad path, unresolved environment value,
home directory, stage root, or user project. Deletion targets must be exact owned random stage/temp IDs
under a validated APG root.

## STATE / PERMISSION / FAILURE / DATA

### State

- shipped graph profile: immutable APG source
- metadata observation: bounded memory/private temporary planning state
- stage plan and approval: immutable process state plus local audit linkage
- downloaded artifact: private quarantine until integrity verified
- sealed stage: APG-owned persistent local code tree and manifest
- startup plan: immutable memory; one process only
- server evidence: same immutable stage evidence for one process lifetime

### Permission

- profile selection grants no external action
- planning grants anonymous metadata reads only
- stage approval grants bounded artifact reads and APG-private writes only
- install approval, stage approval, startup approval, and tool approval are non-transitive
- failure cannot be repaired by pressing Approve
- direct execution never inherits APG assurance

### Failure

- every mismatch before execution fails closed
- partial stages are never runnable
- stage readiness requires filesystem and durable audit agreement
- post-side-effect uncertainty stays incomplete
- no automatic startup retry or rollback claim

### Data

```text
public package names/profile
  -> public registry metadata
  -> exact public URL/integrity graph
  -> one-time stage approval
  -> public tarball bytes into private quarantine
  -> verified/extracted private code tree
  -> safe manifest evidence
  -> separate startup approval
  -> local MCP server process

Never transferred:
  credentials, npm login state, project path, prompts, policy content,
  audit database content, private launch args, raw stdout/stderr, telemetry
```

## Risk register and mitigation

| Risk | Preventive mitigation | Detection/recovery | Residual risk |
| --- | --- | --- | --- |
| malicious registry returns matching malicious bytes | exact profile plus TLS and integrity | record registry evidence | registry remains a trust source |
| compromised publisher | no publisher claim | optional future signature/provenance check | verified bytes may be malicious |
| dependency substitution | exact shipped graph and per-artifact SHA-512 | reject any metadata/artifact drift | reviewed graph can contain a bad version |
| resolver nondeterminism | no runtime general resolver | regenerate/review profile offline | profile maintenance cost |
| lifecycle execution | no script command; scripts disabled; reject native build need | dormant script inventory and acceptance | runtime code itself remains arbitrary |
| tar traversal/link escape | full preflight; regular files/dirs only; no links | post-extraction lstat/realpath scan | archive-library vulnerability |
| decompression/resource exhaustion | fixed per-item and aggregate limits | abort and quarantine cleanup | allowed maximum can still pressure disk/CPU |
| case/Unicode collision | portable path grammar and collision set | deterministic preflight failure | first profile supports fewer packages |
| bundled dependency ambiguity | reject nested node_modules/bundles | post-scan | some packages unsupported |
| stage tampering | private root, read-only modes, complete prelaunch rehash | mark INVALID; rebuild | same-user/root race and post-start mutation |
| npm configuration/credential leak | no runtime npm; private metadata workspace; allowlisted transport | forbidden-value tests | OS/network metadata remains visible |
| launch overclaim | separate evidence dimensions and startup approval | receipt/UX invariant tests | users may still infer safety |
| stage/project boundary confusion | separate commands, paths, approvals, receipts | project file before/after tests | user can separately run direct npm |
| crash across SQLite/filesystem commit | dual readiness requirement; no automatic adoption | inventory as unindexed quarantine | cleanup requires user action |
| post-start effects | no containment claim; tool policy remains active | outcome/incomplete evidence | startup code can act before first tool call |
| receipt privacy leak | safe allowlist; no absolute/private launch values | golden forbidden-byte tests | public graph may reveal software choice |
| broad deletion | exact owned IDs and validated root | refuse ambiguous cleanup | orphaned disk use |

Release-blocking controls are exact shipped graph, separate approvals, integrity-before-extraction,
archive preflight, scripts disabled, quarantine-only construction, atomic seal, dual readiness, complete
prelaunch tree revalidation, honest assurance dimensions, privacy-safe evidence, and no runtime resolver.

## Alternatives considered

### A. Continue launching `npx package@version`

Rejected. `npx` may resolve, download, install, and select code after APG's final pre-spawn check.

### B. Trust package-lock and npm exit status

Rejected as provenance. A lockfile describes intent/tree state; APG must verify downloaded bytes and the
materialized tree independently before startup.

### C. Reuse npm's shared cache as the permanent stage

Rejected. npm documents the cache as opaque and not a reliable persistent data store. Shared cache state
also weakens APG ownership and cleanup boundaries.

### D. Run `npm ci --offline --ignore-scripts` for every startup

Rejected for production launch. It leaves package-manager materialization and package selection inside
the startup boundary and complicates proof that no network or graph drift occurred.

### E. Implement a general npm resolver inside APG

Rejected for the first profile. Semver, aliases, peer dependencies, optional/platform dependencies,
overrides, workspaces, hoisting, and npm-version semantics are a large new security surface.

### F. Ship one closed exact graph profile and materialize it directly

Recommended. It is narrow, reviewable, deterministic, and compatible with exact package evidence.

### G. Use system `tar` or write a minimal tar parser

Rejected. System behavior is platform-dependent, and a custom security-critical parser would be a poor
trade-off. A maintained library needs a separate dependency/security decision.

### H. Verify npm Sigstore provenance now

Deferred. It adds external trust roots, transparency-log behavior, npm-version constraints, and a
distinct publisher/build assurance. It cannot establish package safety.

## Test strategy

### Network-free foundation

- canonical profile and plan digest golden fixtures
- unknown/duplicate/malformed graph fields fail closed
- graph, platform, URL, integrity, lifecycle, limit, and install-path mutation changes identity
- arbitrary caller cannot forge a trusted profile or sealed-stage result
- fake downloader cannot pass bytes before exact SHA-512 success
- timeout, cancellation, redirect, truncation, oversize, and integrity mismatch leave no runnable stage
- fake archive entries cover traversal, absolute path, links, special files, duplicates, case/Unicode
  collision, depth, entry, file, and expanded-byte limits
- exact package.json, dependency edge, and entrypoint checks
- deterministic file manifest/tree digest and full mutation detection
- monotonic state transitions and invalid-stage non-recovery
- approval replay/cross-plan substitution rejection
- receipt 1.0/1.1 bytes and policy decisions remain unchanged
- forbidden private values never appear in errors, audit projection, or synthetic portable evidence
- no network, npm/npx process, external package code, persistent stage, dependency, or database migration

### Dependency/archive checkpoint

Before selecting an archive library:

- review maintenance, license, transitive dependencies, published integrity, and security history
- write adversarial archive fixtures independent of the chosen library
- prove preflight happens before extraction
- prove no links/special entries and no path escape on macOS and Linux
- keep dependency addition separately approval-gated

### Real stage acceptance

Requires separate approvals for each consequence:

1. exact registry metadata reads for the named graph profile
2. exact tarball downloads and APG-private stage creation
3. exact staged package startup
4. one target-only MCP call after startup

Use a disposable APG stage root, empty credential configuration, fixed public registry, pinned profile,
fixed Node/npm generator versions, bounded capture, and guaranteed inventory/cleanup reporting. A failed
acceptance must retain only the minimum evidence needed to explain failure; raw package/output data is
not committed.

## Network-free implementation scope requiring approval

After accepting this Architecture Check, implement only:

1. closed immutable graph-profile and stage-plan types
2. canonical validation and digest rules
3. exact assurance-dimension types with no production claim change
4. stage state machine and runtime-authenticated synthetic stage authority
5. injectable downloader and archive/materializer interfaces
6. streaming SHA-512 verifier over synthetic local byte streams
7. portable path/archive policy validator over synthetic entry descriptions
8. deterministic materialized-tree manifest and revalidation helpers over test-created files
9. fake approval/audit orchestration with no persistent stage
10. network-free security and regression tests
11. architecture/state documentation

The implementation must not:

- ship a production graph or launch profile
- add a public stage/launch CLI
- access a registry or download a package
- invoke npm, npx, package scripts, or external MCP package code
- extract an actual third-party tarball
- add an archive or other dependency
- create a persistent stage/cache
- change policy semantics, receipt bytes, or receipt schema 1.2
- read `.npmrc`, `.env`, tokens, keys, credentials, certificate, proxy, or signing material
- migrate a database
- install into a user project
- commit, push, publish, deploy, or perform another external write without its own approval

## Network-free foundation implementation checkpoint

Accepted and implemented locally on 2026-09-07:

- `src/stage/profile.ts` validates and canonically hashes exact synthetic graph profiles under an
  owning runtime authority. It rejects unknown fields, dynamic/non-HTTPS artifacts, malformed SHA-512,
  disconnected/cyclic graph layouts, duplicate portable paths, and limits above the architecture
  ceilings.
- `src/stage/plan.ts` creates one authenticated immutable stage plan that binds the profile, metadata
  observation and expiry, approved host, scripts-disabled setting, limits, random stage ID, and private
  stage-root binding. Its synthetic approval authority is one-time and cross-plan fail-closed.
- `src/stage/integrity.ts` hashes injected local byte streams with SHA-512, enforces per-artifact and
  aggregate compressed-byte ceilings, and authenticates results only after exact integrity succeeds.
- `src/stage/archive-policy.ts` validates synthetic archive entry descriptions without parsing or
  extracting a tarball. It rejects traversal, links, special files, sparse/xattr entries, privileged
  modes, duplicate/case/Unicode ambiguity, nested `node_modules`, `.npmrc`, and resource overruns.
- `src/stage/tree-manifest.ts` uses no-follow file access and complete deterministic records to validate
  normalized modes, exact package identities, dependency declarations, lifecycle names, entrypoint,
  declared `node_modules` layout, hardlinks, and full-tree mutation.
- `src/stage/state-machine.ts`, `src/stage/authority.ts`, and `src/stage/foundation.ts` keep transitions
  monotonic, require matching synthetic audit evidence before a synthetic seal, and exercise injected
  downloader/archive ordering without adding a real downloader, materializer, stage store, or launch.
- `test/unit/package-stage-foundation.test.ts` covers canonical identity, authority forgery, plan expiry,
  approval replay/substitution, integrity ordering/failure, archive attacks/limits, exact tree identity,
  mode/link/byte/layout drift, terminal state behavior, dual evidence, and privacy-safe errors.

This checkpoint ships no production graph/profile and is unreachable from the public CLI. Its
`Synthetic*` authorities are test scaffolding, not substitutes for the Dashboard approval service or
durable audit recorder. Production receipt wording remains unchanged. The complete network-free suite
passes with 188 tests and 3 intentional skips on 2026-09-07.

## Acceptance criteria

- Arbitrary packages and user-authored profiles cannot enter the trusted graph path.
- Stage approval binds one exact graph, artifact set, registry origin, platform, limits, and stage root.
- No artifact is inspectable/extractable through the trusted path before exact integrity succeeds.
- Archive policy rejects every escape, link, special-file, ambiguity, and resource-overrun category.
- Materialized package identities, dependency edges, entrypoint, and full file tree are deterministic.
- Partial, failed, unindexed, or changed stages cannot become launchable through approval.
- Registry read, package download/stage, project install, startup, and tool action stay separate.
- Production receipts and provenance wording remain unchanged during the network-free checkpoint.
- No credential access, dependency, migration, registry request, package operation, or external write is
  introduced by the foundation.

## Decision checkpoint

Decision recorded: the closed-profile architecture and only its network-free foundation were accepted.
Do not select an archive dependency, ship a production Filesystem graph, create a persistent stage,
access the registry, download artifacts, add receipt 1.2, or start package code until their named
checkpoints receive separate evidence and approval.
