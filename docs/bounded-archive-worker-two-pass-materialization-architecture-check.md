# Bounded Archive Worker & Two-Pass Materialization Architecture Check

Status: accepted on 2026-09-07. The approved network-free implementation checkpoint is implemented
locally using repository-owned fixture bytes and disposable private temporary directories only. It does
not authorize a real package archive download, production profile, persistent stage, receipt/database
change, package startup, commit, or push.

## Outcome

Use a fresh child process for each archive pass and keep every filesystem mutation in the APG parent.
The child is a bounded parser worker, not a sandbox. Pass A produces a complete write-free transcript.
Pass B streams the same archive again, and the parent writes only entries that match that authenticated
transcript byte-for-byte and in order. A stage is runnable only after independent tree revalidation,
durable audit ordering, and publication of an exclusive authenticated seal.

Real archive handling must fail closed when the host cannot provide the required capability. In
particular, Node 24's Permission Model cannot deny network access. APG may continue to support Node 24
generally, but a real archive worker on Node 24 requires a separately reviewed OS containment provider.
Without one, only synthetic network-free tests may run. Node 25 and 26 can omit all `--allow-net`
grants, but Node's own documentation says the Permission Model is not a security boundary against
malicious code; the product must not describe this worker as a sandbox.

## Observable success

The next network-free implementation checkpoint succeeds only when:

1. pass A cannot write stage files and its crash, timeout, protocol overflow, or non-zero exit fails
   the stage;
2. pass B can write only through the APG parent and every entry header, body length, body hash, mode,
   order, and terminal state exactly matches the authenticated pass-A transcript;
3. artifact identity, worker identity, parser graph identity, limits, and archive grammar are identical
   across both passes;
4. files and directories are created only beneath one private APG-owned random pending root using
   exclusive, no-follow leaf opens and continuous identity checks;
5. late parser, writer, tree-verification, seal, or audit failure never produces a launchable stage;
6. timeout/cancel/crash tests terminate the child and leave only a quarantined, unsealed scratch tree;
7. the same synthetic corpus produces the same transcript on Node 24, 25, and 26, while the real-worker
   network-isolation capability gate correctly rejects unsupported Node 24 hosts; and
8. no test downloads an archive, uses a live registry, starts package code, or touches a user project.

## Scope

In scope for the architecture:

- process boundary, resource limits, cancellation, and protocol bounds;
- retained-descriptor artifact identity and two-pass revalidation;
- authenticated pass-A/pass-B equality;
- APG-owned POSIX materialization and tree verification;
- durable seal, audit ordering, failure state, quarantine, and exact cleanup rules;
- Node 24-26 capability behavior; and
- a synthetic isolated temporary-project test strategy.

Out of scope:

- a general-purpose archive extractor;
- PAX, GNU extensions, links, devices, FIFOs, sockets, sparse files, ownership, ACL, xattr, or timestamp
  preservation;
- Windows materialization;
- a claim of hostile-code sandboxing or runtime attestation;
- production registry metadata, artifact download, package graph/profile selection, package launch, MCP
  tool execution, receipt schema 1.2, database migration, or release/publish work.

## Threat and assurance boundary

The archive bytes, headers, paths, sizes, compression ratios, warning behavior, and parser process are
untrusted. The installed JavaScript dependency graph is trusted only to the limited degree expressed by
the exact reviewed lock and runtime byte identity. Root or a hostile same-user process is outside the
software-only assurance boundary and can still race paths, replace modules, inspect memory, signal
processes, or rewrite local audit data.

The design provides:

- deterministic admission of one narrow gzip/USTAR grammar;
- bounded parser-process lifetime and bounded parent protocol buffers;
- complete two-pass semantic and body equality;
- no third-party filesystem writes;
- private unsealed scratch state that is never launchable; and
- precise local evidence linking artifact, worker, transcript, tree, seal, and audit state.

It does not provide:

- proof that parser code is non-malicious;
- a VM/container/OS sandbox;
- publisher identity, reproducible-build proof, notarized package provenance, or remote attestation;
- elimination of same-user time-of-check/time-of-use races; or
- rollback of arbitrary executed code, because this checkpoint never executes package code.

## Component and authority split

```text
APG parent
  -> open/revalidate artifact descriptor
  -> authenticate runtime/config identity
  -> spawn fresh pass-A child
       stdin: bounded artifact bytes
       stdout: bounded closed-schema transcript events
       filesystem: no stage access
  -> authenticate complete pass-A transcript
  -> create private random pending root
  -> reopen/revalidate the same artifact
  -> spawn fresh pass-B child
       stdin: the same bounded artifact bytes
       stdout: entry-start/body-chunk/entry-end events
  -> compare each event against pass A
  -> APG-owned exclusive/no-follow writes
  -> independently hash and revalidate complete tree
  -> durable READY_TO_COMMIT audit
  -> publish exclusive authenticated seal
  -> durable READY audit
  -> future launch may consume the sealed stage after revalidation
```

Only the parent owns stage-plan state, transcript authority, audit authority, artifact descriptors,
pending-root descriptors, and filesystem writes. The child receives no approval token, audit database,
target stage path, registry credential, user configuration, inherited artifact descriptor, or package
launch capability.

## Why child processes, not worker threads

Each pass uses a fresh child process launched without a shell. Worker threads share the parent process,
and their `resourceLimits` constrain the JavaScript heap rather than all external or `ArrayBuffer`
memory. A worker-thread out-of-memory condition can therefore still endanger the APG process. A child
process gives the parent a separate failure/exit boundary and a process that can be terminated on
deadline or cancellation.

This is fault and resource containment, not a security sandbox. A Node child running malicious code as
the same user remains capable of attacks not stopped by JavaScript heap limits or the Permission Model.

## Runtime and parser identity

Before each pass, the parent constructs one closed runtime identity containing:

- real path, device/inode metadata, size, mode, and SHA-256 of the exact Node executable;
- SHA-256 of the worker entry module;
- a deterministic manifest digest for the selected `tar/parse` file and every reviewed production
  dependency file required by the bundled worker;
- exact dependency/lock contract identity;
- exact argv, environment allowlist, Permission Model flags, V8 heap flags, protocol version, grammar
  version, and resource-limit digest; and
- canonical private working-directory identity.

The parent revalidates the identity immediately before spawning pass A and again before pass B. A
different executable, worker, dependency file, argument, environment, grammar, or limit fails before
the pass starts. The transcript binds the complete runtime/configuration digest.

This narrows module substitution but cannot eliminate the final OS-load race. A future bundled worker
may reduce the module surface, but bundling and its build dependency would require a separate review.

## Node capability matrix

| Capability | Node 24 | Node 25 | Node 26 | Required handling |
| --- | --- | --- | --- | --- |
| filesystem read/write permission gates | available | available | available | grant read only to the exact runtime module manifest; grant no filesystem write |
| child/worker/addon/WASI permission gates | available | available | available | start with `--permission` and grant none of these capabilities |
| network permission gate | unavailable | available | available | omit `--allow-net`; fail real-worker capability on Node 24 unless an approved OS provider supplies no-network containment |
| worker-process deadline and kill | available | available | available | parent-owned abort/deadline and process-group termination |
| supported corpus behavior | must match | must match | must match | release matrix blocks on any transcript or terminal-state drift |

The runtime must probe required flags from a fixed allowlist and fail closed; it must not infer assurance
from an unknown flag or silently retry without a rejected flag. Synthetic tests may exercise parsing on
all supported majors, but a real artifact path cannot label Node 24 as network-isolated without an OS
provider.

## Child launch contract

The parent launches the exact Node executable directly with `shell: false` and a fixed argv. The launch
uses:

- a fresh child for each pass;
- a private empty working directory unrelated to the stage root;
- an explicit minimal environment rather than inherited environment;
- no `HOME`, npm configuration, proxy, certificate, credential, token, key, `NODE_OPTIONS`, inspector,
  loader, preload, or package-manager variables;
- stdin/stdout/stderr only, with no extra inherited file descriptors;
- fixed V8 old-space and semi-space limits plus APG archive byte/count/ratio limits;
- Node Permission Model flags with filesystem read granted only to the exact authenticated worker/module
  manifest required to load the parser, and no filesystem-write, child-process, worker-thread,
  native-addon, WASI, or inspector grant; and
- where supported, no network grant.

The parent writes exactly the expected artifact size to stdin from its retained descriptor, calculates
SHA-512 independently, closes stdin, and requires an exact EOF/terminal protocol result. The child
cannot request another path or input source.

## Protocol and resource limits

The protocol is versioned, length-prefixed, and closed-schema. JSON lines, arbitrary object graphs,
unbounded stack traces, and child-selected paths are not accepted. Every message type, field count,
string length, integer range, and state transition is validated before use.

Pass A may emit only bounded header/body-summary/complete records. Pass B may emit only:

```text
entry_start(index, path, kind, declared_size, normalized_mode)
body_chunk(index, offset, bytes <= 64 KiB)
entry_end(index, observed_size, body_sha256)
complete(entry_count, transcript_sha256)
```

The parent permits one active body at a time and acknowledges accepted chunks to apply backpressure.
Aggregate stdout, stderr, message count, entry count, path bytes, compressed bytes, decompressed bytes,
per-file bytes, total file bytes, directory depth, compression ratio, CPU-facing wall time, and child
exit time all have immutable plan-bound ceilings. Exceeding any limit terminates the child and fails the
stage. Stderr is bounded and redacted; raw archive paths and child stack traces are not persisted.

OS-level RSS/CPU enforcement is desirable but platform-specific. The network-free checkpoint must use
the child boundary, V8 limits, protocol limits, and deadline while documenting that these do not form a
hard malicious-code memory sandbox. A later OS provider can strengthen the same contract.

## Artifact descriptor contract

For each pass the parent:

1. opens the approved artifact with `O_RDONLY | O_NOFOLLOW`;
2. obtains bigint metadata and requires a regular file, one hard link, approved owner/mode, and exact
   approved size;
3. streams the complete file from that retained descriptor while independently calculating SHA-512;
4. rejects short read, extra byte, descriptor metadata drift, or integrity mismatch; and
5. re-runs `fstat` after EOF and child completion.

Before pass B, the parent closes and reopens the approved path with the same no-follow rules. It requires
the same device, inode, mode, link count, size, and SHA-512 as pass A and the approved stage plan. Holding
one descriptor prevents path replacement from changing bytes within a pass; reopen plus identity/hash
comparison detects replacement between passes.

## Pass A: write-free inspection

Pass A drains the entire archive and requires:

- strict single-member gzip and USTAR envelope acceptance;
- no warning, recovery, ignored member, trailing member, ambiguous end state, or extension metadata;
- exact ordered header interpretation shared by the APG envelope and `tar/parse`;
- exact observed body length and SHA-256 for every file;
- all path, type, mode, layout, count, size, depth, and graph/profile policy checks; and
- a normal child exit after one complete terminal record and protocol EOF.

Only after successful exit does the parent construct a deeply frozen transcript and brand it through a
parent-owned runtime authority. A child-provided digest or look-alike object is never trusted directly.
Pass A creates no stage root and performs no filesystem mutation.

## Pass B: comparison before and during writes

Pass B uses a fresh child and the independently reopened artifact. The parent compares every message to
the corresponding authenticated pass-A entry before accepting it. For body chunks, it verifies entry
index, exact offset, cumulative length, and ceiling before writing. It independently hashes written
bytes and requires the pass-B `entry_end` size/hash and final transcript digest to equal pass A.

Any reordered, missing, duplicated, renamed, resized, remoded, retyped, truncated, extended, or
body-substituted entry fails immediately. Same-length substitutions therefore fail on per-entry body
SHA-256 and aggregate transcript identity. A second-pass late failure leaves an unsealed quarantine; it
never rolls forward from partial output.

## APG-owned POSIX materializer

The first materializer is POSIX-only. It operates beneath an APG-owned parent directory and creates one
cryptographically random pending root with mode `0700`. That root is never placed on an executable
search path, referenced by an MCP configuration, or exposed to package code before sealing.

Directories are created component by component from the closed expected path set. Files are created
with `O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY` and initial mode `0600`. The parent requires regular-file
type, link count one, expected device/root ancestry, exact size, and exact body hash before close. It
does not restore archive ownership, setuid/setgid/sticky bits, ACLs, xattrs, devices, links, or
timestamps. Final file and directory modes are applied only after all content checks, with the v0
profile limited to ordinary `0644` files and `0755` directories unless an exact future entrypoint
profile separately approves an executable bit.

Every file is synced before close. After materialization, APG walks the entire pending tree without
following links and rebuilds the deterministic tree manifest. No extra node, link, device/inode/root
escape, mode drift, link-count drift, size drift, or content-hash drift is accepted. The result must
equal both the pass-A transcript and exact graph profile.

Node exposes `O_NOFOLLOW`, `O_EXCL`, and `O_DIRECTORY` on POSIX, but its standard filesystem API does not
provide a complete descriptor-relative `openat`/`mkdirat`/no-replace directory-publication design.
Consequently a hostile same-user actor can still race intermediate path components. Private `0700`
ownership, random names, continuous identity checks, and never publishing an unsealed path materially
reduce this risk but do not remove it. Root/same-user resistance requires a later native or OS isolation
provider.

## Seal and launchability

A directory name or successful materialization is not a seal. Readiness requires a small canonical seal
record containing at least:

- stage-plan, artifact, runtime/configuration, pass-A transcript, and final-tree digests;
- pending-root device/inode identity;
- grammar/protocol versions and resource-limit digest;
- audit action/session identity; and
- terminal state `READY`.

The record is first written and synced as a private temporary file in the same APG-owned parent. APG
publishes it under the final seal name using an exclusive same-filesystem operation that fails if the
name exists, then syncs the parent directory. A consumer rejects a partial, duplicate, malformed,
unowned, unlinked, digest-mismatched, or un-audited seal. Node does not expose a general no-replace
directory rename primitive, so the design does not claim that renaming a directory is an atomic seal.

The pending root keeps its fixed random identity. Future launch logic must reopen/revalidate the seal,
root device/inode, full tree manifest, and launch target immediately before spawning. The mere presence
of stage files or a path named `ready` never authorizes launch.

## State and audit ordering

```text
ARTIFACTS_VERIFIED
  -> PASS_A_RUNNING
  -> ARCHIVES_PREFLIGHTED
  -> PASS_B_RUNNING
  -> MATERIALIZING
  -> TREE_VERIFIED
  -> READY_TO_COMMIT
  -> SEALED_PENDING_AUDIT
  -> READY
```

Before the first stage write, a durable audit transition to `MATERIALIZING` must succeed. After complete
tree validation, APG durably records `READY_TO_COMMIT`, publishes the seal, and then durably records
`READY`. Only the final combination of valid seal and durable `READY` evidence is launchable.

If the terminal audit write fails after seal publication, the stage becomes `SEALED_PENDING_AUDIT` or
`audit_failed`, not `READY`. Launch is blocked and materialization is never repeated under the consumed
approval. Recovery requires exclusive stage ownership, complete seal/tree revalidation, and append-only
terminal evidence; designing that durable recovery coordinator is a later approval boundary. If safe
recovery cannot be proven, quarantine remains the fail-closed result.

Every parser exit, protocol error, timeout, cancellation, writer error, identity drift, transcript
mismatch, tree mismatch, seal failure, or audit failure transitions to `FAILED_QUARANTINE`. State never
moves backward and the same approval cannot retry a pass that may have written bytes.

## Cancellation, cleanup, and rollback

Cancellation closes child stdin, sends the configured termination signal to the child process group,
waits a short fixed grace period, then force-kills if required. APG drains only bounded output and
records a sanitized terminal reason. A killed child cannot make a scratch tree launchable because only
the parent writes and no seal/READY state exists.

SIGKILL, power loss, or audit failure may leave a pending directory. Startup inventory may identify it
as quarantined but must not blindly delete it. Cleanup is allowed only when APG holds exclusive cleanup
ownership and revalidates the exact APG parent, random child name, root device/inode, ownership, mode,
and absence of unexpected links or mount boundaries. Identity drift stops cleanup for manual review.

Because no package code runs, rollback is limited to removal of an isolated unsealed or retired stage
tree and its local metadata. Deletion can fail, and the design makes no claim of rollback against
external effects, user projects, registry actions, or lifecycle scripts.

## Approved synthetic test strategy

All implementation tests use a disposable private directory under the test runner's temporary root and
library-independent fixture bytes already in the repository. They must cover:

- all 52 archive fixtures through fresh pass-A and pass-B children;
- exact transcript goldens on Node 24, 25, and 26 before release;
- pre-cancel, mid-stream cancel, deadline, graceful exit, forced kill, crash, non-zero exit, truncated
  frame, oversized frame, extra frame, invalid field, protocol reordering, stderr overflow, and output
  after terminal state;
- compressed/decompressed/file/aggregate/count/depth/ratio ceilings and child heap exhaustion;
- proof that pass A creates no stage root and writes zero bytes;
- the three existing equal-length cross-pass substitutions plus header/order/mode/end-state drift;
- partial body, late body mismatch, late parser failure, parent write failure, and full-disk simulation,
  all leaving no valid seal;
- preexisting path, leaf symlink, directory symlink, hard-link count, directory replacement, stage-root
  replacement, unexpected node, and post-write content/mode drift;
- crash injection before/after every file sync, tree validation, audit transition, seal publication,
  parent-directory sync, and terminal audit;
- audit-before-write failure and audit-after-seal failure, both blocking launch;
- runtime executable, worker, parser dependency, argv, environment, and limit drift between passes;
- attempted child filesystem write, child process, worker thread, addon, inspector, and network access;
  Node 24 must fail the real-worker network-isolation capability gate rather than pretend denial; and
- exact cleanup allowlist behavior with identity/link/mount ambiguity refusing deletion.

Tests must never read user `.npmrc`, `.env`, credentials, tokens, keys, certificate material, user npm
cache, or an existing project. They must not contact a registry, download a package, run package code,
modify a persistent stage, or change the audit database schema.

## Approval boundaries after this check

Approval of this document authorized one checkpoint only:

- a network-free bounded child-worker protocol;
- synthetic two-pass parsing using existing repository fixtures;
- an APG-owned synthetic POSIX materializer inside isolated temporary directories;
- synthetic seal/state/audit adapters and failure injection; and
- no CLI connection, production profile, durable database migration, real artifact, or package launch.

The following remain separate explicit approvals:

1. real public-registry metadata confirmation and exact production graph/profile review;
2. real target artifact download and read-only pass-A acceptance;
3. real isolated pass-B materialization and persistent-stage behavior;
4. receipt schema 1.2 and durable audit/recovery integration; and
5. staged package startup followed by separately approved MCP tool actions.

Direct npm/npx and any package execution not explicitly routed through APG remain outside APG coverage.

## Known risks and mitigations

| Residual risk | Current mitigation | Release-blocking condition |
| --- | --- | --- |
| Node Permission Model is not a hostile-code sandbox | precise assurance language, minimal grants, child boundary, later OS-provider option | any sandbox/attestation claim based only on Node flags |
| Node 24 cannot deny network through the Permission Model | capability-gate real worker; require approved OS provider or Node 25+ | silent Node 24 downgrade or real archive parse without no-network evidence |
| same-user intermediate-path race | private `0700` random root, no-follow exclusive leaves, identity checks, no unsealed publication | production claim of same-user containment without descriptor-relative/native support |
| worker/parser module substitution race | bind and revalidate exact executable/worker/dependency byte manifest before both passes | any unbound runtime file or identity drift |
| external memory or parser CPU exhaustion | separate child, V8/protocol/archive limits, wall deadline, kill/quarantine | child can continue after deadline or parent buffers unbounded data |
| pass differential or parser smuggling | same exact runtime/config, authenticated full transcript, ordered streaming equality | any warning/recovery/ignored member or unmatched event/body/end state |
| crash/power loss leaves partial files | unsealed pending root is never launchable; inventory and exact cleanup rules | path presence alone can authorize launch or cleanup follows ambiguous identity |
| audit failure after seal | durable READY_TO_COMMIT, seal, then durable READY; incomplete state blocks launch | terminal audit failure is reported as success or causes materialization retry |
| filesystem durability differs by platform/filesystem | file and directory sync, crash injection, POSIX-only v0, explicit limits | unsupported filesystem semantics or unverified publication behavior |
| USTAR-only grammar rejects legitimate npm packages | fail closed; expand grammar only through a later exact profile/review | permissive fallback to PAX/GNU/recovery behavior |
| cleanup deletion can be unsafe or fail | exact owned-root revalidation, no blind recursive deletion, quarantine/manual review | cleanup crosses root/mount/link boundary or deletes identity-drifted path |

## Implemented network-free checkpoint

The local implementation now includes:

- one fresh shell-free, permission-gated child process for every pass;
- an exact hashed runtime file manifest, sanitized empty environment, private `0700` cwd, fixed V8
  limits, wall deadline, process-group termination, and bounded stdout/stderr;
- one stdin channel carrying a closed request, exact artifact bytes, and per-frame acknowledgements, plus
  a length-prefixed closed-schema stdout protocol;
- parent reconstruction and runtime authentication of the pass-A transcript rather than trust in a
  child-created object;
- pass-B entry/body/end comparison with at most 64 KiB body chunks and parent-side length/hash checks;
- a POSIX writer using private random pending roots, explicit directories, exclusive no-follow file
  creation, initial restrictive modes, file/directory sync, complete tree revalidation, and no cleanup
  of identity-ambiguous quarantine state;
- exclusive same-filesystem seal publication and a required synthetic audit sequence of
  `materialization_started -> ready_to_commit -> ready`; and
- explicit `PASS_A_RUNNING`, `PASS_B_RUNNING`, and `SEALED_PENDING_AUDIT` monotonic states.

The entire 52-fixture corpus runs through child processes. Focused coverage also exercises cross-pass
substitution, forged authority, cancellation, runtime drift, timeout, malformed/oversized protocol,
stderr overflow, preexisting symlink, pending-root permission drift, intermediate-directory
replacement, post-write mutation, seal collision, and audit failure before writes, before seal, and
after seal. Current local execution evidence is Node 26 only. Node 24 and 25 golden compatibility remain
a release-blocking matrix because those runtimes are not installed on this host.

## Rollback

Rollback is removal of the uncommitted worker/protocol/materializer modules and their synthetic tests,
reversal of the additive state/error values and parser worker-body helper, and reversal of this
document's architecture/state references. Tests keep all generated stage data in disposable owned
directories and remove it after each case; no persistent stage or user project was created.

## References

- Node.js v24 Permission Model: <https://nodejs.org/download/release/latest-v24.x/docs/api/permissions.html>
- Node.js v25 Permission Model: <https://nodejs.org/download/release/latest-v25.x/docs/api/permissions.html>
- Node.js v26 Permission Model: <https://nodejs.org/api/permissions.html>
- Node.js worker threads and resource limits: <https://nodejs.org/api/worker_threads.html>
- Node.js child processes and AbortSignal: <https://nodejs.org/api/child_process.html>
- Node.js filesystem flags: <https://nodejs.org/api/fs.html>

## Next

Review the combined exact-parser and bounded-worker/materializer diff, then obtain separate commit/push
approval. After that checkpoint, perform an Exact Production Graph Profile & Read-only Artifact
Acceptance Architecture Check before any live registry request, real artifact download, persistent
stage, receipt/database change, or package startup.
