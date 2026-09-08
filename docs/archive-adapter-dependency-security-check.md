# Archive Adapter Dependency Security Check

Status: accepted by Jonny on 2026-09-07. The approved library-independent fixture foundation is
implemented, committed, and pushed at `e747325`. The separately approved exact artifact/lock review and
candidate-backed synthetic checkpoint are recorded in
`docs/exact-archive-parser-artifact-lock-review.md`. Exact `tar@7.5.22` is now present, but real package
archive handling, stage writes, package startup, commit, and push remain unapproved.

This check authorizes no dependency change, registry request, package download, real archive parse or
extraction, persistent stage write, package startup, database migration, publish, or push. Candidate
versions below were observed in their public upstream repositories. The exact npm registry artifact,
integrity, and APG lockfile result remain a later approval boundary.

## Decision summary

Use `tar` (`node-tar`) only as a **provisional parser candidate**, imported through its parser-only
`tar/parse` export. Never call `tar.extract`, `tar.x`, `Unpack`, list member-selection helpers, archive
creation, replacement, update, ownership, or library filesystem materialization APIs.

The candidate observed in the upstream repository is `tar@7.5.22`. A later dependency approval must
pin the exact reviewed version, lock the complete production graph, verify registry integrity and
licenses, install with lifecycle scripts disabled, and rerun this security gate. A newer version is not
automatically acceptable, and `^7.5.22` is not an acceptable production declaration.

`tar-stream@3.2.1` remains a reserve candidate rather than the first choice. It has a narrower
parser-only purpose, but its current dependency graph includes Bare-runtime packages, its PAX/GNU
metadata handling is less directly policy-configurable, and the current public evidence provides less
security-history visibility. System `tar`, `tar-fs`, and a custom tar parser are rejected.

The recommendation is therefore **conditional**, not permission to add `tar`:

```text
verified quarantine artifact
  -> APG-owned bounded gzip envelope
  -> exact pinned tar/parse candidate
  -> pass A: inspect every entry and body; write nothing
  -> authenticated ordered transcript
  -> reopen and revalidate the same artifact
  -> pass B: parse again and compare every entry/body to the transcript
  -> APG-owned exclusive no-follow materializer in a fresh private scratch tree
  -> complete post-materialization tree validation
  -> atomic seal only after every check succeeds
```

No parser result alone is a safe-to-run stage. A stage becomes runnable only after both passes,
materialization, complete tree validation, durable evidence, and sealing succeed.

## Observable success criteria

This checkpoint is successful when:

- one parser candidate and its prohibited APIs are explicit;
- the dependency remains absent from `package.json` and `package-lock.json`;
- archive policy is narrower than the parser's feature set;
- preflight is provably complete before any destination-tree mutation;
- the inspection and materialization passes cannot silently interpret different members;
- path, type, resource, gzip, parser-warning, timeout, cancellation, and destination-race behavior
  fail closed;
- adversarial fixtures are specified independently of the selected library; and
- later dependency installation and real-archive acceptance remain separately approval-gated.

## Candidate comparison

| Candidate | Strengths | Security/supply-chain concerns | Decision |
| --- | --- | --- | --- |
| `tar` / node-tar parser-only | maintained; Node >=18; explicit `tar/parse` export; strict warnings; metadata and decompression controls; active advisory response | broad package also ships filesystem mutation APIs; five direct runtime dependencies; extensive traversal, parser-differential, and DoS history; current source version is not registry proof | conditional first candidate, parser-only |
| `tar-stream` | parser does not write to the filesystem; small streaming API; MIT | separate gzip layer required; current graph includes `bare-fs` and related runtime surface; PAX/GNU metadata is applied internally; hard-coded metadata ceiling is broader than APG needs; less advisory visibility is not proof of safety | reserve candidate |
| `tar-fs` or another extractor | convenient materialization | combines attacker-controlled parsing with filesystem mutation and link/path behavior | reject |
| system `tar` / `bsdtar` | mature platform tools | platform/version differences, subprocess boundary, environment/configuration, and scanner/extractor interpretation drift | reject |
| custom APG tar parser | minimal apparent dependency graph | APG would own a security-critical binary-format parser and its ambiguity/compatibility bugs | reject |
| native/WASM/libarchive binding | potentially mature parsing | native artifact and build-chain surface, portability, larger dependency review, and new execution/install consequences | defer |

## Candidate dependency facts

The upstream `tar` repository currently declares version `7.5.22`, license `BlueOak-1.0.0`, Node
`>=18`, and these direct runtime ranges:

- `@isaacs/fs-minipass ^4.0.0`
- `chownr ^3.0.0`
- `minipass ^7.1.2`
- `minizlib ^3.1.0`
- `yallist ^5.0.0`

The upstream repository lock currently resolves a small pure-JavaScript runtime graph, but that lock is
not the APG installation result. APG must not copy its integrity values or assume npm will resolve the
same graph. The later dependency checkpoint must inspect the exact APG lockfile diff and confirm:

- no install scripts, native add-ons, prebuilt binaries, optional downloads, or unexpected packages;
- every package's exact version, resolved public-registry URL, SHA-512, license, engine, and dependency
  edge;
- no credential-bearing or non-public registry configuration was consulted;
- no unrelated lockfile churn; and
- `npm audit`/advisory results are evidence only, not a substitute for the fixture gate.

BlueOak, ISC, and other observed license labels require the normal distribution-notice review. This
document makes no legal compatibility conclusion.

## Security-history consequence

The parser candidate has a material security history, including 2026 advisories for PAX/GNU parser
differentials, NUL and numeric PAX crashes, uncontrolled long-path recursion, negative sizes, unlimited
decompression/parse input, and filesystem hardlink/symlink traversal. Upstream reports the reviewed
parser-differential fixed in `7.5.16`, NUL handling in `7.5.17`, numeric type confusion in `7.5.18`, and
member-selection recursion in `7.5.21`. The observed `7.5.22` source is later than those named fixes,
but version ordering is not evidence that future or unpublished defects are absent.

This history leads to mandatory architectural restrictions:

- exact version pinning and a fresh advisory review before every dependency update;
- parser-only import and a code/test ban on all library filesystem-writing APIs;
- no member-selection list or recursive path filter;
- first-profile rejection of all PAX, global PAX, GNU long-name/long-link, sparse, and other extension
  metadata, even if the library can parse them;
- hard failure on every warning, ignored entry, unsupported type, malformed header, trailing semantic
  data, or ambiguous end state;
- process-level timeout/cancellation plus byte, entry, depth, path, and compression ceilings; and
- same parser, same configuration, and same APG policy in both passes.

Rejecting extensions is deliberately restrictive. A production profile whose exact artifact requires
one must receive a new architecture review rather than silently broadening v0.

## Accepted v0 archive grammar

The first adapter accepts only a bounded gzip-wrapped USTAR stream whose decompressed member sequence
is unambiguous under APG rules.

- compressed input must already have the stage plan's exact SHA-512 and size;
- only gzip is accepted; plain tar, zip, brotli, zstd, and format auto-upgrades are rejected;
- the adapter must prove its policy for concatenated gzip members, garbage after the gzip end, CRC
  failure, truncated input, tar zero blocks, and decompressed trailing bytes with fixtures on every
  supported Node major;
- exactly two terminal zero blocks are required in v0; any later non-zero byte fails, and additional
  zero padding is accepted only if a reviewed real artifact needs it and the bounded rule is explicit;
- all headers must be standard USTAR entries; PAX/GNU extension headers fail before their state can
  affect a later file entry;
- only regular files and directories are accepted;
- one literal `package/` root is required and is stripped only after validation;
- all entry bodies, including rejected entries, are drained only inside bounded preflight processing;
  no rejected archive can reach materialization; and
- all parser warnings and recovery behavior are fatal.

Node's gzip behavior changes across the supported Node 24-26 range. APG must not depend on a newer
Node-only trailing-garbage option while `engines` remains `>=24 <27`. If the fixture gate cannot prove
one policy across all supported majors, the adapter remains blocked until a separate decision either
adds a bounded cross-version envelope validator or changes the supported Node range.

## Pass A: inspection and transcript

Open the verified quarantine artifact read-only with no-follow semantics, retain the file descriptor,
and bind `device`, `inode`, regular-file type, link count, mode, size, and SHA-512 to its authenticated
integrity result. Revalidate descriptor metadata before and after parsing.

The adapter uses a fixed configuration with no caller overrides:

- strict parser mode;
- no file/member selection;
- metadata ceiling no greater than 64 KiB, while v0 rejects metadata entries entirely;
- a conservative decompression-ratio ceiling plus independent compressed and expanded byte counters;
- existing profile ceilings for one/aggregate expanded artifact, one file, entries, path bytes, and
  depth;
- one wall-clock deadline and `AbortSignal` propagated through every stream; and
- bounded stable error codes with no raw path/body bytes in public errors.

Before accepting the transcript, APG must consume the entire compressed stream, the entire decompressed
tar stream, every accepted entry body, tar padding, and the terminal state. Early application-level
rejection aborts the parse and permanently fails that artifact; there is no partial success.

For every entry, the authenticated ordered transcript binds at least:

```text
adapter contract version
candidate package name and exact version
archive rules version
artifact SHA-512 and compressed size
entry index
raw normalized USTAR path
normalized relative output path
entry type
declared and observed body size
normalized output mode
body SHA-256
ordered aggregate transcript digest
total entries, files, directories, and expanded bytes
parser completion and exact-end flags
```

The transcript object is issued only by the archive authority, deeply frozen, and runtime-authenticated.
A caller-created lookalike cannot enter pass B.

## Pass B: comparison and materialization

Pass B reopens the artifact and repeats artifact identity and SHA-512 validation before parsing. It uses
the same parser version, configuration, policy version, and limits as pass A. Every header, normalized
field, body byte count, body SHA-256, order, total, completion event, and aggregate digest must match the
authenticated pass-A transcript exactly.

APG, not node-tar, owns all filesystem writes:

- materialize only into a new random APG-owned `0700` scratch directory;
- create directory segments one at a time after no-follow/lstat checks;
- open regular-file temporaries with exclusive, no-follow creation and mode `0600`;
- hash the complete body before a file can receive its final path;
- never preserve archive uid/gid, ownership, ACLs, xattrs, timestamps, setuid/setgid, or link state;
- normalize final regular-file/directory modes to the reviewed policy;
- reject pre-existing targets, replacements, unexpected link counts, and destination identity changes;
- keep the scratch tree outside the runnable namespace until the entire second pass and post-scan
  succeed; and
- on failure, mark the session unusable. Cleanup may target only the exact owned random directory.

No output path becomes a sealed or launchable stage incrementally. An invalid entry late in the archive
must leave zero runnable output even if earlier file bodies were fully processed.

## Required library-independent fixture corpus

Fixtures must be byte-built by a small test-only USTAR/gzip builder that imports neither candidate
library. Expected transcripts are explicit test data, not output generated by the parser under test.
System tar programs are not production or authoritative test oracles.

### Valid controls

- minimal `package/` directory and one regular file;
- multiple directories/files with exact padding and empty file;
- chunk boundaries split at every header, body, padding, gzip, and end-marker boundary;
- maximum accepted file/path/depth/count/expanded-byte boundaries; and
- deterministic same bytes produce the same transcript on Node 24, 25, and 26.

### Format and parser failures

- bad header checksum, corrupt gzip CRC, truncation at every structural phase;
- missing/one/malformed tar zero blocks, non-zero trailing tar bytes, gzip trailing garbage, and
  concatenated gzip members;
- plain tar, zip, brotli, zstd, and unknown compression;
- negative, base-256, overflow, fractional-equivalent, or header/body-mismatched sizes;
- huge or malformed PAX, global PAX, GNU long-name/link, duplicate keys, numeric path, embedded NUL,
  and `PAX x -> GNU L/K -> file` parser-smuggling sequences;
- unknown type, contiguous/sparse file, symlink, hardlink, device, FIFO, socket, and metadata-only entry;
  and
- warning/recovery/ignored-entry behavior always becomes one stable rejection.

### Path and tree failures

- POSIX absolute, Windows drive/UNC, backslash, `.`, `..`, empty segment, NUL/control, invalid UTF-8,
  Unicode normalization, and case-fold ambiguity;
- duplicate path, file/directory type conflict, prefix conflict, and order variants;
- missing or multiple `package/` roots, nested `node_modules`, and `.npmrc`;
- path byte/depth limit plus many zero-byte entries; and
- setuid/setgid, ownership, xattr, ACL, and unexpected hardlink-count evidence.

### Resource and differential failures

- per-file, per-artifact, aggregate-expanded, entry-count, metadata, path, depth, compression-ratio,
  timeout, and cancellation boundaries;
- high-ratio compressed data, sparse logical-size claims, and many empty members;
- mutate artifact header/body, replace path/inode, reorder entries, or alter limits between passes;
- destination pre-existence, symlink swap, directory replacement, and identity drift;
- late invalid member after valid files proves no runnable output; and
- forged, replayed, cross-artifact, cross-version, or cross-policy transcript rejection.

Every negative fixture must assert bounded completion, stable sanitized error identity, no destination
escape, no package code execution, no child process, no network, and no runnable seal.

## Dependency approval gate

Adding a parser dependency requires a new explicit approval with the exact package/version and command.
Before asking for it, prepare and review:

1. registry metadata for the exact candidate using the existing anonymous read-only boundary;
2. tarball URL/origin, SHA-512, published files, package scripts, engine, license, and advisories;
3. a dry-run lockfile diff showing the exact transitive production graph and no unrelated churn;
4. license/security review of every added production package;
5. the library-independent fixture builder and expectations, still without importing the candidate;
6. rollback as removal of the exact dependency and lockfile nodes; and
7. the exact install command with scripts disabled and a credential-free public-registry environment.

That approval may authorize only the dependency/lockfile change and network-free parser tests. It does
not authorize a real npm package tarball download, persistent APG stage, or package startup.

## Known risks and mitigations

| Residual risk | Mitigation now | Later release gate |
| --- | --- | --- |
| parser zero-day or semantic differential | USTAR-only grammar, extension rejection, two identical passes, exact pin | advisory monitoring and version-specific corpus |
| parser package contains unused filesystem APIs | import-lint/architecture test permits only `tar/parse`; APG writer is separate | fail build on forbidden imports/symbols |
| transitive supply-chain compromise | exact lock graph, public origin/integrity, scripts disabled | reviewed dependency update only |
| gzip/version interpretation drift | cross-Node golden fixtures, exact-end assertions | block unsupported majors or approve a dedicated envelope validator |
| decompression/CPU/memory exhaustion | compressed/expanded/ratio/metadata/count limits, deadline, abort | isolated worker/process limit if in-process abort is insufficient |
| same-user destination or artifact race | private owned roots, descriptor identity, no-follow/exclusive writes, two hashes | stronger OS sandbox/descriptor-based primitives |
| crash after scratch writes | scratch is never runnable; exact owned cleanup only | crash-recovery inventory with explicit cleanup action |
| valid but malicious package code | staging never claims safety; no scripts; separate startup approval | sandboxing/provenance remain separate dimensions |
| restrictive USTAR profile rejects real package | fail closed and review exact artifact | separately approve only the minimum required grammar expansion |

The largest residual risks are parser zero-days and same-user/root races. The architecture reduces their
impact but cannot eliminate them. `artifact integrity verified` must never be presented as `package is
safe` or `runtime is contained`.

## Sources reviewed

- node-tar README and security guidance: <https://github.com/isaacs/node-tar/blob/main/README.md>
- node-tar package metadata and parser export: <https://github.com/isaacs/node-tar/blob/main/package.json>
- node-tar parser implementation: <https://github.com/isaacs/node-tar/blob/main/src/parse.ts>
- node-tar security advisories: <https://github.com/isaacs/node-tar/security/advisories>
- parser-differential advisory: <https://github.com/isaacs/node-tar/security/advisories/GHSA-vmf3-w455-68vh>
- long-path recursion advisory: <https://github.com/isaacs/node-tar/security/advisories/GHSA-r292-9mhp-454m>
- NUL PAX advisory: <https://github.com/isaacs/node-tar/security/advisories/GHSA-gvwx-54wh-qm9j>
- PAX numeric type advisory: <https://github.com/isaacs/node-tar/security/advisories/GHSA-w8wr-v893-vjvp>
- unlimited parse/decompression advisory: <https://github.com/isaacs/node-tar/security/advisories/GHSA-23hp-3jrh-7fpw>
- tar-stream package and parser source: <https://github.com/mafintosh/tar-stream/blob/master/package.json>,
  <https://github.com/mafintosh/tar-stream/blob/master/extract.js>
- Node gzip API: <https://nodejs.org/api/zlib.html>

## Implemented fixture checkpoint

The accepted network-free foundation now provides:

- a test-only USTAR byte builder with explicit fields, checksums, padding, and terminal blocks;
- a deterministic test-only gzip writer with stored DEFLATE blocks, CRC-32, and size trailer;
- 52 fixtures: 2 valid controls, 6 gzip rejections, 19 tar/format rejections, 21 policy rejections,
  and 4 resource-limit rejections;
- explicit expected transcripts with ordered paths, normalized modes, sizes, and body SHA-256 values;
- three equal-length cross-pass substitutions covering header, order, and body drift;
- direct coverage of the existing portable archive policy; and
- an invariant test that neither archive candidate appears in the fixture source or dependency files.

The fixture builder creates bytes only in memory and imports no archive parser. No fixture is a real npm
package archive and no package code runs. The separately accepted synthetic materializer writes only
these fixture bodies beneath test-owned disposable private directories.

The exact registry artifact and APG lock-graph review conditionally accepts exact `tar@7.5.22` for a
separately approved, network-free parser fixture checkpoint. That checkpoint is now implemented: all 52
independent fixtures are evaluated through an APG-owned strict gzip/USTAR envelope and the exact
`tar/parse` candidate, while the original fixture builder remains library-independent. It does not
broaden the real-archive boundary.

The accepted bounded-worker checkpoint now moves both parser passes into fresh permission-gated child
processes and keeps every stage write in the APG parent. It authenticates the complete pass-A transcript,
compares pass-B chunks, verifies the final tree, and requires exclusive seal plus ordered synthetic audit
evidence. This is fault/resource containment, not an OS sandbox, and it remains unconnected to real
package artifacts or production staging.
