# Exact Archive Parser Artifact & Lock Graph Review

Status: review completed on 2026-09-07 and the separately approved candidate-backed fixture checkpoint
is implemented locally. Exact `tar@7.5.22` and its reviewed six-node graph are now present; only
in-memory synthetic fixtures have been parsed. No real MCP package archive was downloaded or parsed,
and no extraction, stage write, package startup, database migration, publish, commit, or push occurred.

## Decision

The implemented checkpoint uses:

```text
tar: 7.5.22
allowed production import: tar/parse
install mode: package-lock update with lifecycle scripts disabled
current use: network-free adversarial fixture tests only
```

The dependency declaration must remain exact (`"tar": "7.5.22"`), and the complete lock graph below
must remain unchanged. `tar`, its extraction aliases, `Unpack`, member-selection helpers, and every
library filesystem-writing API remain prohibited outside the parser-only adapter boundary.

## Review environment and boundaries

The review used a fresh directory under `/private/tmp`, an empty environment, explicit public
`https://registry.npmjs.org/`, separate empty user/global npm configuration files, a private temporary
cache and TMP directory, and lifecycle scripts disabled. It did not set or reuse a HOME directory and
did not read project/user `.npmrc`, `.env`, token, key, certificate, proxy, or credential values.

Two lockfile-only previews were performed without `node_modules`:

1. a minimal package containing only exact `tar@7.5.22`, to enumerate its production graph; and
2. a copy of APG's current `package.json` and `package-lock.json`, to prove the combined diff.

The APG preview changed only the root exact dependency plus the six package nodes listed below. There
was no unrelated version, URL, integrity, license, engine, or dependency churn.

## Exact registry artifact

| Field | Reviewed value |
| --- | --- |
| package | `tar@7.5.22` |
| registry origin | `https://registry.npmjs.org/` |
| tarball URL | `https://registry.npmjs.org/tar/-/tar-7.5.22.tgz` |
| SHA-512 | `sha512-MFO/QzvtAOmJbkhOaCTvbGcFN9L9b+JunIsDwaKljSOdcLMea3NJ1k9Usz/rjdfSXTq4dfzfeS7W4p4YOAAHeA==` |
| SHA-1 registry shasum | `a696f998136e71487dc3f869a85bba2c67971ba9` |
| license | `BlueOak-1.0.0` |
| engine | Node `>=18` |
| module form | ESM package with ESM and CommonJS conditional exports |
| parser entry | public `./parse` export to dedicated ESM/CommonJS parser modules |
| unpacked metadata | 2,298,662 bytes; 249 files |

The public metadata advertises npm registry signatures, but this checkpoint did not download the
artifact or cryptographically verify those signatures. No provenance-attestation field was observed.
Registry integrity metadata is therefore exact selection evidence, not independent publisher or build
provenance.

The package metadata contains development/release lifecycle entries such as `prepare`, `pretest`, and
`prepublishOnly`. It contains no `preinstall`, `install`, or `postinstall` entry, and the generated lock
node has no `hasInstallScript` flag. Scripts must nevertheless remain disabled for dependency addition,
CI, staging, and all later artifact handling.

## Exact added production graph

| Package | SHA-512 integrity | License | Engine | Production edges |
| --- | --- | --- | --- | --- |
| `tar@7.5.22` | `sha512-MFO/QzvtAOmJbkhOaCTvbGcFN9L9b+JunIsDwaKljSOdcLMea3NJ1k9Usz/rjdfSXTq4dfzfeS7W4p4YOAAHeA==` | BlueOak-1.0.0 | `>=18` | `@isaacs/fs-minipass`, `chownr`, `minipass`, `minizlib`, `yallist` |
| `@isaacs/fs-minipass@4.0.1` | `sha512-wgm9Ehl2jpeqP3zw/7mo3kRHFp5MEDhqAdwy1fTGkHAwnkGOVsgpvQhL8B5n1qlb01jV3n/bI0ZfZp5lWA1k4w==` | ISC | `>=18.0.0` | `minipass` |
| `chownr@3.0.0` | `sha512-+IxzY9BZOQd/XuYPRmrvEVjF/nqj5kgT4kEq7VofrDoM1MxoRjEWkrCC3EtLi59TVawxTAn+orJwFQcrqEN1+g==` | BlueOak-1.0.0 | `>=18` | none |
| `minipass@7.1.3` | `sha512-tEBHqDnIoM/1rXME1zgka9g6Q2lcoCkxHLuc7ODJ5BxbP5d4c2Z5cGgtXAku59200Cx7diuHTOYfSBD8n6mm8A==` | BlueOak-1.0.0 | `>=16 || 14 >=14.17` | none |
| `minizlib@3.1.0` | `sha512-KZxYo1BUkWD2TVFLr0MQoM8vUUigWD3LlD83a/75BqC+4qE0Hb1Vo5v1FgcfaNXvfXzr+5EhQ6ing/CaBijTlw==` | MIT | `>=18` | `minipass` |
| `yallist@5.0.0` | `sha512-YgvUTfwqyc7UXVMrB+SImsVYSmTS8X/tSrtdNZMImM+n7+QTriRXyXim0mBrTXNeqzVF0KWGgHPeiyViFFrNDw==` | BlueOak-1.0.0 | `>=18` | none |

Every resolved URL is an HTTPS artifact at the public npm registry. The exact graph adds no optional or
development package, native add-on, prebuilt binary, install script flag, alternate registry origin, or
git/file dependency. All engine ranges include APG's supported Node 24-26 range.

The license labels are four BlueOak-1.0.0 packages, one ISC package, and one MIT package. This is an
inventory for the normal release-notice review, not legal advice or a final distribution conclusion.

## Advisory result

An npm production audit of the isolated combined APG preview returned exit code 0 with zero known info,
low, moderate, high, or critical vulnerabilities. The audited combined lock contained 24 production
packages. This result is a point-in-time check of npm's advisory data, not proof that the parser or its
dependencies have no unknown vulnerability.

The historical node-tar parser and extraction advisories documented in the prior architecture check
still govern the design. Exact pinning does not relax the USTAR-only grammar, PAX/GNU rejection,
two-pass transcript comparison, bounded decompression, fatal warnings, or APG-owned no-follow writer.

## Approved candidate checkpoint boundary

A separate approval authorized only:

- adding exact `"tar": "7.5.22"` and the six reviewed lock nodes;
- importing only `tar/parse` behind one archive adapter module;
- build-time enforcement against forbidden node-tar imports/APIs; and
- running the existing in-memory, network-free adversarial fixture corpus against the candidate parser.

It did not authorize a real MCP package archive download, a real package parse/extraction, filesystem
materialization, persistent stage, production package profile, package startup, receipt change, database
migration, publish, or push.

The exact dependency command for that separately approved checkpoint must run in a credential-free
environment with the public registry, scripts disabled, exact-save enabled, audit/fund/provenance side
effects disabled, and no project/user npm configuration access. After the lock update, the resulting
diff must be byte-for-byte equivalent in scope to this preview before parser tests may run.

## Known risks and mitigations

| Residual risk | Mitigation in the next checkpoint | Blocking escalation condition |
| --- | --- | --- |
| broad package exposes extraction/write APIs | permit only literal `tar/parse`; static import/symbol tests fail the build | any adapter import of root, `x`, `extract`, `unpack`, `list`, or writer APIs |
| parser zero-day or semantic differential | exact pin, USTAR-only policy, independent golden bytes, two identical passes | any warning, ignored entry, inconsistent event/body/end state, or new advisory |
| transitive compromise or graph drift | exact lock nodes, public origins, SHA-512, scripts disabled, reviewed diff | any new node, changed integrity/origin, optional/native/install-script flag, or lock churn |
| metadata integrity is not provenance | preserve assurance wording; do not claim publisher/build identity | production provenance claim without a separately verified attestation design |
| package scripts exist in metadata | always use `--ignore-scripts`; assert no install lifecycle fields/lock flag | any `preinstall`, `install`, `postinstall`, or `hasInstallScript` appearance |
| license/notice omission | retain exact license inventory and perform release-notice review before shipping | unresolved distribution-notice requirement |
| supported-Node gzip/parser drift | run the same golden corpus on Node 24, 25, and 26 before release | any cross-major transcript or terminal-state difference |
| in-process resource exhaustion | byte/count/depth/ratio limits, deadline and abort; no writes in pass A | abort cannot bound CPU/memory or leaves parser work running |

## Rollback

This review changed no APG dependency or runtime code. Its repository rollback is deletion of this review
document and reversal of its documentation/state references. The temporary preview directory can be
deleted in full because it contains only empty npm configs, cache metadata, and disposable manifest/
lockfile copies; it contains no installed package tree or APG source modification.

## Implemented candidate checkpoint

The implementation imports only `Parser` from literal `tar/parse`. APG first validates an exact
single-member, flag-free gzip envelope, CRC-32/ISIZE, bounded decompression ratio, strict USTAR header
and checksum fields, exactly two terminal zero blocks, zero padding, allowed entry types, and resource
ceilings. It then requires node-tar's ordered path/type/size/mode/body interpretation to match the APG
envelope view before the existing portable path/tree policy can issue a frozen transcript.

The transcript binds exact candidate identity, archive rules, artifact SHA-512 and sizes, ordered entry
identity, observed sizes, normalized modes, body SHA-256 values, and an aggregate SHA-256 digest. One
runtime authority authenticates transcript objects and requires complete equality across two inspected
passes. No filesystem, network, subprocess, extraction, list, unpack, or materialization API is imported.

The core adapter remains in-memory and synchronous, but the accepted network-free worker foundation now
runs each pass inside a fresh bounded child process and keeps all filesystem writes in the APG parent.
The local synthetic matrix is verified on Node 26 only. Node 24/25 compatibility, a real artifact, and
persistent materialization remain separately blocked.

## Next

Review the combined exact parser and bounded worker/materializer diff and obtain separate commit/push
approval. Then perform an Exact Production Graph Profile & Read-only Artifact Acceptance Architecture
Check before any real MCP package artifact download, production profile, persistent stage, receipt or
database change, or package startup.
