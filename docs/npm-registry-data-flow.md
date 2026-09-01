# npm Registry Data Flow

Status: IG2.5 read-only public-registry check and one isolated IG3 real npm installation acceptance completed

## Purpose

Install Guard needs to resolve a requested npm package to one exact version and identify whether the selected version declares an install lifecycle script. IG2 introduces a read-only registry adapter behind an injectable transport. The default test suite uses only fake responses.

The user-facing read-only command is:

```text
apg inspect <npm|npx> <package-spec> [--registry <https-url>]
```

It prints an analysis result only. It does not create an approval ticket, download a tarball, update `package.json`, or invoke npm/npx.

## External request

For a request such as `yaml@latest`, the adapter prepares:

```text
GET https://registry.npmjs.org/yaml
Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8
Authorization: not sent
Redirects: rejected
Timeout: 5 seconds
Maximum decoded response: 5 MB
```

The package name is disclosed to the selected registry, together with ordinary connection metadata such as the user's IP address and request time. APG sends no project path, working directory, policy, audit record, agent prompt, account identifier, or telemetry.

The official npm registry documentation defines `GET /<package>` for package metadata and recommends the abbreviated install metadata media type because full package documents can be much larger: <https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md>.

## Credential boundary

APG does not read `.npmrc`, environment tokens, key files, certificate files, or npm login state in IG2. npm documents that `.npmrc` may contain `_authToken`, `_auth`, username/password material, CA files, certificates, and key-file paths: <https://docs.npmjs.com/cli/v12/configuring-npm/npmrc/>.

The v0 adapter therefore accepts only an explicit HTTPS registry URL without embedded credentials, query parameters, or fragments. It sends no `Authorization` header. Authenticated private registries are out of scope until a separate credential-handling architecture is approved.

## Accepted metadata

The adapter accepts only:

- HTTP 200
- JSON or npm's abbreviated install metadata content type
- an exact matching package name
- a matching exact version object
- a dist object with a tarball URL
- an exact requested version or a dist-tag resolved inside the same response

For an IG3 execution plan, the adapter also preserves the selected version's HTTPS tarball URL, SHA-512 integrity value, and declared executable-bin mapping when present. The metadata adapter itself does not fetch the tarball or execute the binary; only the separately approved npm/npx runner may perform those consequences.

## Controlled install network boundary

After one-time approval, `apg install` invokes the approved npm/npx executable with the exact package/version and fixed HTTPS registry argument. The child receives private empty npm configuration, HOME, temporary/cache paths, and an allowlisted environment without parent credentials.

npm itself performs dependency metadata and tarball requests. APG does not proxy each npm HTTP request, does not observe every transitive endpoint, and cannot guarantee that npm applies APG's metadata-adapter redirect policy. The approval prompt therefore treats package download and local mutation/code execution as explicit consequences of the same immutable plan.

After npm exits successfully, APG requires the resulting lockfile to match both the approved top-level version and SHA-512 integrity. This is post-execution detection, not pre-execution containment.

Version ranges are rejected in v0 because APG does not add a semver dependency and should not implement a partial range resolver that appears authoritative.

## Evidence limitations

The abbreviated response supports exact version resolution and `hasInstallScript`. It does not provide enough trusted evidence for all proposed Install Guard signals, including complete advisory status, typosquat analysis, publisher age, and provenance verification.

IG2 marks this as `limited_registry_evidence`. The built-in policy maps that signal to Ask. A successful registry response therefore does not silently imply that a package is safe.

## Cache

- memory only; never written to disk
- scoped to the exact package and requested specifier
- default TTL: 5 minutes
- default maximum: 128 entries
- only resolved and definitively unresolved responses are cached
- network failures and contradictory responses are not cached
- cache disappears when APG exits

## Failure behavior

| Condition | Result |
| --- | --- |
| Package not found | Deny as unresolved |
| Version/tag not resolved exactly | Deny |
| Range requested | Deny in v0 |
| Timeout, connection error, or non-200 response | Ask only when the original request already contains an exact version; otherwise Deny |
| Wrong package/version identity | Ask only for an already exact request; otherwise Deny |
| Unsupported content type or invalid JSON | Ask only for an already exact request; otherwise Deny |
| Oversized response | Same fail-closed unavailable behavior |

Even after Ask approval, an unavailable response can execute only an exact version already present in the request. A mutable tag or range never proceeds without successful exact resolution.

## Not included

- no registry request during tests or this milestone's validation
- no `.npmrc` or credential access
- no npm advisory/audit endpoint
- no download-count or search endpoint
- no typosquat service
- no tarball download
- no real package installation during automated IG3 validation; one separately approved isolated npm acceptance was executed with lifecycle scripts disabled
- no disk cache
- no telemetry
