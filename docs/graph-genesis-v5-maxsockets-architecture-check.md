# Graph Genesis post-v5 npm connection-cap architecture check

Status: approved for network-free implementation and verification only.
Baseline: `3134953ad358c5217fa451a56d4036f3aa46ec80`.

## Observed trigger and narrow change

The supplied v5 acceptance result reached the authenticated private predicate
`concurrent_request_limit` before a broker request ordinal was reserved. Its safe counters were ten starts,
four active requests, six validated responses and 644145 validated bytes. The process was cancelled and
quarantined; no candidate or Dashboard state survived. This result is retained as evidence and is not reopened,
modified or reused for a later acceptance.

The change is exactly one fixed argument in `buildGraphGenesisLaunch`:

```text
--maxsockets=4
```

It is placed once after `--save-exact` and before `--ignore-scripts`. npm 11.16.0 defines `maxsockets` as the
maximum connection count per protocol/host/port origin, flattens it to `maxSockets`, passes install options to
Arborist and then to registry fetch/its HTTP agent. The live launch has one loopback registry origin, so this
limits npm's origin connection pressure to four. This source inspection is design evidence only; it does not
claim a successful npm runtime experiment.

## Invariants

- Broker limits remain: `concurrentRequests=4`, `responseBytes=4 MiB`, `aggregateResponseBytes=64 MiB`,
  `totalRequests=256`, and `requestTimeoutMs=10000`.
- The launch remains shell-free, lock-only, exact-version, ignore-scripts and loopback-registry-only.
  Tarball/download/install/`node_modules`/lifecycle/package code/import/activation remain prohibited.
- The broker remains an immediate reservation boundary. There is no queue, retry, fallback, extra approval
  capability or audit-schema change. First failure still wins once and aborts pending work.
- The exact args are canonicalized into the launch digest; the hardened plan includes that digest; the Dashboard
  execution envelope includes it and hashes it. A previous launch's approval cannot authorize this launch.

`maxsockets` bounds connections, not an independently authenticated count of in-flight HTTP requests. The broker
therefore remains the authoritative fail-closed request boundary. A fifth reservation must still latch failure;
the flag is a compatibility control intended to avoid issuing that fifth concurrent loopback request.

## Alternatives rejected

Raising the broker cap to eight would increase worst-case active reservation from `4 × 4 MiB = 16 MiB` to
`8 × 4 MiB = 32 MiB`, double simultaneous public metadata exposure and cancellation fan-out, and suppress the
observed fail-closed signal. The 64 MiB aggregate cap would remain but does not justify the increased burst.

Adding a broker queue would require new scheduler state: a decision whether durable request intent is recorded at
enqueue or dispatch, queue timeout accounting, atomic cancellation/removal, ordering semantics, and a definition
of retry-free liveness. Those changes would alter audit interpretation and approval identity far beyond one fixed
launch option.

## Required verification and later acceptance

Network-free tests must prove the exact flag occurs once at the fixed position, and that missing, changed or
duplicate variants fail hardened plan preparation. They must also prove the envelope hash covers the launch digest
and retain the unchanged broker limits and first-failure behavior. Typecheck, build, full safe suite and diff
checks must pass without package/lockfile, migration, audit/DB schema, parser or approval changes.

No npm runtime result is established by this checkpoint. A later live acceptance requires a reviewed commit,
fresh private root/audit/output/state paths, a new exact command approval and a new Dashboard Approve once. It
must not reuse any v1-v5 root, approval, token, candidate, audit or conclusion. It must preserve stderr through
terminal observation, verify the broker never exceeds four active requests, and retain terminal audit/quarantine
evidence under the existing no-retry rule.
