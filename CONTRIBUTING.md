# Contributing

Thanks for helping improve Agent Permission Guard.

## Development setup

Requirements:

- Node.js 24 LTS
- npm
- a local checkout with no production credentials

Install and verify:

```sh
npm ci
npm run typecheck
npm test
```

Tests must use temporary policy files, temporary SQLite databases, and local mock MCP servers. Do not add telemetry, external writes, credential access, or production service dependencies to tests.

## Pull requests

- Keep changes focused on one security or product concern.
- Add tests for Allow, Ask, Deny, cancellation, audit failure, and other affected fail-closed paths.
- Document policy or audit schema changes.
- Preserve stdout for MCP JSON-RPC; operational messages belong on stderr.
- Do not weaken redaction, loopback binding, dashboard authentication, or default-Ask behavior without an explicit design discussion.
- Run type checking and the full test suite before submitting.

## Security reports

Do not disclose vulnerabilities in public issues or pull requests. Follow [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
