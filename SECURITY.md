# Security Policy

Agent Permission Guard is security-sensitive software and is currently a developer alpha.

## Supported versions

Security fixes are provided for the latest `0.1.x` release and the current `main` branch. Older alpha builds may not receive patches.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use a [private GitHub security advisory](https://github.com/iamjohn96/agent-permission-guard/security/advisories/new) and include:

- the affected version or commit;
- the policy, transport, or dashboard boundary involved;
- minimal reproduction steps;
- expected and observed behavior;
- potential impact and any known mitigations.

Do not include real credentials, private user data, or destructive proof-of-concept payloads. Reports will be acknowledged and triaged on a best-effort basis while the project remains in alpha.

## Security boundaries

The local gateway is the enforcement point. The dashboard is loopback-only and token-protected, but it is not a substitute for operating-system account isolation. Review the documented limitations before using APG with production credentials or irreversible tools.
