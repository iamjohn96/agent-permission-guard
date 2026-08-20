# Connect Agent Permission Guard to Codex

This guide connects a local Codex host to an STDIO MCP server through Agent Permission Guard (APG).

Codex CLI, the IDE extension, and the ChatGPT desktop app share MCP configuration on the same Codex host. Adding or removing a server changes that local Codex configuration. Review every upstream command before registering it.

## Prerequisites

- Node.js 24-26
- Codex CLI with `codex mcp` support
- Agent Permission Guard `0.1.x`

```sh
npm install --global agent-permission-guard
mkdir apg-codex-demo
cd apg-codex-demo
apg init
apg doctor -- npx
```

Review `.apg/policy.yaml` before continuing. The starter policy defaults unmatched tools to Ask.

## Safe reference-server demo

The following command changes your local Codex MCP configuration. It registers the pinned official Everything reference server behind APG:

```sh
codex mcp add apg-everything -- \
  apg proxy \
  --policy "$PWD/.apg/policy.yaml" \
  --audit-db "$PWD/.apg/audit.sqlite" \
  --dashboard-port 47831 \
  -- npx -y @modelcontextprotocol/server-everything@2026.8.18
```

`npx` downloads and executes that reviewed external package the first time Codex starts it. Do not replace it with an upstream command you have not inspected and trusted.

Verify registration:

```sh
codex mcp get apg-everything
codex mcp list
```

Restart the Codex client after adding the server. In clients that support it, use `/mcp` to inspect connected servers.

APG writes its tokenized localhost dashboard URL to MCP stderr when the server starts. Open that exact URL to review Ask decisions and inspect the audit trail. Some Codex surfaces may not make MCP stderr easy to discover; improving dashboard discovery is a known developer-alpha limitation.

## Protect another local STDIO server

Replace only the command after APG's second `--` separator:

```sh
codex mcp add apg-protected -- \
  apg proxy \
  --policy "/absolute/path/to/.apg/policy.yaml" \
  --audit-db "/absolute/path/to/.apg/audit.sqlite" \
  --dashboard-port 47831 \
  -- <trusted-upstream-command> [args...]
```

Use absolute policy and database paths because Codex may start the MCP process from a different working directory.

APG `0.1.x` intentionally forwards only `PATH` to the upstream process. Servers that require API keys or other environment credentials are not yet supported by this setup. Do not put secrets directly in command-line arguments.

## Remove the demo

This command changes your local Codex MCP configuration:

```sh
codex mcp remove apg-everything
```

Removing the Codex entry does not delete `.apg/policy.yaml` or `.apg/audit.sqlite`.

## Current scope

- Local STDIO MCP servers only
- Localhost approval dashboard
- Local YAML policy and SQLite audit database
- No remote HTTP MCP proxy yet
- No credential forwarding yet
