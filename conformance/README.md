# MCP authorization conformance

This directory contains a deliberately small MCP HTTP adapter for exercising
`AttestoClient.MCPAuthorization` against the official Model Context Protocol
conformance harness. It is test infrastructure, not an MCP SDK and not part of
the Hex package.

The adapter implements only the traffic needed to reach the authorization
boundary: the stateful 2025-11-25 initialization lifecycle, the stateless
2026-07-28 request metadata, `tools/list`, and `tools/call`. OAuth discovery,
registration selection, authorization-code exchange, scope escalation,
authorization-server migration, token binding, and Bearer presentation all use
the package's public API.

From a checkout of `modelcontextprotocol/conformance` with its npm dependencies
installed, run the authorization scenarios frozen into either requirements
file:

```sh
conformance/run_mcp_auth_conformance.sh /path/to/conformance 2025-11-25
conformance/run_mcp_auth_conformance.sh /path/to/conformance 2026-07-28
```

The runner extracts only the `auth/` client scenarios from the selected frozen
requirements file. Non-authorization MCP conformance belongs to a full MCP
client implementation and is intentionally outside this library's claim.
