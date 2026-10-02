# Cursor Firewall Plugin

Silmaril Firewall lifecycle protection for Cursor agents and subagents.

The plugin classifies host-visible prompts, tool calls, tool results, file reads, assistant output, reasoning blocks, and subagent activity with the bundled `@silmaril-security/sdk` 0.6.2. Shadow and Warn return no hook output. Block acts at native denial boundaries, and replaces malicious MCP tool results, only for the exact prediction `MALICIOUS` or a governance action `block`. Other completed-output boundaries remain unchanged and record `block_unavailable`.

## Install

Clone the repository and install a lean copy into Cursor's local plugin directory. Node.js 22 or newer is required:

```sh
git clone https://github.com/Silmaril-Security/CursorFirewallPlugin.git
cd CursorFirewallPlugin
npm ci
npm run install:local
```

Cursor rejects local-plugin symlinks whose targets are outside `~/.cursor/plugins/local`. The installer atomically writes only the packaged runtime, manifests, hooks, skill, and documentation; it excludes `node_modules`, source, and tests.

Restart Cursor or run **Developer: Reload Window**. Confirm **Silmaril Firewall** appears under **Customize → Plugins** and inspect the Hooks output channel for loading errors.

This repository intentionally has no Cursor Marketplace manifest or submission. Local plugin loading is the supported distribution path.

## Configure

The macOS app writes a private configuration file at `~/.cursor/silmaril-firewall.json`:

```json
{
  "enabled": true,
  "apiUrl": "https://...",
  "apiKey": "...",
  "endpointId": "2b64e603-f82a-4aec-9524-9736472dc80a",
  "timeoutMs": 2500,
  "mode": "warn",
  "debug": false
}
```

The file must be a regular file owned by the current user with no group or world permissions. Omit `mode` to use the backend, or set `shadow`, `warn`, or `block`; explicit mode wins over legacy booleans. Symbolic links, files larger than 64 KiB, malformed JSON, invalid recognized fields, and insecure permissions are rejected without falling back to ambient credentials. `SILMARIL_CONFIG_PATH` can select a different private file.

Environment variables remain supported as a fallback when the private file is missing. When the private file exists, it is authoritative for enabled state, credentials, timeout, and mode so ambient shell variables cannot silently replace app-managed protection. `SILMARIL_DEBUG` remains an explicit diagnostic override.

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_ENDPOINT_ID="2b64e603-f82a-4aec-9524-9736472dc80a"
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
export SILMARIL_ENABLED="true"
```

`SILMARIL_TIMEOUT_MS` accepts `250` through `10000`. A value outside that range keeps the 2500 ms default. An invalid `timeoutMs` in the private file rejects the file. `SILMARIL_BLOCK_MALICIOUS=false` selects shadow; omit both `SILMARIL_MODE` and `SILMARIL_BLOCK_MALICIOUS` to leave the effective mode to the backend. Missing or insecure configuration, malformed hook input, invalid classifier responses, SDK failures, network errors, and timeouts fail open. `SILMARIL_DEBUG=true` writes metadata-only diagnostics to stderr; raw classified content is never logged.

Every classifier request carries plugin-owned `metadata.silmaril.provenance` with `schema_version` 1 and `harness` `cursor`. A canonical UUID v4 is sent as `endpoint_id` when configured; otherwise that field is omitted and classification continues. `device_name` is included only when a previously validated macOS Computer Name is available.

Set `SILMARIL_LOCAL_EVENT_DIR` only when the default private evidence spool must be overridden.

## Coverage

| Cursor hook | Firewall label | Shadow behavior | Block-mode capability |
| --- | --- | --- | --- |
| `beforeSubmitPrompt` | `user_input` | Observe | Prevent prompt submission |
| `preToolUse` | `tool_call` | Observe | Deny tool execution |
| `beforeReadFile` | `tool_response` | Observe | Deny content before model consumption |
| `postToolUse` | `tool_response` | Observe | Replace MCP tool output; generic tools record `block_unavailable` |
| `postToolUseFailure` | `tool_response` | Observe | Preserve the failure and record `block_unavailable` |
| `afterAgentResponse` | `llm_output` | Observe | Preserve completed response and record `block_unavailable` |
| `stop` | None | No classification | No mutation |
| `afterAgentThought` | `llm_output` | Observe | Preserve the thought and record `block_unavailable` |
| `subagentStart` | `user_input` | Observe | Deny spawn |
| `subagentStop` | `llm_output` | Observe current summary | Preserve completed output and record `block_unavailable` |

The generic `preToolUse` hook covers Shell, Read, Write, Delete, Task, and MCP tools. The separate `beforeReadFile` hook is retained because it exposes file contents before they reach the model.

Every native hook event produces at most one classification. `subagentStop` classifies only the current `summary` and ignores `agent_transcript_path`; historical state is accumulated by the Firewall sequence cache from earlier incremental hooks. Reasoning is classified only through Cursor's native `afterAgentThought` event.

Cursor Tab/inline-completion hooks are not included. Local plugin installation does not establish a supported cloud-agent distribution path, so cloud coverage is not claimed.

## Enforcement semantics

Shadow and Warn return no hook output. Malicious Warn records `warnDelivery` as `unsupported`. Omit mode to use the backend, set `SILMARIL_MODE=block` for a pilot override, or use the legacy block boolean. Explicit mode wins over that boolean and over the backend mode. If the backend omits mode, the plugin uses shadow. A native block requires effective mode `block` and either `prediction === "MALICIOUS"` or governance `action` `block`. Other prediction strings do not block by themselves.

Post-execution hooks cannot undo tool side effects. Block replaces a malicious MCP result with `updated_mcp_tool_output` and the same safe message in `additional_context` before model reuse. Generic tool results and other unsupported completed-output boundaries remain unchanged and record `block_unavailable`.

## Local evidence

Each completed classification emits a bounded `LocalProtectionEventV1` record to:

```text
~/Library/Application Support/Silmaril/Evidence/incoming
```

The spool directory is private (`0700`), files are private (`0600`), and each event is written to a temporary file before atomic rename. Events contain fingerprints, policy/native decisions, bounded consequence metadata, and version provenance. They never contain prompts, reasoning, assistant output, tool arguments/results, API keys, endpoints, transcripts, workspace paths, or user email. Evidence failures never change a Cursor decision.

## Demo

The bundled `silmaril-demo` skill and launcher point to the hosted demo:

```sh
node scripts/open-playground.mjs
node scripts/open-playground.mjs --open
node scripts/open-playground.mjs --route playground --json
SILMARIL_DEMO_BASE_URL="http://localhost:3001" node scripts/open-playground.mjs
```

JSON output reports only the URL, configuration presence, API-key presence, and API origin. It never prints the key.

## Development

```sh
npm ci
npm run lint
npm test
npm run pack:dry
npm run install:local
```

The committed `dist/cursor-hook.js` is rebuilt from TypeScript and bundles the pinned `@silmaril-security/sdk@0.6.2`, so backend-selected mode and governance decisions are preserved and users do not need to install dependencies after cloning a release.

## Security and license

Report vulnerabilities through GitHub private vulnerability reporting. See [SECURITY.md](SECURITY.md). The plugin is licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## References

- [Silmaril documentation](https://www.silmaril.dev/docs)
- [Cursor plugins](https://cursor.com/docs/plugins)
- [Cursor hooks](https://cursor.com/docs/hooks)
