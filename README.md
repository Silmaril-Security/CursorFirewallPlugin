# Cursor Firewall Plugin

Silmaril Firewall lifecycle protection for Cursor agents and subagents.

The plugin classifies host-visible prompts, tool calls, tool results, file reads, assistant output, reasoning blocks, and subagent activity with `@silmaril-security/sdk`. Shadow mode is the default and never changes Cursor behavior. Block mode acts only on the exact SDK prediction `MALICIOUS` and only where Cursor exposes a native enforcement response.

## Install

Clone the repository and load it from Cursor's local plugin directory:

```sh
git clone https://github.com/Silmaril-Security/CursorFirewallPlugin.git
mkdir -p "$HOME/.cursor/plugins/local"
ln -s "$(pwd)/CursorFirewallPlugin" "$HOME/.cursor/plugins/local/silmaril-firewall"
```

Restart Cursor or run **Developer: Reload Window**. Confirm **Silmaril Firewall** appears under **Customize → Plugins** and inspect the Hooks output channel for loading errors.

This repository intentionally has no Cursor Marketplace manifest or submission. Local plugin loading is the supported v0.1.0 distribution path.

## Configure

Set the following variables in the environment inherited by Cursor. Never commit their values.

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
```

`SILMARIL_TIMEOUT_MS` accepts `250` through `10000`. Missing configuration, malformed hook input, invalid classifier responses, SDK failures, network errors, and timeouts fail open. `SILMARIL_DEBUG=true` writes metadata-only diagnostics to stderr; raw classified content is never logged.

Set `SILMARIL_LOCAL_EVENT_DIR` only when the default private evidence spool must be overridden.

## Coverage

| Cursor hook | Firewall label | Shadow behavior | Block-mode capability |
| --- | --- | --- | --- |
| `beforeSubmitPrompt` | `user_input` | Observe | Prevent prompt submission |
| `preToolUse` | `tool_call` | Observe | Deny tool execution |
| `beforeReadFile` | `tool_response` | Observe | Deny content before model consumption |
| `postToolUse` | `tool_response` | Observe | Replace MCP results; other completed tools are observational |
| `postToolUseFailure` | `tool_response` | Observe | None |
| `afterAgentResponse` | `llm_output` | Observe | Cache a bounded decision for `stop` |
| `stop` | `llm_output` | Consume cached decision | Submit one safe follow-up |
| `afterAgentThought` | `llm_output` | Observe | None |
| `subagentStart` | `user_input` | Observe | Deny spawn |
| `subagentStop` | segment-native labels | Observe bounded transcript | Submit one safe follow-up |

The generic `preToolUse` hook covers Shell, Read, Write, Delete, Task, and MCP tools. The separate `beforeReadFile` hook is retained because it exposes file contents before they reach the model.

Subagent transcript capture is bounded to a 2 MiB host transcript and the latest 256 visible segments. Malformed, missing, oversized, or unknown transcript records fail open. Reasoning is classified only when Cursor explicitly exposes a completed reasoning block; it is never written to logs, evidence, or the output-decision cache.

Cursor Tab/inline-completion hooks are not included in v0.1.0. Local plugin installation does not establish a supported cloud-agent distribution path, so cloud coverage is not claimed.

## Enforcement semantics

Shadow mode returns no hook output. Block mode is enabled only with `SILMARIL_BLOCK_MALICIOUS=true`. A result blocks only when `prediction === "MALICIOUS"`; casing variants and unknown values never block.

Post-execution hooks cannot undo tool side effects. Cursor can replace a post-tool result only for MCP tools. Assistant-output blocking uses a private, ten-minute, single-use metadata cache keyed by hashed conversation and generation identifiers. The cache contains no assistant text.

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
```

The committed `dist/cursor-hook.js` is rebuilt from TypeScript and bundles the pinned `@silmaril-security/sdk@0.5.0`, so users do not need to install dependencies after cloning a release.

## Security and license

Report vulnerabilities through GitHub private vulnerability reporting. See [SECURITY.md](SECURITY.md). The plugin is licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## References

- [Silmaril documentation](https://www.silmaril.dev/docs)
- [Cursor plugins](https://cursor.com/docs/plugins)
- [Cursor hooks](https://cursor.com/docs/hooks)
