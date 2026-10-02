# Architecture

## Runtime path

Cursor starts `dist/cursor-hook.js` as a fresh command process and sends one JSON hook event over stdin. The hook validates configuration, maps the event to a Firewall label, invokes the pinned SDK with a stable logical request ID, emits privacy-safe local evidence, and writes at most one host-native JSON response to stdout.

All configuration, input parsing, SDK construction, classification, and local evidence failures are fail-open. Debug output uses stderr and contains metadata only.

## Enforcement boundaries

Prompt submission, pre-tool use, file reads, and subagent starts support direct denial. Malicious MCP `postToolUse` results are replaced through `updated_mcp_tool_output` before model reuse; that replacement does not undo the tool's completed side effect. Generic post-tool results, tool failures, assistant output, reasoning, and completed subagent summaries stay observational. The `stop` hook does not classify.

Block applies only when the effective mode is `block` and the result is the exact prediction `MALICIOUS` or a governance action `block`. Shadow and Warn return no hook output. Where the hook cannot deny or replace, completed output is preserved and evidence records `block_unavailable`. Malicious Warn records `warnDelivery` as `unsupported`.

Each native Cursor event produces at most one classification of the current event. Subagent completion classifies only the current summary and never reads host transcripts. The plugin does not accumulate conversation state locally; that continuity is left to the Firewall sequence cache.

## Trust boundaries

Raw lifecycle content is sent only to the configured Silmaril Firewall endpoint through the SDK. It is not written locally. Classifier metadata `silmaril.provenance` always includes schema version 1 and harness `cursor`. It includes `endpoint_id` only for a canonical UUID v4, and `device_name` only when a previously validated macOS Computer Name is available. A private cache under `~/Library/Application Support/Silmaril` may store that name; it is not part of the evidence spool. Local evidence carries only hashes, bounded taxonomy values, numeric scores, native actions, and version provenance. API keys and endpoints come from the private user-owned configuration file when it exists, with environment variables retained only as a fallback when the file is missing. They are excluded from logs and evidence. The runtime rejects symbolic links, oversized files, non-regular files, files owned by another user, invalid recognized fields, and files with group or world permissions.

Local installation uses an atomic, non-symlinked copy under `~/.cursor/plugins/local`. Only package allowlisted files are copied, so Cursor never scans the development checkout or `node_modules` and the source checkout remains independent from the active installation.

## Rollback

Set `mode` to `shadow` for immediate observational behavior, omit it to restore backend control, or set `enabled` to `false` to disable classification without removing the plugin. Remove the plugin from `~/.cursor/plugins/local/silmaril-firewall` and reload Cursor to disable it completely.
