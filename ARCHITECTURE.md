# Architecture

## Runtime path

Cursor starts `dist/cursor-hook.js` as a fresh command process and sends one JSON hook event over stdin. The hook validates configuration, maps the event to a Firewall label, invokes the pinned SDK with a stable logical request ID, emits privacy-safe local evidence, and writes at most one host-native JSON response to stdout.

All configuration, input parsing, SDK construction, classification, local evidence, transcript parsing, and decision-cache failures are fail-open. Debug output uses stderr and contains metadata only.

## Enforcement boundaries

Prompt submission, pre-tool use, file reads, and subagent starts support direct denial. MCP results support post-tool replacement. General post-tool hooks are observational because completed side effects cannot be reversed.

Cursor exposes assistant output before `stop` but does not accept a response replacement at that hook. When block mode sees an exact-malicious output, the plugin writes only bounded classification metadata to a private single-use cache. `stop` consumes the decision and, on the first completed stop loop, returns a safe follow-up. Cache write/read failures fail open.

Subagent completion reads at most 2 MiB and classifies at most the latest 256 host-visible transcript segments. It never interprets encrypted or unavailable reasoning.

## Trust boundaries

Raw lifecycle content is sent only to the configured Silmaril Firewall endpoint through the SDK. It is not written locally. Local evidence carries only hashes, bounded taxonomy values, numeric scores, native actions, and version provenance. API keys and endpoints remain process configuration and are excluded from logs and evidence.

## Rollback

Set `SILMARIL_BLOCK_MALICIOUS=false` for immediate observational behavior. Remove the symlink from `~/.cursor/plugins/local/silmaril-firewall` and reload Cursor to disable the plugin completely.
