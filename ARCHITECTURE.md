# Architecture

## Runtime path

Cursor starts `dist/cursor-hook.js` as a fresh command process and sends one JSON hook event over stdin. The hook validates configuration, maps the event to a Firewall label, invokes the pinned SDK with a stable logical request ID, emits privacy-safe local evidence, and writes at most one host-native JSON response to stdout.

All configuration, input parsing, SDK construction, classification, local evidence, and transcript parsing failures are fail-open. Debug output uses stderr and contains metadata only.

## Enforcement boundaries

Prompt submission, pre-tool use, file reads, and subagent starts support direct denial. Post-tool hooks are observational because completed side effects cannot be reversed.

Cursor exposes assistant output after generation but does not provide a genuine native cancel primitive at that boundary. Block therefore preserves completed assistant and subagent output and records `block_unavailable`.

Subagent completion reads at most 2 MiB and classifies at most the latest 256 host-visible transcript segments. It never interprets encrypted or unavailable reasoning.

## Trust boundaries

Raw lifecycle content is sent only to the configured Silmaril Firewall endpoint through the SDK. It is not written locally. Local evidence carries only hashes, bounded taxonomy values, numeric scores, native actions, and version provenance. API keys and endpoints come from the private user-owned configuration file when it exists, with environment variables retained only as a fallback when the file is missing. They are excluded from logs and evidence. The runtime rejects symbolic links, oversized files, non-regular files, files owned by another user, invalid recognized fields, and files with group or world permissions.

Local installation uses an atomic, non-symlinked copy under `~/.cursor/plugins/local`. Only package allowlisted files are copied, so Cursor never scans the development checkout or `node_modules` and the source checkout remains independent from the active installation.

## Rollback

Set `mode` to `shadow` for immediate observational behavior, omit it to restore backend control, or set `enabled` to `false` to disable classification without removing the plugin. Remove the plugin from `~/.cursor/plugins/local/silmaril-firewall` and reload Cursor to disable it completely.
