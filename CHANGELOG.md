# Changelog

## 0.2.5

- Include the macOS Computer Name in captured endpoint provenance when available.

## 0.2.4

- Restore Cursor-native malicious MCP tool-result replacement in Block mode.

## 0.2.3

- Stop replaying child transcripts at `subagentStop`; classify only the current summary and rely on the Firewall sequence cache for conversation state.

## 0.2.2

- Add normalized agent, hook, MCP, tool, file, and subagent governance context.
- Preserve Shadow and Warn pass-through behavior while allowing governance
  blocks to use Cursor's existing native Block-mode boundaries.
- Bundle TypeScript SDK 0.6.2 and publish the governance-capable plugin version.

## 0.2.1

- Preserve the backend-selected effective mode by bundling TypeScript SDK 0.6.0.

## 0.2.0

- Add backend-controlled Shadow, Warn, and Block modes with explicit-mode precedence.
- Surface bounded Warn context only where Cursor supports it and record unsupported Block boundaries without replacing content.

## 0.1.4

- Classify each visible Cursor transcript segment individually while preserving bounded concurrency and fail-open behavior.

## 0.1.3

- Add app-managed endpoint and harness provenance to every Firewall request.

## 0.1.2

- Make the private app-managed configuration authoritative over stale ambient shell variables.
- Preserve `SILMARIL_DEBUG` as an explicit metadata-only diagnostic override.

## 0.1.1

- Add authoritative private host-local JSON configuration with environment fallback when the file is missing.
- Replace the rejected out-of-tree symlink workflow with an atomic lean local installer.
- Reject insecure, linked, oversized, or foreign-owned configuration files.

## 0.1.0

- Initial public Cursor lifecycle plugin.
- Prompt, tool, file-read, output, reasoning, and subagent classification.
- Optional exact-malicious enforcement with fail-open defaults.
- Privacy-safe local evidence and bounded output decision cache.
- Hosted demo skill and release-ready bundled JavaScript.
