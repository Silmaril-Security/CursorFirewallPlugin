# Changelog

## 0.4.0

- Bundle SDK 1.0.0, which calls `/v2/classify` and falls back to `/classify` on deployments that predate it. Configuration is unchanged.
- Treat every classify decision whose `action` is not `allow` as a block candidate, replacing the `MALICIOUS` prediction and governance action checks.
- Record the Firewall's `confidence` and `severity` labels in local evidence when a block carries them, and stop recording `modelScore` and `modelThreshold`.
- Record the SDK result's `modelId` as provenance `modelVersion`, and the governance decision's `policyVersion` as provenance `policyVersion` in place of the plugin's fixed value when a decision carries one. Both have control and format characters removed and are limited to 128 UTF-8 bytes, the limits Silmaril for macOS enforces on ingestion.
- Store decision fields in the output decision cache under cache version 2 and discard version 1 entries.
- Map the SDK's harmful outcomes (`control_abuse`, `prompt_injection`, `information_disclosure`, `system_compromise`, `service_disruption`) to their local evidence consequence categories instead of `other`.

## 0.3.6

- Bundle SDK 0.11.0, which names the tenant acceptable-use policy outcome `abuse` and validates verdict scores and thresholds strictly.

## 0.3.5

- Anchor every native hook command to `CURSOR_PLUGIN_ROOT` while retaining absolute commands in local installations.
- Treat Cursor Cloud HTTP MCP redacted results as unavailable observations without classifying or claiming replacement.
- Bundle SDK 0.8.2 and send canonical governed resources alongside compatibility attribution metadata.

## 0.3.4

- Bundle SDK 0.7.2 so caller cancellation immediately clears attempt timers, including stalled response cleanup after retries.

## 0.3.3

- Bound classification, retries, response reads, and SDK cleanup to one deadline capped at 8 seconds.
- Bundle SDK 0.7.1 with cancellation and add shipped-bundle deadline regressions.

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
