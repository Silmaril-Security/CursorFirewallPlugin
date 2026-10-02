# Security Policy

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub's **Report a vulnerability** flow for this repository so maintainers can investigate privately.

Include the affected version, host version, lifecycle event, expected behavior, observed behavior, and a minimal reproduction. Remove API keys, endpoints, prompts, tool payloads, transcripts, and customer data before submitting.

## Supported versions

The latest tagged release is supported. Security fixes may require upgrading Cursor or the Silmaril SDK.

## Runtime posture

When `mode` is omitted, the backend selects the effective mode. If the backend omits mode, the plugin falls back to shadow. The bundled SDK rejects an unrecognized mode, and the hook then fails open. It also fails open when configuration, parsing, networking, the SDK, or evidence fails. Enable blocking only after validating the configured endpoint and local policy expectations.
