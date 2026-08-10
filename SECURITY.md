# Security Policy

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub's **Report a vulnerability** flow for this repository so maintainers can investigate privately.

Include the affected version, host version, lifecycle event, expected behavior, observed behavior, and a minimal reproduction. Remove API keys, endpoints, prompts, tool payloads, transcripts, and customer data before submitting.

## Supported versions

The latest tagged release is supported. Security fixes may require upgrading Cursor or the Silmaril SDK.

## Runtime posture

The plugin defaults to shadow mode and fails open when configuration, parsing, networking, the SDK, evidence, or the output-decision cache fails. Enable blocking only after validating the configured endpoint and local policy expectations.
