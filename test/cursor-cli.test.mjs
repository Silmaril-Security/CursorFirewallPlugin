import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { classifyDecision } from "../scripts/classify-responses.mjs";
import { withMockClassifier } from "./mock-classifier.mjs";

function runHook(input, env, hookPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [hookPath], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(new Error(`hook exited with code ${code}: ${stderr}`));
    });
    child.stdin.end(input);
  });
}

test("bundled command hook speaks Cursor JSON over stdio", async () => {
  await withMockClassifier(async (apiUrl, requests) => {
    const evidenceDirectory = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-cli-"));
    const pluginLink = path.join(evidenceDirectory, "plugin-link");
    await symlink(fileURLToPath(new URL("..", import.meta.url)), pluginLink, "dir");
    const hookPath = path.join(pluginLink, "dist", "cursor-hook.js");
    const input = JSON.stringify({
      hook_event_name: "beforeSubmitPrompt",
      conversation_id: "conversation-cli",
      generation_id: "generation-cli",
      prompt: "classify through the bundled hook",
      workspace_roots: [],
      cursor_version: "test",
    });
    const commonEnv = {
      ...process.env,
      SILMARIL_CONFIG_PATH: path.join(evidenceDirectory, "missing-config.json"),
      SILMARIL_API_KEY: "test-key",
      SILMARIL_API_URL: apiUrl,
      SILMARIL_TIMEOUT_MS: "2500",
      SILMARIL_DEBUG: "false",
      SILMARIL_LOCAL_EVENT_DIR: evidenceDirectory,
    };

    const blocked = await runHook(input, { ...commonEnv, SILMARIL_BLOCK_MALICIOUS: "true" }, hookPath);
    assert.deepEqual(JSON.parse(blocked.stdout), {
      continue: false,
      user_message: "Silmaril Firewall blocked potentially malicious content.",
    });

    const shadow = await runHook(input, { ...commonEnv, SILMARIL_BLOCK_MALICIOUS: "false" }, hookPath);
    assert.equal(shadow.stdout, "");

    const mcpInput = JSON.stringify({
      hook_event_name: "preToolUse",
      conversation_id: "conversation-cli",
      generation_id: "generation-cli",
      tool_name: "mcp__github__fetch",
      tool_use_id: "tool-use-cli",
      tool_input: { url: "https://example.test" },
      workspace_roots: [],
      cursor_version: "test",
    });
    const deniedMcp = await runHook(
      mcpInput,
      { ...commonEnv, SILMARIL_BLOCK_MALICIOUS: "true" },
      hookPath,
    );
    assert.equal(JSON.parse(deniedMcp.stdout).permission, "deny");

    assert.deepEqual(requests.map(({ path: requestPath }) => requestPath), Array(3).fill("/v2/classify"));
    const payloads = requests.map(({ payload }) => payload);
    assert.ok(payloads.slice(0, 2).every((payload) => payload.hook === "user_input"));
    assert.ok(payloads.slice(0, 2).every((payload) => payload.text === "classify through the bundled hook"));
    assert.deepEqual(payloads[0].resource, { kind: "agent", id: "cursor" });
    assert.deepEqual(payloads[0].metadata.silmaril.governance, {
      agent: "cursor",
      resource: { kind: "agent", id: "cursor" },
    });
    assert.equal(payloads[0].metadata.silmaril.sdk_version, "1.0.0");
    assert.deepEqual(payloads[2].resource, {
      kind: "mcp_tool",
      id: "fetch",
      parent_id: "github",
    });
    assert.deepEqual(payloads[2].metadata.silmaril.governance, {
      agent: "cursor",
      resource: {
        kind: "mcp_tool",
        id: "fetch",
        parent_id: "github",
      },
    });
    assert.equal(payloads[2].metadata.conversationId, "conversation-cli");
    assert.equal(payloads[2].metadata.silmaril.request_id.startsWith("cursor-"), true);
  }, { decision: classifyDecision("block", { source: "model", outcome: "system_compromise" }) });
});
