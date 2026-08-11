import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, symlink } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

async function withMockFirewall(run) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push(JSON.parse(body));
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ prediction: "MALICIOUS", score: 0.9, threshold: 0.5, primary_outcome: "code_execution" }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await run(`http://127.0.0.1:${address.port}`, requests);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

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
  await withMockFirewall(async (apiUrl, requests) => {
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
    assert.equal(requests.length, 2);
    assert.ok(requests.every((payload) => payload.hook === "user_input"));
    assert.ok(requests.every((payload) => payload.text === "classify through the bundled hook"));
  });
});
