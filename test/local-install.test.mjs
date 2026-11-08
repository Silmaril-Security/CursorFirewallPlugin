import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installLocalPlugin } from "../scripts/install-local.mjs";

const sourceRoot = fileURLToPath(new URL("..", import.meta.url));

function runPackagedCommand(command, input, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, {
      ...options,
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`packaged hook exited ${code}: ${stderr}`));
    });
    child.stdin.end(JSON.stringify(input));
  });
}

test("local installer creates a lean non-symlinked Cursor plugin", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-install-"));
  const destination = await installLocalPlugin({ sourceRoot, localPluginsRoot: root });

  assert.equal((await lstat(destination)).isDirectory(), true);
  assert.equal((await lstat(destination)).isSymbolicLink(), false);
  assert.equal((await stat(path.join(destination, "dist", "cursor-hook.js"))).isFile(), true);
  assert.equal((await stat(path.join(destination, ".cursor-plugin", "plugin.json"))).isFile(), true);
  await assert.rejects(stat(path.join(destination, "node_modules")), { code: "ENOENT" });
  await assert.rejects(stat(path.join(destination, "src")), { code: "ENOENT" });
  await assert.rejects(stat(path.join(destination, "test")), { code: "ENOENT" });
});

test("local installer replaces an out-of-tree symlink without touching its source", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-symlink-install-"));
  const linkedSource = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-linked-source-"));
  const sentinel = path.join(linkedSource, "sentinel.txt");
  await writeFile(sentinel, "preserved", "utf8");
  const destination = path.join(root, "silmaril-firewall");
  await symlink(linkedSource, destination, "dir");

  await installLocalPlugin({ sourceRoot, localPluginsRoot: root });

  assert.equal((await lstat(destination)).isDirectory(), true);
  assert.equal((await lstat(destination)).isSymbolicLink(), false);
  assert.equal(await readFile(sentinel, "utf8"), "preserved");
});

test("installed stop hooks execute from an unrelated workspace with spaces in the plugin path", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril cursor plugins "));
  const workspace = await mkdtemp(path.join(os.tmpdir(), "unrelated cursor workspace "));
  const destination = await installLocalPlugin({ sourceRoot, localPluginsRoot: root });
  const hooks = JSON.parse(await readFile(path.join(destination, "hooks", "hooks.json"), "utf8")).hooks;
  const expectedHookPath = path.join(destination, "dist", "cursor-hook.js");
  for (const entries of Object.values(hooks)) {
    assert.ok(entries.every(({ command }) => command.includes(expectedHookPath)));
    assert.ok(entries.every(({ command }) => !command.includes("CURSOR_PLUGIN_ROOT")));
  }

  const requests = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push(JSON.parse(body));
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ prediction: "BENIGN", score: 0.01, threshold: 0.5 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const env = {
      ...process.env,
      HOME: workspace,
      SILMARIL_CONFIG_PATH: path.join(workspace, "missing-config.json"),
      SILMARIL_API_KEY: "test-key",
      SILMARIL_API_URL: `http://127.0.0.1:${address.port}`,
      SILMARIL_TIMEOUT_MS: "2500",
      SILMARIL_MODE: "shadow",
      SILMARIL_LOCAL_EVENT_DIR: path.join(workspace, "evidence"),
    };
    const common = {
      conversation_id: "installed-conversation",
      generation_id: "installed-generation",
      workspace_roots: [workspace],
      cursor_version: "test",
    };
    const stopped = await runPackagedCommand(
      hooks.stop[0].command,
      { ...common, hook_event_name: "stop", status: "completed" },
      { cwd: workspace, env },
    );
    assert.equal(stopped.stdout, "");

    const subagentStopped = await runPackagedCommand(
      hooks.subagentStop[0].command,
      { ...common, hook_event_name: "subagentStop", summary: "installed summary" },
      { cwd: workspace, env },
    );
    assert.equal(subagentStopped.stdout, "");
    assert.equal(requests.length, 1);
    assert.equal(requests[0].text, "installed summary");
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
