import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installLocalPlugin } from "../scripts/install-local.mjs";

const sourceRoot = fileURLToPath(new URL("..", import.meta.url));

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
