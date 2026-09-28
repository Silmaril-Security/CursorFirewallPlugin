import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  flushMacDeviceNameRefreshForTests,
  runCursorHook,
  setMacDeviceNameLookupForTests,
  withProvenance,
} from "../dist/cursor-hook.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distModule = pathToFileURL(path.join(repoRoot, "dist", "cursor-hook.js")).href;
const ENDPOINT_ID = "2b64e603-f82a-4aec-9524-9736472dc80a";
const BASE_ENV = {
  SILMARIL_CONFIG_PATH: path.join(os.tmpdir(), `silmaril-cursor-device-name-${process.pid}-missing.json`),
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "true",
};
const homes = [];

function hookInput(extra = {}) {
  return {
    hook_event_name: "beforeSubmitPrompt",
    conversation_id: "conversation-1",
    generation_id: "generation-1",
    cursor_version: "9.9.9",
    workspace_roots: ["/private/project"],
    prompt: "hello",
    ...extra,
  };
}

function captureDependencies(results, events = [], calls = []) {
  return {
    firewallConstructor: class {
      constructor(options) {
        calls.push({ constructor: options });
      }
      async classify(text, options) {
        calls.push({ text, options });
        const next = results.shift();
        if (next instanceof Error) throw next;
        return next ?? { prediction: "BENIGN", score: 0.01, threshold: 0.5 };
      }
    },
    evidenceEmitter: async (event) => {
      events.push(event);
    },
  };
}

function cacheFile(home) {
  return path.join(home, "Library", "Application Support", "Silmaril", "cursor-device-name.json");
}

async function tempHome() {
  const home = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-device-name-"));
  homes.push(home);
  return home;
}

function runDeviceNameProcess(home, phase) {
  const script = `
    import { flushMacDeviceNameRefreshForTests, setMacDeviceNameLookupForTests, withProvenance } from ${JSON.stringify(distModule)};
    if (process.env.PHASE === "write") {
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        homeDirectory: process.env.HOME,
        command: () => "Office Mac\\n",
      });
      const cold = withProvenance({});
      await flushMacDeviceNameRefreshForTests();
      const warm = withProvenance({});
      process.stdout.write(JSON.stringify({
        cold: cold.silmaril.provenance.device_name ?? null,
        warm: warm.silmaril.provenance.device_name ?? null,
      }));
    } else {
      let calls = 0;
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        homeDirectory: process.env.HOME,
        command: () => {
          calls += 1;
          throw new Error("should-not-run");
        },
      });
      const read = withProvenance({
        silmaril: { provenance: { device_name: "spoofed", endpoint_id: "spoofed", harness: "spoofed" } },
      });
      process.stdout.write(JSON.stringify({
        device_name: read.silmaril.provenance.device_name ?? null,
        harness: read.silmaril.provenance.harness,
        endpoint: Object.hasOwn(read.silmaril.provenance, "endpoint_id"),
        calls,
      }));
    }
  `;
  return spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
    env: { ...process.env, HOME: home, PHASE: phase },
    encoding: "utf8",
    timeout: 10_000,
  });
}

describe("macOS computer name provenance", { concurrency: 1 }, () => {
  afterEach(() => {
    setMacDeviceNameLookupForTests({ platform: "linux" });
  });

  test("classification does not wait for a computer-name lookup", async () => {
    const home = await tempHome();
    let settled = false;
    let resolveLookup;
    const pending = new Promise((resolve) => {
      resolveLookup = (value) => {
        settled = true;
        resolve(value);
      };
    });
    const events = [];
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      command: () => pending,
    });
    const classifyCalls = [];
    await runCursorHook(
      hookInput(),
      BASE_ENV,
      captureDependencies([{ prediction: "BENIGN" }], events, classifyCalls),
    );
    const provenance = classifyCalls.find((call) => call.options).options.metadata.silmaril.provenance;
    assert.equal(settled, false);
    assert.equal(provenance.device_name, undefined);
    assert.equal(provenance.harness, "cursor");
    assert.equal(Object.hasOwn(provenance, "endpoint_id"), false);
    assert.equal(JSON.stringify(events).includes("Office Mac"), false);
    resolveLookup("  Office Mac \n");
    await flushMacDeviceNameRefreshForTests();
    const warm = withProvenance({}, ENDPOINT_ID);
    assert.equal(warm.silmaril.provenance.device_name, "Office Mac");
    assert.equal(warm.silmaril.provenance.endpoint_id, ENDPOINT_ID);
    const stored = JSON.parse(await readFile(cacheFile(home), "utf8"));
    assert.equal(stored.name, "Office Mac");
    assert.equal(Object.hasOwn(stored, "retryAt"), false);
  });

  test("a later process reuses the per-user cache without another lookup", async () => {
    const home = await tempHome();
    const writer = runDeviceNameProcess(home, "write");
    assert.equal(writer.status, 0, writer.stderr);
    assert.deepEqual(JSON.parse(writer.stdout), { cold: null, warm: "Office Mac" });
    const fileStat = await lstat(cacheFile(home));
    const directoryStat = await lstat(path.dirname(cacheFile(home)));
    assert.equal(fileStat.isSymbolicLink(), false);
    assert.equal(fileStat.mode & 0o777, 0o600);
    assert.equal(directoryStat.mode & 0o777, 0o700);
    const reader = runDeviceNameProcess(home, "read");
    assert.equal(reader.status, 0, reader.stderr);
    assert.deepEqual(JSON.parse(reader.stdout), {
      device_name: "Office Mac",
      harness: "cursor",
      endpoint: false,
      calls: 0,
    });
  });

  test("default refresh is scheduled without invoking the lookup in-process", async () => {
    const home = await tempHome();
    const now = { value: 30_000 };
    let scheduled = 0;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      schedule: () => {
        scheduled += 1;
      },
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    assert.equal(scheduled, 1);
    const stored = JSON.parse(await readFile(cacheFile(home), "utf8"));
    assert.equal(Object.hasOwn(stored, "name"), false);
    assert.equal(stored.retryAt, 35_000);
    now.value += 5_000 - 1;
    withProvenance({});
    assert.equal(scheduled, 1);
    now.value += 1;
    withProvenance({});
    assert.equal(scheduled, 2);
  });

  test("a renamed computer is omitted at expiry and published by the following refresh", async () => {
    const home = await tempHome();
    const names = ["Old Office Mac\n"];
    const now = { value: 40_000 };
    let calls = 0;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => {
        calls += 1;
        return names[0];
      },
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    await flushMacDeviceNameRefreshForTests();
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Old Office Mac");
    now.value += 5 * 60 * 1000;
    names[0] = "New Office Mac\n";
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    assert.equal(calls, 2);
    await flushMacDeviceNameRefreshForTests();
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "New Office Mac");
  });

  test("invalid names, C1 controls, symlinks, and oversized files are not used", async () => {
    const rejected = [
      "Mac\u0080Book",
      "Mac\u0085Book",
      "Mac\u009FBook",
      "bad\u0000name",
      "bad\u007Fname",
    ];
    for (const output of rejected) {
      const home = await tempHome();
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        homeDirectory: home,
        command: () => output,
      });
      assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined, output);
      await flushMacDeviceNameRefreshForTests();
      assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined, output);
    }
    const acceptedHome = await tempHome();
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: acceptedHome,
      command: () => "Café Mac\n",
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    await flushMacDeviceNameRefreshForTests();
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Café Mac");

    const symlinkHome = await tempHome();
    const directory = path.join(symlinkHome, "Library", "Application Support", "Silmaril");
    await mkdir(directory, { recursive: true });
    const target = path.join(symlinkHome, "planted.json");
    await writeFile(target, JSON.stringify({
      v: 1,
      name: "Spoofed Mac",
      expiresAt: Date.now() + 60_000,
    }));
    await symlink(target, path.join(directory, "cursor-device-name.json"));
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: symlinkHome,
      command: () => "Real Mac\n",
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    await flushMacDeviceNameRefreshForTests();
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Real Mac");
    assert.equal((await lstat(cacheFile(symlinkHome))).isSymbolicLink(), false);

    const hugeHome = await tempHome();
    await mkdir(path.dirname(cacheFile(hugeHome)), { recursive: true });
    await writeFile(cacheFile(hugeHome), `${JSON.stringify({ v: 1, name: "Huge Mac", expiresAt: Date.now() + 60_000 })}${" ".repeat(5000)}`);
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: hugeHome,
      command: () => "Bounded Mac\n",
    });
    assert.notEqual(withProvenance({}).silmaril.provenance.device_name, "Huge Mac");
    await flushMacDeviceNameRefreshForTests();
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Bounded Mac");
  });

  test("non-darwin platforms do not read or schedule a mac computer name", async () => {
    const source = await readFile(path.join(repoRoot, "src", "cursor-hook.ts"), "utf8");
    assert.equal(source.includes("hostname"), false);
    assert.equal(source.includes("LocalHostName"), false);
    assert.equal(source.includes("execFileSync"), false);
    assert.match(source, /detached:\s*true/);
    assert.match(source, /\.unref\(\)/);
    const home = await tempHome();
    let calls = 0;
    setMacDeviceNameLookupForTests({
      platform: "linux",
      homeDirectory: home,
      command: () => {
        calls += 1;
        return "Office Mac";
      },
    });
    const provenance = withProvenance({
      silmaril: { provenance: { device_name: "spoofed" } },
    }).silmaril.provenance;
    assert.equal(calls, 0);
    assert.equal(Object.hasOwn(provenance, "device_name"), false);
    assert.equal(provenance.harness, "cursor");
  });
});

test.after(async () => {
  await Promise.all(homes.map((home) => rm(home, { recursive: true, force: true })));
});
