import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  flushMacDeviceNameRefreshForTests,
  refreshMacDeviceNameForTests,
  runCursorHook,
  runMacDeviceNameRefreshForTests,
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

function lockFile(home, now) {
  const epoch = Math.floor(now / 5_000);
  return path.join(home, "Library", "Application Support", "Silmaril", `cursor-device-name.lock.${epoch}`);
}

function generationFile(home, kind, epoch) {
  return path.join(home, "Library", "Application Support", "Silmaril", `cursor-device-name.${kind}.${epoch}`);
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
    assert.match(source, /child\.on\("error"/);
    assert.match(source, /\.unref\(\)/);
    assert.equal(source.includes("reclaimDeviceNameLock"), false);
    assert.match(source, /cursor-device-name\.lock\.\$\{epoch\}/);
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

  test("an asynchronous refresh spawn error does not abort classification", async () => {
    const home = await tempHome();
    const crashes = [];
    const onCrash = (error) => {
      crashes.push(error);
    };
    process.on("uncaughtException", onCrash);
    try {
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        homeDirectory: home,
        refreshProgram: path.join(home, "missing-refresh-bin"),
      });
      assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(crashes.length, 0);
      const output = await runCursorHook(
        hookInput(),
        { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
        captureDependencies([{ prediction: "MALICIOUS", score: 0.99, threshold: 0.5 }]),
      );
      assert.deepEqual(output, {
        continue: false,
        user_message: "Silmaril Firewall blocked potentially malicious content.",
      });
    } finally {
      process.off("uncaughtException", onCrash);
    }
  });

  test("a cache close failure still publishes a cached name and classifies", async () => {
    const home = await tempHome();
    const directory = path.dirname(cacheFile(home));
    await mkdir(directory, { recursive: true });
    await writeFile(cacheFile(home), JSON.stringify({
      v: 1,
      name: "Office Mac",
      expiresAt: Date.now() + 60_000,
    }));
    let closes = 0;
    let lookups = 0;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      closeFile: () => {
        closes += 1;
        throw new Error("close failed");
      },
      command: () => {
        lookups += 1;
        return "Replacement Mac\n";
      },
    });
    const calls = [];
    const output = await runCursorHook(
      hookInput(),
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      captureDependencies([{ prediction: "MALICIOUS", score: 0.99, threshold: 0.5 }], [], calls),
    );
    const provenance = calls.find((call) => call.options).options.metadata.silmaril.provenance;
    assert.ok(closes >= 1);
    assert.equal(lookups, 0);
    assert.equal(provenance.device_name, "Office Mac");
    assert.deepEqual(output, {
      continue: false,
      user_message: "Silmaril Firewall blocked potentially malicious content.",
    });

    const notHome = path.join(home, "home-file");
    await writeFile(notHome, "not a directory");
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: notHome,
      command: () => {
        throw new Error("should not run");
      },
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    const fallback = await runCursorHook(
      hookInput(),
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      captureDependencies([{ prediction: "MALICIOUS", score: 0.99, threshold: 0.5 }]),
    );
    assert.deepEqual(fallback, {
      continue: false,
      user_message: "Silmaril Firewall blocked potentially malicious content.",
    });
  });

  test("concurrent refresh keeps a newer success ahead of an older failure", async () => {
    const home = await tempHome();
    const now = { value: 100_000 };
    let calls = 0;
    let releaseStale;
    const stale = new Promise((resolve) => {
      releaseStale = resolve;
    });
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => {
        calls += 1;
        if (calls === 1) return stale.then(() => { throw new Error("stale failure"); });
        return "Office Mac\n";
      },
    });
    const older = refreshMacDeviceNameForTests();
    assert.equal(calls, 1);
    await refreshMacDeviceNameForTests();
    assert.equal(calls, 1);
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    assert.equal(calls, 1);

    now.value += 5_000;
    await refreshMacDeviceNameForTests();
    assert.equal(calls, 2);
    assert.equal(JSON.parse(await readFile(cacheFile(home), "utf8")).name, "Office Mac");
    releaseStale();
    await older;
    const stored = JSON.parse(await readFile(cacheFile(home), "utf8"));
    assert.equal(stored.name, "Office Mac");
    assert.equal(Object.hasOwn(stored, "retryAt"), false);
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Office Mac");

    const recoveredHome = await tempHome();
    const recoveredNow = { value: 200_000 };
    const recovered = [
      () => { throw new Error("first failure"); },
      () => "Recovered Mac\n",
    ];
    let recoveredIndex = 0;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: recoveredHome,
      now: () => recoveredNow.value,
      command: () => recovered[recoveredIndex++](),
    });
    await refreshMacDeviceNameForTests();
    recoveredNow.value += 5_000;
    await refreshMacDeviceNameForTests();
    assert.equal(JSON.parse(await readFile(cacheFile(recoveredHome), "utf8")).name, "Recovered Mac");
  });

  test("a later lock generation survives the claimant that saw the expired one", async () => {
    const home = await tempHome();
    const now = { value: 100_000 };
    let calls = 0;
    let releaseExpired;
    const expired = new Promise((resolve) => {
      releaseExpired = resolve;
    });
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => {
        calls += 1;
        if (calls === 1) return expired.then(() => { throw new Error("expired generation failed"); });
        return "Office Mac\n";
      },
    });
    const older = refreshMacDeviceNameForTests();
    assert.equal(calls, 1);
    const expiredLock = lockFile(home, now.value);
    const expiredLease = JSON.parse(await readFile(expiredLock, "utf8"));
    assert.equal(expiredLease.epoch, 20);
    await refreshMacDeviceNameForTests();
    assert.equal(calls, 1);
    assert.equal(JSON.parse(await readFile(expiredLock, "utf8")).owner, expiredLease.owner);

    now.value = 105_000;
    await refreshMacDeviceNameForTests();
    assert.equal(calls, 2);
    const liveLock = lockFile(home, now.value);
    const liveLease = JSON.parse(await readFile(liveLock, "utf8"));
    assert.equal(liveLease.epoch, 21);
    assert.notEqual(liveLease.owner, expiredLease.owner);
    await assert.rejects(lstat(expiredLock));
    assert.equal(JSON.parse(await readFile(cacheFile(home), "utf8")).name, "Office Mac");

    await refreshMacDeviceNameForTests();
    assert.equal(calls, 2);
    assert.deepEqual(JSON.parse(await readFile(liveLock, "utf8")), liveLease);

    releaseExpired();
    await older;
    assert.deepEqual(JSON.parse(await readFile(liveLock, "utf8")), liveLease);
    const stored = JSON.parse(await readFile(cacheFile(home), "utf8"));
    assert.equal(stored.name, "Office Mac");
    assert.equal(stored.epoch, 21);
    assert.equal(Object.hasOwn(stored, "retryAt"), false);
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Office Mac");
  });

  test("a refresh removes successful cache files older than five minutes", async () => {
    const home = await tempHome();
    const now = { value: 500_000 };
    const current = Math.floor(now.value / 5_000);
    const previous = current - 1;
    const future = current + 3;
    const stale = Math.floor((now.value - (5 * 60 * 1000) - 5_000) / 5_000);
    const directory = path.join(home, "Library", "Application Support", "Silmaril");
    await mkdir(directory, { recursive: true });
    const record = (epoch, name) => JSON.stringify({
      v: 1,
      epoch,
      name,
      expiresAt: now.value + 60_000,
    });
    await writeFile(generationFile(home, "cache", stale), record(stale, "Ancient Mac"));
    await writeFile(generationFile(home, "cache", 1), record(1, "Gap Mac"));
    await writeFile(generationFile(home, "lock", stale), JSON.stringify({ v: 1, owner: "a".repeat(32), epoch: stale }));
    await writeFile(generationFile(home, "lock", previous), JSON.stringify({ v: 1, owner: "b".repeat(32), epoch: previous }));
    await writeFile(generationFile(home, "cache", previous), record(previous, "Recent Mac"));
    await writeFile(generationFile(home, "cache", future), record(future, "Future Mac"));
    await writeFile(generationFile(home, "lock", future), JSON.stringify({ v: 1, owner: "c".repeat(32), epoch: future }));
    const outside = path.join(home, "outside-secret");
    await writeFile(outside, "keep");
    await symlink(outside, generationFile(home, "cache", 2));
    const decoy = generationFile(home, "cache", 4);
    await mkdir(decoy);
    await writeFile(path.join(decoy, "nested"), "inside");

    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => "Office Mac\n",
    });
    await refreshMacDeviceNameForTests();

    await assert.rejects(lstat(generationFile(home, "cache", stale)));
    await assert.rejects(lstat(generationFile(home, "cache", 1)));
    await assert.rejects(lstat(generationFile(home, "cache", 2)));
    await assert.rejects(lstat(generationFile(home, "lock", stale)));
    await assert.rejects(lstat(generationFile(home, "lock", previous)));
    assert.equal(await readFile(outside, "utf8"), "keep");
    assert.equal(await readFile(path.join(decoy, "nested"), "utf8"), "inside");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", previous), "utf8")).name, "Recent Mac");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", future), "utf8")).name, "Future Mac");
    assert.equal((await lstat(generationFile(home, "lock", future))).isSymbolicLink(), false);
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", current), "utf8")).name, "Office Mac");
    assert.equal((await lstat(lockFile(home, now.value))).isFile(), true);
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Office Mac");
  });

  test("cold classification returns before stale generation cleanup", async () => {
    const home = await tempHome();
    const now = { value: 500_000 };
    const current = Math.floor(now.value / 5_000);
    const previous = current - 1;
    const future = current + 3;
    const stale = Math.floor((now.value - (5 * 60 * 1000) - 5_000) / 5_000);
    const directory = path.join(home, "Library", "Application Support", "Silmaril");
    await mkdir(directory, { recursive: true });
    const record = (epoch, name) => JSON.stringify({
      v: 1,
      epoch,
      name,
      expiresAt: now.value + 60_000,
    });
    await writeFile(generationFile(home, "cache", stale), record(stale, "Ancient Mac"));
    await writeFile(generationFile(home, "cache", previous), JSON.stringify({
      v: 1,
      epoch: previous,
      name: "Recent Mac",
      expiresAt: now.value - 1,
    }));
    await writeFile(generationFile(home, "cache", future), record(future, "Future Mac"));
    await writeFile(generationFile(home, "lock", future), JSON.stringify({
      v: 1,
      owner: "c".repeat(32),
      epoch: future,
    }));
    let scheduled = null;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      schedule: (owner, epoch) => {
        scheduled = { owner, epoch };
      },
    });
    const calls = [];
    const output = await runCursorHook(
      hookInput(),
      BASE_ENV,
      captureDependencies([{ prediction: "BENIGN" }], [], calls),
    );
    assert.equal(calls.some((call) => call.options), true);
    assert.equal(output, undefined);
    assert.equal(scheduled?.epoch, current);
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", stale), "utf8")).name, "Ancient Mac");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", previous), "utf8")).name, "Recent Mac");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", future), "utf8")).name, "Future Mac");

    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => "Office Mac\n",
    });
    await runMacDeviceNameRefreshForTests(scheduled.owner, scheduled.epoch);

    await assert.rejects(lstat(generationFile(home, "cache", stale)));
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", previous), "utf8")).name, "Recent Mac");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", future), "utf8")).name, "Future Mac");
    assert.equal((await lstat(generationFile(home, "lock", future))).isFile(), true);
    assert.equal((await lstat(lockFile(home, now.value))).isFile(), true);
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", current), "utf8")).name, "Office Mac");
  });

  test("a late refresh worker cleans stale generations without publishing", async () => {
    const home = await tempHome();
    const now = { value: 100_000 };
    const claimed = Math.floor(now.value / 5_000);
    const previous = claimed - 1;
    const stale = claimed - 3;
    const newer = claimed + 2;
    const directory = path.join(home, "Library", "Application Support", "Silmaril");
    await mkdir(directory, { recursive: true });
    const record = (epoch, name) => JSON.stringify({
      v: 1,
      epoch,
      name,
      expiresAt: now.value + 60_000,
    });
    await writeFile(generationFile(home, "cache", stale), record(stale, "Ancient Mac"));
    await writeFile(generationFile(home, "cache", previous), JSON.stringify({
      v: 1,
      epoch: previous,
      name: "Recent Mac",
      expiresAt: now.value - 1,
    }));
    await writeFile(generationFile(home, "cache", newer), record(newer, "Future Mac"));
    await writeFile(generationFile(home, "lock", newer), JSON.stringify({
      v: 1,
      owner: "d".repeat(32),
      epoch: newer,
    }));
    let scheduled = null;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      schedule: (owner, epoch) => {
        scheduled = { owner, epoch };
      },
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, undefined);
    assert.equal(scheduled?.epoch, claimed);
    now.value += 5_000;
    let calls = 0;
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      homeDirectory: home,
      now: () => now.value,
      command: () => {
        calls += 1;
        return "Should Not Publish\n";
      },
    });
    await runMacDeviceNameRefreshForTests(scheduled.owner, scheduled.epoch);
    assert.equal(calls, 0);
    await assert.rejects(lstat(generationFile(home, "cache", stale)));
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", previous), "utf8")).name, "Recent Mac");
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", newer), "utf8")).name, "Future Mac");
    assert.equal((await lstat(generationFile(home, "lock", newer))).isFile(), true);
    assert.equal((await lstat(lockFile(home, 100_000))).isFile(), true);
    const shared = JSON.parse(await readFile(cacheFile(home), "utf8"));
    assert.equal(Object.hasOwn(shared, "name"), false);
    assert.equal(JSON.parse(await readFile(generationFile(home, "cache", claimed), "utf8")).name, undefined);
  });
});

test.after(async () => {
  await Promise.all(homes.map((home) => rm(home, { recursive: true, force: true })));
});
