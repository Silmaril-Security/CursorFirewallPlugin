import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  runCursorHook,
  setMacDeviceNameLookupForTests,
  withProvenance,
} from "../dist/cursor-hook.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENDPOINT_ID = "2b64e603-f82a-4aec-9524-9736472dc80a";
const BASE_ENV = {
  SILMARIL_CONFIG_PATH: path.join("/tmp", `silmaril-cursor-device-name-${process.pid}-missing.json`),
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "true",
};

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

describe("macOS computer name provenance", { concurrency: 1 }, () => {
  afterEach(() => {
    setMacDeviceNameLookupForTests({ platform: "linux" });
  });

  test("valid computer name is cached on classify metadata without an endpoint id", async () => {
    const calls = [];
    const now = { value: 1_000 };
    const events = [];
    const classifyCalls = [];
    const stderr = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
      stderr.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      return originalWrite(chunk, ...rest);
    };
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      now: () => now.value,
      command: (invocation) => {
        calls.push(invocation);
        return "  Office Mac \n";
      },
    });
    try {
      await runCursorHook(hookInput(), BASE_ENV, captureDependencies([{ prediction: "BENIGN" }], events, classifyCalls));
      const provenance = classifyCalls.find((call) => call.options).options.metadata.silmaril.provenance;
      assert.equal(provenance.device_name, "Office Mac");
      assert.equal(provenance.harness, "cursor");
      assert.equal(provenance.schema_version, 1);
      assert.equal(Object.hasOwn(provenance, "endpoint_id"), false);
      assert.deepEqual(calls, [{
        file: "/usr/sbin/scutil",
        args: ["--get", "ComputerName"],
        timeoutMs: 100,
        maxBuffer: 1024,
      }]);
      assert.equal(JSON.stringify(events).includes("Office Mac"), false);
      assert.equal(stderr.join("").includes("Office Mac"), false);

      const withEndpoint = withProvenance({
        trace: "keep",
        silmaril: { integration: "cursor-firewall-plugin", provenance: { device_name: "spoofed", harness: "spoofed" } },
      }, ENDPOINT_ID, { agent: "cursor", resource: { kind: "agent", id: "cursor" } });
      assert.deepEqual(withEndpoint, {
        trace: "keep",
        silmaril: {
          integration: "cursor-firewall-plugin",
          provenance: {
            schema_version: 1,
            endpoint_id: ENDPOINT_ID,
            harness: "cursor",
            device_name: "Office Mac",
          },
          governance: { agent: "cursor", resource: { kind: "agent", id: "cursor" } },
        },
      });
      assert.equal(calls.length, 1);
      now.value += 5 * 60 * 1000;
      assert.equal(withProvenance({}).silmaril.provenance.device_name, "Office Mac");
      assert.equal(calls.length, 2);
    } finally {
      process.stderr.write = originalWrite;
    }
  });

  test("invalid or missing computer names are omitted", () => {
    const rejected = [
      "",
      " \n\t",
      "a".repeat(257),
      "😀".repeat(129),
      "bad\u0000name",
      "bad\u001Fname",
      "bad\u007Fname",
      `${" ".repeat(1022)}Mac`,
    ];
    for (const output of rejected) {
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        command: () => output,
      });
      const provenance = withProvenance({}).silmaril.provenance;
      assert.equal(provenance.device_name, undefined);
      assert.equal(provenance.harness, "cursor");
    }
    for (const output of ["a".repeat(256), "😀".repeat(128)]) {
      setMacDeviceNameLookupForTests({
        platform: "darwin",
        command: () => output,
      });
      assert.equal(withProvenance({}).silmaril.provenance.device_name, output);
    }
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      command: () => `${" ".repeat(1021)}Mac`,
    });
    assert.equal(withProvenance({}).silmaril.provenance.device_name, "Mac");
  });

  test("spoofed device_name metadata cannot win", () => {
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      command: () => "Office Mac\n",
    });
    assert.equal(withProvenance({
      silmaril: { provenance: { device_name: "spoofed", endpoint_id: "spoofed", harness: "spoofed" } },
    }).silmaril.provenance.device_name, "Office Mac");

    setMacDeviceNameLookupForTests({
      platform: "darwin",
      command: () => {
        throw new Error("SECRET-COMPUTER");
      },
    });
    const failed = withProvenance({
      silmaril: { provenance: { device_name: "spoofed" } },
    }).silmaril.provenance;
    assert.equal(Object.hasOwn(failed, "device_name"), false);
    assert.equal(failed.harness, "cursor");
  });

  test("non-darwin platforms do not read a mac computer name", async () => {
    const source = await readFile(path.join(repoRoot, "src", "cursor-hook.ts"), "utf8");
    assert.equal(source.includes("hostname"), false);
    assert.equal(source.includes("LocalHostName"), false);
    assert.match(source, /execFileSync\(invocation\.file, \[\.\.\.invocation\.args\]/);
    assert.match(source, /\/usr\/sbin\/scutil/);
    assert.match(source, /"--get", "ComputerName"/);
    for (const platform of ["linux", "win32"]) {
      let calls = 0;
      setMacDeviceNameLookupForTests({
        platform,
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
    }
  });

  test("computer name lookup failure still classifies and does not log the name", async () => {
    let calls = 0;
    const classifyCalls = [];
    const events = [];
    const stderr = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
      stderr.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      return originalWrite(chunk, ...rest);
    };
    setMacDeviceNameLookupForTests({
      platform: "darwin",
      command: () => {
        calls += 1;
        throw new Error("SECRET-COMPUTER");
      },
    });
    try {
      await runCursorHook(
        hookInput(),
        BASE_ENV,
        captureDependencies([{ prediction: "BENIGN" }], events, classifyCalls),
      );
      await runCursorHook(
        hookInput({ prompt: "again" }),
        BASE_ENV,
        captureDependencies([{ prediction: "BENIGN" }], events, classifyCalls),
      );
    } finally {
      process.stderr.write = originalWrite;
    }
    const provenances = classifyCalls
      .filter((call) => call.options)
      .map((call) => call.options.metadata.silmaril.provenance);
    assert.equal(provenances.length, 2);
    assert.equal(provenances.every((provenance) => provenance.device_name === undefined), true);
    assert.equal(provenances.every((provenance) => provenance.harness === "cursor"), true);
    assert.equal(calls, 1);
    assert.equal(stderr.join("").includes("SECRET-COMPUTER"), false);
    assert.equal(JSON.stringify(events).includes("SECRET-COMPUTER"), false);
  });
});
