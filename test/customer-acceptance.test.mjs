import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { accessSync, constants, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const driver = path.join(root, "scripts", "customer-published-acceptance");
const version = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version;

function drive(args, extra) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "cursor-customer-test-"));
  const env = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => !/^(CUSTOMER_|CURSOR_)/.test(name)));
  const resultFile = path.join(directory, "result.json");
  const child = spawnSync(driver, args, { env: { ...env, CUSTOMER_RESULT: resultFile, ...extra(directory) }, encoding: "utf8" });
  const result = JSON.parse(readFileSync(resultFile, "utf8"));
  rmSync(directory, { recursive: true, force: true });
  return { child, result };
}

test("the driver is executable", () => {
  accessSync(driver, constants.X_OK);
});

test("a wrong digest or malformed identity never reports a pass", () => {
  for (const identity of [
    { CUSTOMER_ARTIFACT_SHA256: "0".repeat(64), CUSTOMER_VERSION: version },
    { CUSTOMER_ARTIFACT_SHA256: "0".repeat(64), CUSTOMER_VERSION: "latest" },
  ]) {
    const { child, result } = drive([], (directory) => {
      const artifact = path.join(directory, "candidate.tar.gz");
      writeFileSync(artifact, "not the supplied archive");
      return {
        CUSTOMER_ARTIFACT: artifact, CUSTOMER_SOURCE_SHA: "1".repeat(40),
        CUSTOMER_ARCHIVE_HELPER: path.join(directory, "unused-helper.py"), ...identity,
      };
    });
    assert.deepEqual(result, { install: "FAIL", native: "BLOCKED", live: "BLOCKED", policy_denial: "BLOCKED" });
    assert.equal(child.status, 1);
  }
});

test("a real lean install without QA or live credentials leaves native and live blocked", () => {
  const { child, result } = drive(["--leased", root], () => ({ CUSTOMER_VERSION: version }));
  assert.deepEqual(result, { install: "PASS", native: "BLOCKED", live: "BLOCKED", policy_denial: "BLOCKED" });
  assert.equal(child.status, 3);
});


test("the client denial requires the actual rule decision and withholds the unprompted file value", async () => {
  const { denialVisible } = await import("../scripts/customer-published-acceptance");
  const denied = { hook: "tool_call", trace: true, deny: true, ok: true };
  const notice = "Silmaril Firewall blocked potentially malicious content.";
  const word = "test-only-file-value";
  assert.equal(denialVisible([denied], notice, word), true);
  assert.equal(denialVisible([], notice, word), false);
  assert.equal(denialVisible([denied], "", word), false);
  assert.equal(denialVisible([denied], notice + word, word), false);
  assert.equal(denialVisible([denied, { hook: "tool_response", containsWord: true }], notice, word), false);
});


test("CLI diagnostics disclose only fixed failure categories", async () => {
  const { cursorFailureReason } = await import("../scripts/customer-published-acceptance");
  assert.equal(cursorFailureReason("Authentication required. Private text and credential"), "authentication rejected");
  assert.equal(cursorFailureReason("Workspace Trust Required: /private/qa"), "workspace trust required");
  assert.equal(cursorFailureReason("arbitrary secret response"), "unrecognized CLI error");
});


test("private diagnostics retain only the last 8192 bytes across UTF-8 chunks", async () => {
  const { diagnosticTail } = await import("../scripts/customer-published-acceptance");
  const chunk = Buffer.from("é".repeat(6000));
  const tail = diagnosticTail(Buffer.alloc(0), chunk);
  assert.equal(tail.length, 8192);
  assert.deepEqual(diagnosticTail(tail, Buffer.from("end")), Buffer.concat([chunk, Buffer.from("end")]).subarray(-8192));
});
