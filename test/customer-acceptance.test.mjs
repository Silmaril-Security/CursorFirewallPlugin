import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { accessSync, constants, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

test("only the operator-designated Cursor login may drive the isolated plugin", async (t) => {
  const { agentEnvironment } = await import("../scripts/customer-published-acceptance");
  const fs = (await import("node:fs")).default;
  const home = mkdtempSync(path.join(os.tmpdir(), "qa-login-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const agent = path.join(home, "agent");
  const email = "qa@example.test";
  const descriptor = "/Users/Shared/silmaril-release-qa/cursor-qa-identity.json";
  const oldKey = process.env.CUSTOMER_CURSOR_API_KEY;
  t.after(() => {
    if (oldKey === undefined) delete process.env.CUSTOMER_CURSOR_API_KEY;
    else process.env.CUSTOMER_CURSOR_API_KEY = oldKey;
  });
  delete process.env.CUSTOMER_CURSOR_API_KEY;
  t.mock.method(fs, "existsSync", (file) => file === descriptor);
  let mode = 0o644;
  let owner = 0;
  t.mock.method(fs, "lstatSync", (file) => ({ uid: owner, mode,
    isFile: () => file === descriptor, isDirectory: () => file === path.dirname(descriptor) }));
  let consoleUid = 502;
  t.mock.method(fs, "statSync", () => ({ uid: consoleUid }));
  t.mock.method(os, "userInfo", () => ({ uid: 502, username: "qa", homedir: "/Users/qa" }));
  t.mock.method(fs, "readFileSync", () => JSON.stringify({ account: "qa", email }));
  function identity(authenticated, address) {
    writeFileSync(agent, "#!/bin/sh\nprintf '%s' '" + JSON.stringify({
      isAuthenticated: authenticated, userInfo: { email: address },
    }) + "'\n", { mode: 0o700 });
  }
  identity(true, email);
  const env = agentEnvironment(agent, home);
  assert.equal(env.HOME, "/Users/qa");
  assert.equal(env.CURSOR_CONFIG_DIR, path.join(home, ".cursor"));
  assert.ok(env.SILMARIL_CONFIG_PATH.startsWith(home + path.sep));
  assert.ok(env.SILMARIL_LOCAL_EVENT_DIR.startsWith(home + path.sep));
  for (const [auth, address] of [[true, "other@example.test"], [false, email]]) {
    identity(auth, address);
    assert.equal(agentEnvironment(agent, home), undefined);
  }
  identity(true, email);
  consoleUid = 501;
  assert.equal(agentEnvironment(agent, home), undefined);
  consoleUid = 502;
  mode = 0o666;
  assert.equal(agentEnvironment(agent, home), undefined);
  mode = 0o644;
  owner = 502;
  assert.equal(agentEnvironment(agent, home), undefined);
  process.env.CUSTOMER_CURSOR_API_KEY = "test-only";
  assert.equal(agentEnvironment(agent, home).HOME, home);
  assert.equal(agentEnvironment(agent, home).CURSOR_API_KEY, "test-only");
});

test("reports missing correlated callbacks using only fixed names", async () => {
  const { missingAllowCallbacks } = await import("../scripts/customer-published-acceptance");
  const observed = (hook, changes = {}) => ({ hook, trace: true, ok: true, prediction: "BENIGN", ...changes });
  const tools = [observed("tool_call"), observed("tool_response")];
  assert.deepEqual(missingAllowCallbacks([...tools, observed("user_input", { trace: false }),
    observed("user_input", { ok: false }), observed("user_input", { prediction: "MALICIOUS" }),
    observed("private provider text")]), ["user_input"]);
  assert.deepEqual(missingAllowCallbacks([...tools, observed("user_input", { prediction: "benign" })]), []);
});

test("discovers the exact Cursor release after auto-update and respects explicit selection", async (t) => {
  const { pinnedAgent } = await import("../scripts/customer-published-acceptance");
  const home = mkdtempSync(path.join(os.tmpdir(), "cursor-cli-selection-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const version = "2026.11.19-f005e9d";
  const bin = path.join(home, "bin");
  const pinned = path.join(home, ".local/share/cursor-agent/versions", version, "cursor-agent");
  const launcher = path.join(bin, "agent");
  const override = path.join(bin, "custom-agent");
  function executable(file, reportedVersion) {
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, `#!/bin/sh\necho '${reportedVersion}'\n`, { mode: 0o700 });
  }
  const environment = { HOME: home, PATH: bin };
  executable(launcher, "updated-version");
  executable(pinned, version);
  assert.equal(pinnedAgent(home, environment), pinned);
  executable(override, version);
  assert.equal(pinnedAgent(home, { ...environment, CURSOR_AGENT_BIN: override }), override);
  assert.equal(pinnedAgent(home, { ...environment, CURSOR_AGENT_BIN: launcher }), undefined);
  executable(launcher, version);
  executable(pinned, "unexpected-version");
  assert.equal(pinnedAgent(home, environment), launcher);
  rmSync(pinned);
  assert.equal(pinnedAgent(home, environment), launcher);
});
