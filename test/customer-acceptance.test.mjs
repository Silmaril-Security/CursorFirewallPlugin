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

test("the pinned CLI may omit only prompt coverage from a completed read or denial", async () => {
  const { assessTurnEvidence } = await import("../scripts/customer-published-acceptance");
  const pin = "2026.11.19-f005e9d";
  const callback = (hook) => ({ hook, session: "this-turn", trace: true, ok: true, prediction: "BENIGN" });
  const event = (hook, denied = false) => ({
    hook, host: "cursor", provenance: { pluginVersion: version }, sessionFingerprint: "this-turn",
    mode: "block", prediction: "benign", policyDecision: denied ? "block" : "allow",
    nativeAction: denied ? "block_returned" : "allowed",
  });
  const callbacks = [callback("tool_call"), callback("tool_response")];
  const events = [event("pre_tool"), event("post_tool")];
  const assess = (records, requests, denied = false, cli = pin) => assessTurnEvidence(records, requests, version, denied, cli);
  const passes = (result) => result.complete && result.missing.length === 0;
  assert.deepEqual(assess(events, callbacks), { complete: true, missing: [], requirePrompt: false });
  assert.equal(passes(assess(events, callbacks, false, "new-cli")), false);
  assert.equal(passes(assess(events, callbacks.slice(0, 1))), false);
  assert.equal(passes(assess([events[0], { ...events[1], sessionFingerprint: "unrelated" }], callbacks)), false);
  assert.equal(passes(assess(events, [callbacks[0], { ...callbacks[1], session: "unrelated" }])), false);
  assert.equal(passes(assess(events, [...callbacks, { ...callbacks[0], session: "second-read" }])), false);
  assert.equal(passes(assess(events, callbacks.map((entry) => ({ ...entry, session: undefined })))), false);
  assert.equal(passes(assess(events, [...callbacks, callback("user_input")])), false);
  assert.equal(passes(assess([...events, event("user_input")], callbacks)), false);
  const promptEvents = [...events, event("user_input")];
  assert.equal(passes(assess(promptEvents, [...callbacks, { ...callback("user_input"), ok: false }])), false);
  assert.equal(passes(assess(promptEvents, [...callbacks, callback("user_input")], false, "new-cli")), true);
  assert.equal(passes(assess([event("pre_tool", true)], [callbacks[0]], true)), true);
  assert.equal(passes(assess(events, [callbacks[0]], true)), false);
});

test("only a verified read or denial can resume its own interrupted conversation", async () => {
  const { createHash } = await import("node:crypto");
  const { canResumeTurn } = await import("../scripts/customer-published-acceptance");
  const session = "d6fdc7a2-8346-4bf8-a698-a02ddbe322df";
  const fingerprint = createHash("sha256").update(`session:${session}`).digest("hex");
  const turn = { code: 1, session, valid: true, reconnecting: true, disclosed: false };
  const call = { session: fingerprint, hook: "tool_call", trace: true, deny: false, ok: true, prediction: "BENIGN" };
  const response = { ...call, hook: "tool_response", containsWord: true };
  const evidence = { complete: true, missing: [] };
  const eligible = (t, e = evidence, rows = [call, response]) => canResumeTurn(t, e, false, rows);
  assert.equal(eligible(turn), true);
  for (const changes of [{ code: 0 }, { code: null }, { session: "unrelated" }, { valid: false },
    { reconnecting: false }, { reply: { is_error: true } }]) {
    assert.equal(eligible({ ...turn, ...changes }), false);
  }
  assert.equal(eligible(turn, { ...evidence, complete: false }), false);
  assert.equal(eligible(turn, { ...evidence, missing: ["tool_response"] }), false);
  assert.equal(eligible(turn, evidence, [call]), false);
  assert.equal(eligible(turn, evidence, [call, { ...response, ok: false }]), false);
  const blocked = [{ ...call, deny: true }];
  assert.equal(canResumeTurn(turn, evidence, true, blocked), true);
  assert.equal(canResumeTurn(turn, evidence, true, [...blocked, response]), false);
  assert.equal(canResumeTurn({ ...turn, disclosed: true }, evidence, true, blocked), false);
});

test("stream results must terminate a single initialized conversation", async () => {
  const { Readable } = await import("node:stream");
  const { readTurnStream } = await import("../scripts/customer-published-acceptance");
  const session_id = "d6fdc7a2-8346-4bf8-a698-a02ddbe322df";
  const init = { type: "system", subtype: "init", session_id };
  const result = { type: "result", session_id, result: "answer", is_error: false };
  const read = (...rows) => readTurnStream(Readable.from(rows.map((r) =>
    (typeof r === "string" ? r : JSON.stringify(r)) + "\n")), "private-word");
  const flags = await read(init, { type: "tool_call" }, { type: "connection", subtype: "reconnecting" },
    { type: "assistant", message: { content: [{ type: "text", text: "private-word" }] } });
  assert.deepEqual(flags, { valid: true, session: session_id, reconnecting: true, toolUsed: true, disclosed: true, reply: undefined });
  assert.deepEqual((await read(init, result)).reply, result);
  for (const rows of [[result], [init, "truncated"], [init, init], [init, result, result],
    [init, { ...result, session_id: "another" }], [init, { ...result, session_id: undefined }]]) {
    assert.equal((await read(...rows)).valid, false);
  }
});

test("the driver resumes once and qualifies only a completed tool-free reply from the original session", async (t) => {
  const { verifyTurn } = await import("../scripts/customer-published-acceptance");
  const work = mkdtempSync(path.join(os.tmpdir(), "cursor-resume-"));
  t.after(() => rmSync(work, { recursive: true, force: true }));
  mkdirSync(path.join(work, ".cursor"));
  const agent = path.join(work, "cli.mjs");
  const session = "d6fdc7a2-8346-4bf8-a698-a02ddbe322df";

  async function simulateClient() {
    const fs = await import("node:fs");
    const { createHash } = await import("node:crypto");
    const { session, scenario, version, HOME } = process.env;
    const args = process.argv.slice(2);
    const resume = args.indexOf("--resume");
    fs.appendFileSync(HOME + "/calls", JSON.stringify(resume < 0 ? null : args[resume + 1]) + "\n");
    const session_id = resume >= 0 && scenario === "changed session" ? "0640c4c1-73ba-4a09-8892-94a17d116534" : session;
    const emit = (type, fields) => console.log(JSON.stringify({ type, session_id, ...fields }));
    emit("system", { subtype: "init" });
    const note = fs.readdirSync(".").find((name) => name.startsWith("note-"));
    const [trace, word] = fs.readFileSync(note, "utf8").trim().split(" ");
    const classify = async () => {
      const config = JSON.parse(fs.readFileSync(HOME + "/.cursor/silmaril-firewall.json", "utf8"));
      const response = await fetch(config.apiUrl, { method: "POST",
        body: JSON.stringify({ hook: "tool_call", text: trace, metadata: { conversationId: session } }) });
      if ((await response.json()).governance?.action !== "block") throw new Error("expected denied read");
    };
    if (resume < 0) {
      await classify();
      const spool = HOME + "/Library/Application Support/Silmaril/Evidence/incoming";
      fs.mkdirSync(spool, { recursive: true });
      fs.writeFileSync(spool + "/event-deny.json", JSON.stringify({
        host: "cursor", hook: "pre_tool", provenance: { pluginVersion: version }, mode: "block", prediction: "benign",
        sessionFingerprint: createHash("sha256").update("session:" + session).digest("hex"),
        policyDecision: "block", nativeAction: "block_returned",
      }));
    }
    if (resume < 0 || scenario === "second disconnect") {
      emit("connection", { subtype: "reconnecting" });
      process.exitCode = 1;
      return;
    }
    if (scenario === "tool event") emit("tool_call", { subtype: "started" });
    if (scenario === "classified tool") await classify();
    if (scenario === "intermediate disclosure") emit("assistant", { message: { content: [{ type: "text", text: word }] } });
    const result = scenario === "terminal disclosure" ? word : "Silmaril Firewall blocked potentially malicious content.";
    emit("result", { subtype: "success", result, is_error: scenario === "unsuccessful reply" });
  }
  writeFileSync(agent, "#!" + process.execPath + "\nawait (" + simulateClient.toString() + ")();\n", { mode: 0o700 });
  for (const scenario of ["success", "changed session", "tool event", "classified tool", "intermediate disclosure",
    "terminal disclosure", "second disconnect", "unsuccessful reply"]) {
    writeFileSync(path.join(work, "calls"), "");
    const status = await verifyTurn(agent, { home: work, work, installed: work, kind: "denial", version,
      env: { HOME: work, session, scenario, version } });
    assert.equal(status, scenario === "success" ? "PASS" : "FAIL", scenario);
    assert.deepEqual(readFileSync(path.join(work, "calls"), "utf8").trim().split("\n").map(JSON.parse),
      [null, session], scenario);
  }
});
