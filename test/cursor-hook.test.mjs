import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildCursorTargets,
  buildLocalProtectionEvent,
  consumeOutputDecision,
  effectiveMode,
  governanceContext,
  resolveRuntimeConfig,
  runCursorHook,
  withProvenance,
  writeLocalProtectionEvent,
  writeOutputDecision,
} from "../dist/cursor-hook.js";
import {
  buildDemoStatus,
  buildDemoUrl,
  normalizeBaseUrl,
  openBrowser,
  optionValue,
} from "../scripts/open-playground.mjs";

const BASE_ENV = {
  SILMARIL_CONFIG_PATH: path.join(os.tmpdir(), `silmaril-cursor-tests-${process.pid}-missing.json`),
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "false",
};

function hookInput(hookEventName, extra = {}) {
  return {
    hook_event_name: hookEventName,
    conversation_id: "conversation-1",
    generation_id: "generation-1",
    cursor_version: "9.9.9",
    workspace_roots: ["/private/project"],
    ...extra,
  };
}

function fakeFirewall(results, calls = []) {
  return class {
    constructor(options) {
      calls.push({ constructor: options });
    }
    async classify(text, options) {
      calls.push({ text, options });
      const next = results.shift();
      if (next instanceof Error) throw next;
      return next ?? { prediction: "BENIGN", score: 0.01, threshold: 0.5 };
    }
    async classifyBatch(texts, options) {
      calls.push({ texts, options });
      throw new Error("Plugin runtime must not call classifyBatch");
    }
  };
}

function captureDependencies(results, events = [], calls = []) {
  return {
    firewallConstructor: fakeFirewall([...results], calls),
    evidenceEmitter: async (event) => { events.push(event); },
  };
}

test("configured pilot override wins and backend mode controls otherwise", () => {
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }, "block"), "block");
  assert.equal(effectiveMode({ prediction: "MALICIOUS" }, "block"), "block");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "block" }, "warn"), "warn");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }, "shadow"), "shadow");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }), "warn");
  assert.equal(effectiveMode({ prediction: "MALICIOUS" }), "shadow");
});

test("bundled SDK enforces backend-selected Block when local mode is omitted", async () => {
  const originalFetch = globalThis.fetch;
  const requestBodies = [];
  globalThis.fetch = async (_input, init) => {
    requestBodies.push(JSON.parse(String(init?.body)));
    return new Response(JSON.stringify({
      prediction: "MALICIOUS",
      score: 0.99,
      threshold: 0.5,
      mode: "block",
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const env = { ...BASE_ENV };
  delete env.SILMARIL_BLOCK_MALICIOUS;
  const events = [];
  try {
    const output = await runCursorHook(
      hookInput("beforeSubmitPrompt", { prompt: "unsafe prompt" }),
      env,
      { evidenceEmitter: async (event) => { events.push(event); } },
    );
    assert.deepEqual(output, {
      continue: false,
      user_message: "Silmaril Firewall blocked potentially malicious content.",
    });
    assert.equal(requestBodies.length, 1);
    assert.equal(Object.hasOwn(requestBodies[0], "mode"), false);
    assert.equal(events[0].mode, "block");
    assert.equal(events[0].policyDecision, "block");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime config defaults and rejects incomplete configuration", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-missing-config-"));
  const missingConfig = path.join(root, "missing.json");
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: missingConfig }), undefined);
  assert.deepEqual(resolveRuntimeConfig(BASE_ENV), {
    apiKey: "test-key",
    apiUrl: "https://firewall.example/classify",
    timeoutMs: 2500,
    mode: "shadow",
    blockMalicious: false,
    debug: false,
  });
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_TIMEOUT_MS: "249" }).timeoutMs, 2500);
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "yes" }).blockMalicious, true);
  assert.equal(resolveRuntimeConfig({
    ...BASE_ENV,
    SILMARIL_ENDPOINT_ID: "2b64e603-f82a-4aec-9524-9736472dc80a",
  }).endpointId, "2b64e603-f82a-4aec-9524-9736472dc80a");
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_ENDPOINT_ID: "NOT-A-UUID" }).endpointId, undefined);
});

test("plugin-owned provenance overwrites caller values and preserves unrelated metadata", () => {
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { integration: "cursor-firewall-plugin", provenance: { endpoint_id: "spoofed", harness: "spoofed" } },
  }, "2b64e603-f82a-4aec-9524-9736472dc80a"), {
    trace: "keep",
    silmaril: {
      integration: "cursor-firewall-plugin",
      provenance: {
        schema_version: 1,
        endpoint_id: "2b64e603-f82a-4aec-9524-9736472dc80a",
        harness: "cursor",
      },
    },
  });
  assert.deepEqual(withProvenance({}), {
    silmaril: { provenance: { schema_version: 1, harness: "cursor" } },
  });
});

test("governance context normalizes Cursor tool, MCP, and file-read resources", () => {
  assert.deepEqual(governanceContext({
    hookEventName: "preToolUse",
    toolName: "Shell",
    metadata: {},
  }), {
    agent: "cursor",
    resource: { kind: "tool", id: "Shell" },
  });
  assert.deepEqual(governanceContext({
    hookEventName: "preToolUse",
    toolName: "mcp__github__create_issue",
    metadata: {},
  }), {
    agent: "cursor",
    resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
  });
  const explicitMcp = buildCursorTargets(hookInput("preToolUse", {
    tool_name: "create_issue",
    mcp_server_name: "github",
    tool_input: { title: "Issue" },
  }))[0];
  assert.deepEqual(governanceContext(explicitMcp), {
    agent: "cursor",
    resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
  });
  const fileRead = buildCursorTargets(hookInput("beforeReadFile", {
    file_path: "/tmp/input.txt",
    content: "text",
  }))[0];
  assert.deepEqual(governanceContext(fileRead), {
    agent: "cursor",
    resource: { kind: "tool", id: "Read" },
  });
});

test("runtime config treats a private host file as authoritative", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-config-"));
  const configPath = path.join(root, "silmaril-firewall.json");
  await writeFile(configPath, JSON.stringify({
    enabled: true,
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: configPath }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  });
  assert.deepEqual(resolveRuntimeConfig({
    SILMARIL_CONFIG_PATH: configPath,
    SILMARIL_ENABLED: "false",
    SILMARIL_API_KEY: "environment-key",
    SILMARIL_API_URL: "https://stale.example/classify",
    SILMARIL_TIMEOUT_MS: "9000",
    SILMARIL_BLOCK_MALICIOUS: "false",
  }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  });

  await writeFile(configPath, JSON.stringify({
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({
    SILMARIL_CONFIG_PATH: configPath,
    SILMARIL_ENABLED: "false",
    SILMARIL_API_KEY: "stale-key",
    SILMARIL_API_URL: "https://stale.example/classify",
    SILMARIL_TIMEOUT_MS: "9000",
    SILMARIL_BLOCK_MALICIOUS: "true",
  }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 2500,
    blockMalicious: false,
    debug: false,
  });

  await chmod(configPath, 0o644);
  assert.equal(resolveRuntimeConfig({
    ...BASE_ENV,
    SILMARIL_CONFIG_PATH: configPath,
  }), undefined);
  await chmod(configPath, 0o600);
  const symlinkPath = path.join(root, "linked.json");
  await symlink(configPath, symlinkPath);
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: symlinkPath }), undefined);
});

test("every supported Cursor lifecycle event maps to the intended Firewall hook", () => {
  const cases = [
    [hookInput("beforeSubmitPrompt", { prompt: "hello" }), "user_input"],
    [hookInput("preToolUse", { tool_name: "Shell", tool_input: { command: "pwd" } }), "tool_call"],
    [hookInput("beforeReadFile", { content: "file text" }), "tool_response"],
    [hookInput("postToolUse", { tool_name: "Shell", tool_output: "ok" }), "tool_response"],
    [hookInput("postToolUseFailure", { error_message: "failed" }), "tool_response"],
    [hookInput("afterAgentResponse", { text: "done" }), "llm_output"],
    [hookInput("afterAgentThought", { text: "reasoning" }), "llm_output"],
    [hookInput("subagentStart", { task: "inspect auth", tool_call_id: "task-1" }), "user_input"],
  ];
  for (const [input, expected] of cases) {
    assert.equal(buildCursorTargets(input)[0]?.firewallHook, expected);
  }
});

test("logical request IDs are stable but change across generations", () => {
  const first = buildCursorTargets(hookInput("beforeSubmitPrompt", { prompt: "same" }))[0].requestId;
  const second = buildCursorTargets(hookInput("beforeSubmitPrompt", { prompt: "changed content" }))[0].requestId;
  const nextGeneration = buildCursorTargets(hookInput("beforeSubmitPrompt", { prompt: "same", generation_id: "generation-2" }))[0].requestId;
  assert.equal(first, second);
  assert.notEqual(first, nextGeneration);
});

test("runtime verification markers correlate with local evidence", async () => {
  const marker = "silmaril-runtime-check:123e4567-e89b-12d3-a456-426614174000";
  const events = [];
  await runCursorHook(
    hookInput("beforeSubmitPrompt", { prompt: `Reply with OK only. ${marker}` }),
    BASE_ENV,
    captureDependencies([{ prediction: "BENIGN", score: 0.1, threshold: 0.5 }], events),
  );
  assert.equal(events.length, 1);
  assert.equal(
    events[0].requestFingerprint,
    createHash("sha256").update(marker).digest("hex"),
  );
});

test("shadow mode observes without returning hook output", async () => {
  const events = [];
  const output = await runCursorHook(
    hookInput("beforeSubmitPrompt", { prompt: "raw-shadow-secret" }),
    BASE_ENV,
    captureDependencies([{ prediction: "MALICIOUS", score: 0.9, threshold: 0.5 }], events),
  );
  assert.equal(output, undefined);
  assert.equal(events[0].policyDecision, "monitor");
  assert.equal(events[0].mode, "shadow");
  assert.doesNotMatch(JSON.stringify(events[0]), /raw-shadow-secret/u);
});

test("governance blocks deny only supported pre-execution hooks in block mode", async () => {
  const decision = {
    prediction: "BENIGN",
    governance: { action: "block", rule_id: "block-shell", policy_version: "v1" },
  };
  const prompt = hookInput("beforeSubmitPrompt", { prompt: "prompt" });

  assert.equal(
    await runCursorHook(prompt, { ...BASE_ENV, SILMARIL_MODE: "shadow" }, captureDependencies([decision])),
    undefined,
  );
  assert.equal(
    await runCursorHook(prompt, { ...BASE_ENV, SILMARIL_MODE: "warn" }, captureDependencies([decision])),
    undefined,
  );
  const blocked = await runCursorHook(
    prompt,
    { ...BASE_ENV, SILMARIL_MODE: "block" },
    captureDependencies([decision]),
  );
  assert.equal(blocked.continue, false);

  assert.equal(
    await runCursorHook(
      hookInput("postToolUse", { tool_name: "Shell", tool_output: "done" }),
      { ...BASE_ENV, SILMARIL_MODE: "block" },
      captureDependencies([decision]),
    ),
    undefined,
  );
});

test("only exact MALICIOUS blocks prompts and tools", async () => {
  const env = { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" };
  const promptOutput = await runCursorHook(
    hookInput("beforeSubmitPrompt", { prompt: "prompt" }),
    env,
    captureDependencies([{ prediction: "MALICIOUS" }]),
  );
  assert.deepEqual(promptOutput, { continue: false, user_message: "Silmaril Firewall blocked potentially malicious content." });

  const toolOutput = await runCursorHook(
    hookInput("preToolUse", { tool_name: "Shell", tool_input: { command: "command" } }),
    env,
    captureDependencies([{ prediction: "MALICIOUS" }]),
  );
  assert.equal(toolOutput.permission, "deny");

  for (const prediction of ["malicious", "UNKNOWN", undefined]) {
    const output = await runCursorHook(
      hookInput("beforeSubmitPrompt", { prompt: "prompt" }),
      env,
      captureDependencies([{ prediction }]),
    );
    assert.equal(output, undefined);
  }
});

test("beforeReadFile blocks before model consumption", async () => {
  const output = await runCursorHook(
    hookInput("beforeReadFile", { file_path: "/private/secret", content: "untrusted" }),
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    captureDependencies([{ prediction: "MALICIOUS" }]),
  );
  assert.equal(output.permission, "deny");
});

test("postToolUse replaces MCP output while generic tools stay explicitly unavailable", async () => {
  const env = { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" };
  const events = [];
  const generic = await runCursorHook(
    hookInput("postToolUse", { tool_name: "Shell", tool_output: "unsafe" }),
    env,
    captureDependencies([{ prediction: "MALICIOUS" }], events),
  );
  assert.equal(generic, undefined);
  for (const identity of [
    { tool_name: "MCP:github:fetch" },
    { tool_name: "mcp__github__fetch" },
    { tool_name: "fetch", mcp_server_name: "github" },
  ]) {
    const mcp = await runCursorHook(
      hookInput("postToolUse", { ...identity, tool_output: "unsafe" }),
      env,
      captureDependencies([{ prediction: "MALICIOUS" }], events),
    );
    assert.deepEqual(mcp, {
      updated_mcp_tool_output: { error: "Silmaril Firewall blocked potentially malicious content." },
      additional_context: "Silmaril Firewall blocked potentially malicious content.",
    });
    assert.doesNotMatch(JSON.stringify(mcp), /unsafe/u);
  }
  assert.equal(events[0].blockUnavailable, true);
  assert.ok(events.slice(1).every((event) => event.blockUnavailable === undefined));
  assert.ok(events.slice(1).every((event) => event.nativeAction === "content_replaced"));
});

test("warn mode remains unchanged where Cursor cannot deliver same-turn context", async () => {
  const env = { ...BASE_ENV };
  delete env.SILMARIL_BLOCK_MALICIOUS;
  const events = [];
  for (const input of [
    hookInput("beforeSubmitPrompt", { prompt: "raw prompt" }),
    hookInput("preToolUse", { tool_name: "Shell", tool_input: { command: "raw args" } }),
    hookInput("postToolUse", { tool_name: "Shell", tool_output: "raw output" }),
  ]) {
    assert.equal(
      await runCursorHook(input, env, captureDependencies([{ prediction: "MALICIOUS", mode: "warn" }], events)),
      undefined,
    );
  }
  assert.ok(events.every((event) => event.mode === "warn" && event.warnDelivery === "unsupported"));
  assert.doesNotMatch(JSON.stringify(events), /raw prompt|raw args|raw output/u);
});

test("configuration, network, timeout, SDK, and malformed-response paths fail open", async () => {
  assert.equal(await runCursorHook(hookInput("beforeSubmitPrompt", { prompt: "text" }), {}), undefined);
  const timeout = new Error("request timed out");
  timeout.name = "TimeoutError";
  for (const failure of [new Error("network failed"), timeout, new Error("SDK failed")]) {
    assert.equal(await runCursorHook(
      hookInput("beforeSubmitPrompt", { prompt: "text" }),
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      captureDependencies([failure]),
    ), undefined);
  }
  assert.equal(await runCursorHook(
    hookInput("beforeSubmitPrompt", { prompt: "text" }),
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    captureDependencies([{ unexpected: "response" }]),
  ), undefined);
});

test("assistant output does not use replacement or follow-up as a block", async () => {
  const env = { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" };
  const writes = [];
  const firstEvents = [];
  const responseOutput = await runCursorHook(
    hookInput("afterAgentResponse", { text: "raw assistant output" }),
    env,
    {
      ...captureDependencies([{ prediction: "MALICIOUS", score: 0.8, threshold: 0.5 }], firstEvents),
      decisionWriter: async (conversationId, generationId, result) => {
        writes.push({ conversationId, generationId, result });
        return true;
      },
    },
  );
  assert.equal(responseOutput, undefined);
  assert.equal(writes.length, 0);
  assert.equal(firstEvents.length, 1);
  assert.equal(firstEvents[0].policyDecision, "monitor");
  assert.equal(firstEvents[0].blockUnavailable, true);

  const stopEvents = [];
  const stopOutput = await runCursorHook(
    hookInput("stop", { status: "completed", loop_count: 0 }),
    env,
    {
      evidenceEmitter: async (event) => { stopEvents.push(event); },
      decisionConsumer: async () => ({
        version: 1,
        createdAt: new Date().toISOString(),
        conversationFingerprint: "fingerprint",
        generationFingerprint: "fingerprint",
        prediction: "MALICIOUS",
        score: 0.8,
        threshold: 0.5,
      }),
    },
  );
  assert.equal(stopOutput, undefined);
  assert.equal(stopEvents.length, 0);
});

test("decision cache is private, bounded, single-use, and expires", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-cache-"));
  const now = new Date("2026-08-10T12:00:00.000Z");
  assert.equal(await writeOutputDecision("c1", "g1", { prediction: "MALICIOUS", primaryOutcome: "code_execution" }, { directory: root, now }), true);
  const files = await import("node:fs/promises").then(({ readdir }) => readdir(root));
  assert.equal(files.length, 1);
  assert.equal((await stat(path.join(root, files[0]))).mode & 0o777, 0o600);
  assert.equal((await consumeOutputDecision("c1", "g1", { directory: root, now })).prediction, "MALICIOUS");
  assert.equal(await consumeOutputDecision("c1", "g1", { directory: root, now }), undefined);

  await writeOutputDecision("c2", "g2", { prediction: "MALICIOUS" }, { directory: root, now });
  assert.equal(await consumeOutputDecision("c2", "g2", { directory: root, now: new Date(now.getTime() + 11 * 60 * 1000) }), undefined);

  await writeOutputDecision("c3", "g3", { prediction: "MALICIOUS" }, { directory: root, now });
  await writeOutputDecision("c4", "g4", { prediction: "MALICIOUS" }, { directory: root, now: new Date(now.getTime() + 11 * 60 * 1000) });
  const remaining = await import("node:fs/promises").then(({ readdir }) => readdir(root));
  assert.equal(remaining.length, 1);
});

test("subagent stop classifies only the current summary and never replays transcripts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-transcript-"));
  const transcript = path.join(root, "child.jsonl");
  await writeFile(transcript, Array.from({ length: 300 }, (_, index) => JSON.stringify({
    message: { role: "user", content: `historical segment ${index}` },
  })).join("\n"));
  const input = hookInput("subagentStop", {
    status: "completed",
    loop_count: 0,
    agent_transcript_path: transcript,
    task: "already observed task",
    summary: "current summary",
  });
  const targets = buildCursorTargets(input);
  assert.equal(targets.length, 1);
  assert.equal(targets[0].text, "current summary");
  assert.equal(targets[0].firewallHook, "llm_output");
  assert.equal(targets[0].metadata.source, "subagent_summary");
  assert.equal(targets[0].metadata.transcriptSegmentIndex, undefined);

  const calls = [];
  const events = [];
  const output = await runCursorHook(
    input,
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    captureDependencies([{ prediction: "MALICIOUS" }], events, calls),
  );
  assert.equal(output, undefined);
  assert.equal(events.length, 1);
  assert.equal(events[0].blockUnavailable, true);
  assert.equal(events[0].nativeAction, "allowed");
  const classificationCalls = calls.filter((call) => Object.hasOwn(call, "text"));
  assert.equal(classificationCalls.length, 1);
  assert.equal(calls.some((call) => Object.hasOwn(call, "texts")), false);
  assert.equal(classificationCalls[0].text, "current summary");
  assert.equal(classificationCalls[0].options.hook, "llm_output");
});

test("local evidence is redacted and written atomically with private permissions", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-cursor-evidence-"));
  const event = buildLocalProtectionEvent({
    pluginName: "cursor-firewall-plugin",
    pluginVersion: "0.2.4",
    hook: "user_input",
    mode: "block",
    requestId: "raw-request-id",
    sessionId: "raw-session-id",
    toolName: "Shell",
    classification: { prediction: "MALICIOUS", score: 0.9, threshold: 0.5, primaryOutcome: "code_execution", raw: "must-not-leak" },
    policyDecision: "block",
    nativeAction: "block_returned",
  });
  const destination = await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: root });
  assert.ok(destination);
  const encoded = await readFile(destination, "utf8");
  assert.doesNotMatch(encoded, /must-not-leak|raw-request-id|raw-session-id/u);
  assert.ok(Buffer.byteLength(encoded) <= 16 * 1024);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
  assert.ok((await import("node:fs/promises").then(({ readdir }) => readdir(root))).every((name) => !name.endsWith(".tmp")));

  const symlinkRoot = path.join(root, "symlink");
  const realRoot = await mkdtemp(path.join(os.tmpdir(), "silmaril-real-evidence-"));
  await symlink(realRoot, symlinkRoot);
  assert.equal(await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: symlinkRoot }), undefined);

  const output = await runCursorHook(
    hookInput("preToolUse", { tool_name: "Shell", tool_input: { command: "pwd" } }),
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    {
      ...captureDependencies([{ prediction: "MALICIOUS" }]),
      evidenceEmitter: async () => { throw new Error("disk failure"); },
    },
  );
  assert.equal(output.permission, "deny");
});

test("demo launcher normalizes URLs and never returns the key", async () => {
  assert.equal(normalizeBaseUrl("example.com/path?key=value"), "https://example.com");
  assert.equal(buildDemoUrl("https://app.silmaril.dev", "setup"), "https://app.silmaril.dev/demo/setup-complete");
  assert.equal(buildDemoUrl("http://localhost:3001", "playground"), "http://localhost:3001/demo/playground");
  const statusPayload = JSON.stringify(buildDemoStatus({ SILMARIL_API_KEY: "super-secret", SILMARIL_API_URL: "https://api.example/path" }));
  assert.doesNotMatch(statusPayload, /super-secret/u);
  assert.match(statusPayload, /https:\/\/api\.example/u);

  const openedChild = new EventEmitter();
  openedChild.unref = () => undefined;
  const opened = openBrowser("https://example.com", () => openedChild);
  openedChild.emit("spawn");
  assert.equal(await opened, true);

  const failedChild = new EventEmitter();
  failedChild.unref = () => undefined;
  const failed = openBrowser("https://example.com", () => failedChild);
  failedChild.emit("error", new Error("missing opener"));
  assert.equal(await failed, false);
  assert.equal(await openBrowser("https://example.com", () => { throw new Error("spawn failed"); }), false);

  const originalArgs = process.argv;
  process.argv = ["node", "script", "--route", "--open"];
  assert.equal(optionValue("--route"), undefined);
  process.argv = originalArgs;
});

test("package and Cursor manifests preserve release invariants", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const pluginJson = JSON.parse(await readFile(new URL("../.cursor-plugin/plugin.json", import.meta.url), "utf8"));
  const hooksJson = JSON.parse(await readFile(new URL("../hooks/hooks.json", import.meta.url), "utf8"));
  assert.equal(packageJson.version, "0.2.4");
  assert.equal(pluginJson.version, packageJson.version);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.6.2");
  assert.equal(packageJson.private, true);
  assert.equal(hooksJson.hooks.beforeSubmitPrompt[0].failClosed, false);
  assert.equal(hooksJson.hooks.subagentStop[0].loop_limit, 1);
  await stat(new URL("../dist/cursor-hook.js", import.meta.url));
});
