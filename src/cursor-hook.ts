import { Firewall, HookLabel, type FirewallOptions } from "@silmaril-security/sdk";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { consumeOutputDecision, writeOutputDecision, type CachedOutputDecision } from "./decision-cache.js";
import {
  resolveRuntimeConfig,
  type RuntimeConfig,
  type RuntimeEnv,
} from "./runtime-config.js";
import {
  buildLocalProtectionEvent,
  writeLocalProtectionEvent,
  type LocalEvidenceInput,
  type LocalProtectionEventV1,
  type ProtectionHook,
} from "./local-evidence.js";

export { consumeOutputDecision, writeOutputDecision } from "./decision-cache.js";
export { buildLocalProtectionEvent, resolveLocalEventDirectory, writeLocalProtectionEvent } from "./local-evidence.js";
export { configurationPath, resolveRuntimeConfig } from "./runtime-config.js";

export const PLUGIN_NAME = "cursor-firewall-plugin";
export const PLUGIN_VERSION = "0.1.2";
const MAX_STDIN_BYTES = 4 * 1024 * 1024;
const MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024;
const MAX_TRANSCRIPT_SEGMENTS = 256;
const SAFE_BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content.";
const SAFE_FOLLOWUP_MESSAGE = "Silmaril Firewall blocked the previous output. Continue without using or reproducing the flagged content.";

type ClassificationResult = Record<string, unknown>;
type ClassifyOptions = { hook?: string; toolName?: string; metadata?: Record<string, unknown>; requestId?: string };
type ClassifyBatchOptions = { hooks?: string[]; toolNames?: Array<string | undefined>; metadata?: Array<Record<string, unknown>>; requestId?: string };
type FirewallClient = {
  classify(text: string, options?: ClassifyOptions): Promise<ClassificationResult>;
  classifyBatch?(texts: string[], options?: ClassifyBatchOptions): Promise<ClassificationResult[]>;
};
type FirewallConstructor = new (options: FirewallOptions) => FirewallClient;
type HookRecord = Record<string, unknown>;
type HookOutput = Record<string, unknown>;

type Target = {
  hookEventName: string;
  text: string;
  firewallHook: string;
  evidenceHook: ProtectionHook;
  requestId: string;
  sessionId?: string;
  generationId?: string;
  toolName?: string;
  toolUseId?: string;
  metadata: Record<string, unknown>;
  nativeCapability: "none" | "deny" | "replace_mcp" | "followup";
};

type RuntimeDependencies = {
  firewallConstructor: FirewallConstructor;
  evidenceEmitter: (event: LocalProtectionEventV1, env: RuntimeEnv) => Promise<unknown>;
  decisionWriter: typeof writeOutputDecision;
  decisionConsumer: typeof consumeOutputDecision;
};

const DEFAULT_DEPENDENCIES: RuntimeDependencies = {
  firewallConstructor: Firewall as unknown as FirewallConstructor,
  evidenceEmitter: writeLocalProtectionEvent,
  decisionWriter: writeOutputDecision,
  decisionConsumer: consumeOutputDecision,
};

export async function runCursorHook(
  input: unknown,
  env: RuntimeEnv = process.env,
  dependencies: Partial<RuntimeDependencies> = {},
): Promise<HookOutput | undefined> {
  const config = resolveRuntimeConfig(env);
  if (!config) {
    debugLog(env, "missing_config");
    return undefined;
  }
  const deps = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  const record = readRecord(input);
  const hookEventName = readString(record?.hook_event_name);
  if (!record || !hookEventName) return undefined;

  if (hookEventName === "stop") {
    return handleStop(record, config, env, deps);
  }

  const targets = buildCursorTargets(record);
  if (targets.length === 0) {
    debugLog(env, "unsupported_or_empty_event", { hookEventName });
    return undefined;
  }

  let classified: Array<{ target: Target; result: ClassificationResult }>;
  try {
    const firewall = new deps.firewallConstructor({
      apiKey: config.apiKey,
      apiUrl: config.apiUrl,
      timeoutMs: config.timeoutMs,
    });
    classified = await classifyTargets(firewall, targets);
  } catch (error) {
    debugLog(env, "classification_error", { hookEventName, targetCount: targets.length, ...safeErrorFields(error) });
    return undefined;
  }

  if (hookEventName === "afterAgentResponse") {
    return handleAgentResponse(classified[0], config, env, deps);
  }

  const blocking = classified.find(({ target, result }) => shouldNativeBlock(target, result, config, record));
  await Promise.allSettled(classified.map(({ target, result }) => emitEvidence(
    target,
    result,
    config,
    blocking?.target === target,
    env,
    deps.evidenceEmitter,
  )));
  for (const { target, result } of classified) {
    debugClassification(env, target, result, blocking?.target === target);
  }
  return blocking ? buildBlockOutput(blocking.target, record) : undefined;
}

export function buildCursorTargets(input: HookRecord): Target[] {
  const hookEventName = readString(input.hook_event_name);
  if (!hookEventName) return [];
  const sessionId = readString(input.conversation_id);
  const generationId = readString(input.generation_id);

  const makeTarget = (
    text: string | undefined,
    firewallHook: string,
    evidenceHook: ProtectionHook,
    capability: Target["nativeCapability"],
    suffix = "0",
    toolName = readString(input.tool_name),
    toolUseId = readString(input.tool_use_id),
    extraMetadata: Record<string, unknown> = {},
  ): Target[] => {
    if (!text?.trim()) return [];
    return [{
      hookEventName,
      text,
      firewallHook,
      evidenceHook,
      requestId: logicalRequestId(input, suffix),
      ...(sessionId ? { sessionId } : {}),
      ...(generationId ? { generationId } : {}),
      ...(toolName ? { toolName } : {}),
      ...(toolUseId ? { toolUseId } : {}),
      metadata: buildMetadata(input, extraMetadata),
      nativeCapability: capability,
    }];
  };

  switch (hookEventName) {
    case "beforeSubmitPrompt":
      return makeTarget(readString(input.prompt), HookLabel.USER_INPUT, "user_input", "deny");
    case "preToolUse":
      return makeTarget(stableStringify(input.tool_input), HookLabel.TOOL_CALL, "pre_tool", "deny");
    case "beforeReadFile":
      return makeTarget(readString(input.content), HookLabel.TOOL_RESPONSE, "tool_result", "deny", "0", "Read");
    case "postToolUse": {
      const toolName = readString(input.tool_name);
      const capability = toolName?.startsWith("MCP:") ? "replace_mcp" : "none";
      return makeTarget(readTextOrSerialized(input.tool_output), HookLabel.TOOL_RESPONSE, "post_tool", capability);
    }
    case "postToolUseFailure":
      return makeTarget(readString(input.error_message), HookLabel.TOOL_RESPONSE, "post_tool", "none");
    case "afterAgentResponse":
      return makeTarget(readString(input.text), HookLabel.LLM_OUTPUT, "llm_output", "followup");
    case "afterAgentThought":
      return makeTarget(readString(input.text), HookLabel.LLM_OUTPUT, "llm_output", "none", "0", undefined, undefined, { source: "reasoning" });
    case "subagentStart":
      return makeTarget(readString(input.task), HookLabel.USER_INPUT, "subagent", "deny", "0", "Task", readString(input.tool_call_id), { source: "subagent_task" });
    case "subagentStop":
      return buildSubagentTargets(input);
    default:
      return [];
  }
}

async function classifyTargets(
  firewall: FirewallClient,
  targets: Target[],
): Promise<Array<{ target: Target; result: ClassificationResult }>> {
  if (targets.length === 1 || !firewall.classifyBatch) {
    return Promise.all(targets.map(async (target) => ({
      target,
      result: await firewall.classify(target.text, classifyOptions(target)),
    })));
  }

  const classified: Array<{ target: Target; result: ClassificationResult }> = [];
  for (let offset = 0; offset < targets.length; offset += MAX_TRANSCRIPT_SEGMENTS) {
    const batch = targets.slice(offset, offset + MAX_TRANSCRIPT_SEGMENTS);
    const results = await firewall.classifyBatch(
      batch.map((target) => target.text),
      {
        hooks: batch.map((target) => target.firewallHook),
        toolNames: batch.map((target) => target.toolName),
        metadata: batch.map((target) => target.metadata),
        requestId: `cursor-batch-${sha256(batch.map((target) => target.requestId).join("\u0000"))}`,
      },
    );
    if (results.length !== batch.length) throw new Error("Firewall batch result length mismatch");
    batch.forEach((target, index) => classified.push({ target, result: results[index] ?? {} }));
  }
  return classified;
}

async function handleAgentResponse(
  entry: { target: Target; result: ClassificationResult } | undefined,
  config: RuntimeConfig,
  env: RuntimeEnv,
  deps: RuntimeDependencies,
): Promise<undefined> {
  if (!entry) return undefined;
  const { target, result } = entry;
  const shouldCache = config.blockMalicious && isMalicious(result) && target.sessionId && target.generationId;
  let cached = false;
  if (shouldCache && target.sessionId && target.generationId) {
    cached = await deps.decisionWriter(target.sessionId, target.generationId, result);
  }
  await emitEvidence(target, result, config, false, env, deps.evidenceEmitter);
  debugClassification(env, target, result, false, { decisionCached: cached });
  return undefined;
}

async function handleStop(
  input: HookRecord,
  config: RuntimeConfig,
  env: RuntimeEnv,
  deps: RuntimeDependencies,
): Promise<HookOutput | undefined> {
  if (!config.blockMalicious) return undefined;
  const conversationId = readString(input.conversation_id);
  const generationId = readString(input.generation_id);
  if (!conversationId || !generationId) return undefined;
  const decision = await deps.decisionConsumer(conversationId, generationId);
  if (!decision) return undefined;

  const enforceable = input.status === "completed" && readFiniteNumber(input.loop_count) === 0;
  const target: Target = {
    hookEventName: "stop",
    text: "",
    firewallHook: HookLabel.LLM_OUTPUT,
    evidenceHook: "llm_output",
    requestId: logicalRequestId(input, "cached-output"),
    sessionId: conversationId,
    generationId,
    metadata: buildMetadata(input, { source: "cached_output_decision" }),
    nativeCapability: "followup",
  };
  const result = cachedDecisionResult(decision);
  await emitEvidence(target, result, config, enforceable, env, deps.evidenceEmitter);
  debugClassification(env, target, result, enforceable, { decisionCacheConsumed: true });
  return enforceable ? { followup_message: SAFE_FOLLOWUP_MESSAGE } : undefined;
}

function buildBlockOutput(target: Target, input: HookRecord): HookOutput | undefined {
  switch (target.hookEventName) {
    case "beforeSubmitPrompt":
      return { continue: false, user_message: SAFE_BLOCK_MESSAGE };
    case "preToolUse":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE, agent_message: SAFE_BLOCK_MESSAGE };
    case "beforeReadFile":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    case "postToolUse":
      return target.nativeCapability === "replace_mcp"
        ? { updated_mcp_tool_output: { error: SAFE_BLOCK_MESSAGE }, additional_context: SAFE_BLOCK_MESSAGE }
        : undefined;
    case "subagentStart":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    case "subagentStop":
      return input.status === "completed" && readFiniteNumber(input.loop_count) === 0
        ? { followup_message: SAFE_FOLLOWUP_MESSAGE }
        : undefined;
    default:
      return undefined;
  }
}

function shouldNativeBlock(target: Target, result: ClassificationResult, config: RuntimeConfig, input: HookRecord): boolean {
  if (!config.blockMalicious || !isMalicious(result) || target.nativeCapability === "none") return false;
  if (target.nativeCapability === "followup") {
    return input.status === "completed" && readFiniteNumber(input.loop_count) === 0;
  }
  return true;
}

async function emitEvidence(
  target: Target,
  result: ClassificationResult,
  config: RuntimeConfig,
  nativeBlocked: boolean,
  env: RuntimeEnv,
  emitter: RuntimeDependencies["evidenceEmitter"],
): Promise<void> {
  const malicious = isMalicious(result);
  const policyDecision: LocalEvidenceInput["policyDecision"] = nativeBlocked
    ? "block"
    : malicious
      ? "monitor"
      : "allow";
  const nativeAction: LocalEvidenceInput["nativeAction"] = nativeBlocked
    ? target.nativeCapability === "replace_mcp" ? "content_replaced" : "block_returned"
    : "allowed";
  const event = buildLocalProtectionEvent({
    pluginName: PLUGIN_NAME,
    pluginVersion: PLUGIN_VERSION,
    hook: target.evidenceHook,
    mode: config.blockMalicious ? "block" : "shadow",
    requestId: target.requestId,
    ...(target.sessionId ? { sessionId: target.sessionId } : {}),
    ...(target.toolName ? { toolName: target.toolName } : {}),
    classification: result,
    policyDecision,
    nativeAction,
  });
  await Promise.resolve(emitter(event, env)).catch(() => undefined);
}

function buildSubagentTargets(input: HookRecord): Target[] {
  const segments = readCursorTranscriptSegments(readString(input.agent_transcript_path));
  const task = readString(input.task);
  const summary = readString(input.summary);
  if (task && !segments.some((segment) => segment.text === task)) {
    segments.unshift({ text: task, firewallHook: HookLabel.USER_INPUT, evidenceHook: "subagent", source: "subagent_task" });
  }
  if (summary && !segments.some((segment) => segment.text === summary)) {
    segments.push({ text: summary, firewallHook: HookLabel.LLM_OUTPUT, evidenceHook: "subagent", source: "subagent_summary" });
  }
  return segments.slice(-MAX_TRANSCRIPT_SEGMENTS).map((segment, index) => ({
    hookEventName: "subagentStop",
    text: segment.text,
    firewallHook: segment.firewallHook,
    evidenceHook: segment.evidenceHook,
    requestId: logicalRequestId(input, `subagent-${index}-${sha256(segment.text)}`),
    ...(readString(input.conversation_id) ? { sessionId: readString(input.conversation_id) as string } : {}),
    ...(readString(input.generation_id) ? { generationId: readString(input.generation_id) as string } : {}),
    ...(segment.toolName ? { toolName: segment.toolName } : {}),
    metadata: buildMetadata(input, { source: segment.source, transcriptSegmentIndex: index }),
    nativeCapability: "followup",
  }));
}

type TranscriptSegment = { text: string; firewallHook: string; evidenceHook: ProtectionHook; source: string; toolName?: string };

export function readCursorTranscriptSegments(transcriptPath: string | undefined): TranscriptSegment[] {
  if (!transcriptPath) return [];
  try {
    if (statSync(transcriptPath).size > MAX_TRANSCRIPT_BYTES) return [];
  } catch {
    return [];
  }
  let encoded: string;
  try {
    encoded = readFileSync(transcriptPath, "utf8");
  } catch {
    return [];
  }
  const segments: TranscriptSegment[] = [];
  const toolNames = new Map<string, string>();
  for (const line of encoded.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    const root = readRecord(parsed);
    const message = readRecord(root?.message) ?? root;
    if (!message) continue;
    const role = readString(message.role) ?? readString(root?.role);
    const content = message.content ?? root?.content;
    if (typeof content === "string" && content.trim()) {
      segments.push(messageSegment(content, role));
      continue;
    }
    if (!Array.isArray(content)) continue;
    for (const item of content) {
      const part = readRecord(item);
      if (!part) continue;
      const type = readString(part.type);
      if (type === "text") {
        const text = readString(part.text);
        if (text) segments.push(messageSegment(text, role));
      } else if (type === "thinking" || type === "reasoning") {
        const text = readString(part.thinking) ?? readString(part.text);
        if (text) segments.push({ text, firewallHook: HookLabel.LLM_OUTPUT, evidenceHook: "subagent", source: "reasoning" });
      } else if (type === "tool_use" || type === "tool_call") {
        const toolUseId = readString(part.id) ?? readString(part.tool_call_id);
        const toolName = readString(part.name) ?? readString(part.tool_name);
        if (toolUseId && toolName) toolNames.set(toolUseId, toolName);
        const text = stableStringify(part.input ?? part.arguments);
        if (text) segments.push({ text, firewallHook: HookLabel.TOOL_CALL, evidenceHook: "subagent", source: "tool_call", ...(toolName ? { toolName } : {}) });
      } else if (type === "tool_result") {
        const toolUseId = readString(part.tool_use_id) ?? readString(part.tool_call_id);
        const toolName = toolUseId ? toolNames.get(toolUseId) : undefined;
        const text = stableStringify(part.content ?? part.result);
        if (text) segments.push({ text, firewallHook: HookLabel.TOOL_RESPONSE, evidenceHook: "subagent", source: "tool_result", ...(toolName ? { toolName } : {}) });
      }
    }
  }
  return segments.slice(-MAX_TRANSCRIPT_SEGMENTS);
}

function messageSegment(text: string, role: string | undefined): TranscriptSegment {
  return role === "assistant"
    ? { text, firewallHook: HookLabel.LLM_OUTPUT, evidenceHook: "subagent", source: "message" }
    : { text, firewallHook: HookLabel.USER_INPUT, evidenceHook: "subagent", source: "message" };
}

function classifyOptions(target: Target): ClassifyOptions {
  return {
    hook: target.firewallHook,
    ...(target.toolName ? { toolName: target.toolName } : {}),
    metadata: target.metadata,
    requestId: target.requestId,
  };
}

function buildMetadata(input: HookRecord, extra: Record<string, unknown>): Record<string, unknown> {
  return omitUndefined({
    silmaril: { integration: PLUGIN_NAME, version: PLUGIN_VERSION },
    cursorHookEvent: readString(input.hook_event_name),
    conversationId: readString(input.conversation_id),
    generationId: readString(input.generation_id),
    toolUseId: readString(input.tool_use_id) ?? readString(input.tool_call_id),
    toolName: readString(input.tool_name),
    cursorVersion: readString(input.cursor_version),
    workspaceCount: Array.isArray(input.workspace_roots) ? input.workspace_roots.length : undefined,
    ...extra,
  });
}

function logicalRequestId(input: HookRecord, suffix: string): string {
  const runtimeMarker = readString(input.prompt)?.match(
    /\bsilmaril-runtime-check:[0-9a-f-]{36}\b/iu,
  )?.[0];
  if (runtimeMarker) return runtimeMarker;
  return `cursor-${sha256([
    readString(input.conversation_id) ?? "",
    readString(input.generation_id) ?? "",
    readString(input.hook_event_name) ?? "",
    readString(input.tool_use_id) ?? readString(input.tool_call_id) ?? "",
    suffix,
  ].join("\u0000"))}`;
}

function cachedDecisionResult(decision: CachedOutputDecision): ClassificationResult {
  return omitUndefined({
    prediction: decision.prediction,
    score: decision.score,
    threshold: decision.threshold,
    primaryOutcome: decision.primaryOutcome,
  });
}

function isMalicious(result: ClassificationResult): boolean {
  return result.prediction === "MALICIOUS";
}

function stableStringify(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(value, (_key, current) => {
      if (!current || typeof current !== "object") return current;
      if (seen.has(current)) return "[Circular]";
      seen.add(current);
      if (Array.isArray(current)) return current;
      return Object.fromEntries(Object.entries(current).sort(([left], [right]) => left.localeCompare(right)));
    }) ?? "";
  } catch {
    return "";
  }
}

function readTextOrSerialized(value: unknown): string {
  return typeof value === "string" ? value : stableStringify(value);
}

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value !== "string") return undefined;
  if (/^(?:1|true|yes|on)$/iu.test(value.trim())) return true;
  if (/^(?:0|false|no|off)$/iu.test(value.trim())) return false;
  return undefined;
}

function readRecord(value: unknown): HookRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as HookRecord : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function omitUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeErrorFields(error: unknown): Record<string, unknown> {
  return error instanceof Error ? { errorName: error.name, errorCode: readString((error as Error & { code?: unknown }).code) } : {};
}

function debugClassification(env: RuntimeEnv, target: Target, result: ClassificationResult, blocked: boolean, extra: Record<string, unknown> = {}): void {
  debugLog(env, "classification_result", {
    hookEventName: target.hookEventName,
    hook: target.firewallHook,
    toolName: target.toolName,
    prediction: result.prediction,
    blocked,
    ...extra,
  });
}

function debugLog(env: RuntimeEnv, event: string, fields: Record<string, unknown> = {}): void {
  if (!(parseBoolean(env.SILMARIL_DEBUG) ?? false)) return;
  process.stderr.write(`[silmaril] ${JSON.stringify(omitUndefined({ event, ...fields }))}\n`);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > MAX_STDIN_BYTES) throw new Error("Cursor hook input exceeds size limit");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  try {
    const encoded = await readStdin();
    if (!encoded.trim()) return;
    const output = await runCursorHook(JSON.parse(encoded));
    if (output) process.stdout.write(`${JSON.stringify(output)}\n`);
  } catch (error) {
    debugLog(process.env, "hook_error", safeErrorFields(error));
  }
}

function isMainModule(): boolean {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1] as string) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) await main();
