import { Firewall, HookLabel, type FirewallOptions } from "@silmaril-security/sdk";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  resolveRuntimeConfig,
  type RuntimeConfig,
  type RuntimeEnv,
  type FirewallMode,
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
export const PLUGIN_VERSION = "0.2.3";
const MAX_STDIN_BYTES = 4 * 1024 * 1024;
const SAFE_BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content.";

type ClassificationResult = Record<string, unknown>;
type GovernanceContext = {
  agent: "cursor";
  resource: {
    kind: "agent" | "tool" | "mcp_server" | "mcp_tool";
    id: string;
    parent_id?: string;
  };
};
type ClassifyOptions = { hook?: string; toolName?: string; metadata?: Record<string, unknown>; requestId?: string; mode?: FirewallMode };
type FirewallClient = {
  classify(text: string, options?: ClassifyOptions): Promise<ClassificationResult>;
};
type FirewallConstructor = new (options: FirewallOptions & { mode?: FirewallMode }) => FirewallClient;
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
  nativeCapability: "none" | "deny";
};

type RuntimeDependencies = {
  firewallConstructor: FirewallConstructor;
  evidenceEmitter: (event: LocalProtectionEventV1, env: RuntimeEnv) => Promise<unknown>;
};

const DEFAULT_DEPENDENCIES: RuntimeDependencies = {
  firewallConstructor: Firewall as unknown as FirewallConstructor,
  evidenceEmitter: writeLocalProtectionEvent,
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
    return undefined;
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
      ...(config.mode ? { mode: config.mode } : {}),
    });
    classified = await classifyTargets(firewall, targets, config.endpointId);
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
      return makeTarget(readTextOrSerialized(input.tool_output), HookLabel.TOOL_RESPONSE, "post_tool", "none");
    }
    case "postToolUseFailure":
      return makeTarget(readString(input.error_message), HookLabel.TOOL_RESPONSE, "post_tool", "none");
    case "afterAgentResponse":
      return makeTarget(readString(input.text), HookLabel.LLM_OUTPUT, "llm_output", "none");
    case "afterAgentThought":
      return makeTarget(readString(input.text), HookLabel.LLM_OUTPUT, "llm_output", "none", "0", undefined, undefined, { source: "reasoning" });
    case "subagentStart":
      return makeTarget(readString(input.task), HookLabel.USER_INPUT, "subagent", "deny", "0", "Task", readString(input.tool_call_id), { source: "subagent_task" });
    case "subagentStop":
      return makeTarget(readString(input.summary), HookLabel.LLM_OUTPUT, "subagent", "none", "0", undefined, undefined, { source: "subagent_summary" });
    default:
      return [];
  }
}

async function classifyTargets(
  firewall: FirewallClient,
  targets: Target[],
  endpointId?: string,
): Promise<Array<{ target: Target; result: ClassificationResult }>> {
  const [target] = targets;
  if (!target || targets.length !== 1) {
    throw new Error("Each Cursor hook event must produce exactly one classification target");
  }
  return [{
    target,
    result: await firewall.classify(target.text, classifyOptions(target, endpointId)),
  }];
}

async function handleAgentResponse(
  entry: { target: Target; result: ClassificationResult } | undefined,
  config: RuntimeConfig,
  env: RuntimeEnv,
  deps: RuntimeDependencies,
): Promise<undefined> {
  if (!entry) return undefined;
  const { target, result } = entry;
  const cached = false;
  await emitEvidence(target, result, config, false, env, deps.evidenceEmitter);
  debugClassification(env, target, result, false, { decisionCached: cached });
  return undefined;
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
      return undefined;
    case "subagentStart":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    default:
      return undefined;
  }
}

function shouldNativeBlock(target: Target, result: ClassificationResult, config: RuntimeConfig, _input: HookRecord): boolean {
  return effectiveMode(result, config.mode) === "block"
    && isMalicious(result)
    && target.nativeCapability === "deny";
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
  const mode = effectiveMode(result, config.mode);
  const policyDecision: LocalEvidenceInput["policyDecision"] = nativeBlocked
    ? "block"
    : malicious
      ? "monitor"
      : "allow";
  const nativeAction: LocalEvidenceInput["nativeAction"] = nativeBlocked
    ? "block_returned"
    : "allowed";
  const event = buildLocalProtectionEvent({
    pluginName: PLUGIN_NAME,
    pluginVersion: PLUGIN_VERSION,
    hook: target.evidenceHook,
    mode,
    requestId: target.requestId,
    ...(target.sessionId ? { sessionId: target.sessionId } : {}),
    ...(target.toolName ? { toolName: target.toolName } : {}),
    classification: result,
    policyDecision,
    nativeAction,
    ...(malicious && mode === "warn" ? { warnDelivery: "unsupported" } : {}),
    ...(malicious && mode === "block" && !nativeBlocked ? { blockUnavailable: true } : {}),
  });
  await Promise.resolve(emitter(event, env)).catch(() => undefined);
}

function classifyOptions(target: Target, endpointId?: string): ClassifyOptions {
  return {
    hook: target.firewallHook,
    ...(target.toolName ? { toolName: target.toolName } : {}),
    metadata: withProvenance(target.metadata, endpointId, governanceContext(target)),
    requestId: target.requestId,
  };
}

export function withProvenance(
  metadata: Record<string, unknown>,
  endpointId?: string,
  governance?: GovernanceContext,
): Record<string, unknown> {
  const existingSilmaril = metadata.silmaril && typeof metadata.silmaril === "object" && !Array.isArray(metadata.silmaril)
    ? metadata.silmaril as Record<string, unknown>
    : {};
  return {
    ...metadata,
    silmaril: {
      ...existingSilmaril,
      provenance: {
        schema_version: 1,
        ...(endpointId ? { endpoint_id: endpointId } : {}),
        harness: "cursor",
      },
      ...(governance ? { governance } : {}),
    },
  };
}

export function governanceContext(
  target: Pick<Target, "hookEventName" | "toolName" | "metadata">,
): GovernanceContext {
  if (
    target.hookEventName === "preToolUse"
    || target.hookEventName === "postToolUse"
    || target.hookEventName === "postToolUseFailure"
    || target.hookEventName === "beforeReadFile"
  ) {
    const toolName = target.toolName ?? "unknown";
    const mcp = parseMcpToolName(toolName, readString(target.metadata.mcpServerName));
    return {
      agent: "cursor",
      resource: mcp
        ? { kind: "mcp_tool", id: mcp.toolId, parent_id: mcp.serverId }
        : { kind: "tool", id: toolName },
    };
  }
  return {
    agent: "cursor",
    resource: { kind: "agent", id: "cursor" },
  };
}

function parseMcpToolName(
  toolName: string,
  explicitServer: string | undefined,
): { serverId: string; toolId: string } | undefined {
  if (explicitServer) {
    return { serverId: explicitServer, toolId: toolName };
  }
  const canonical = /^mcp__(.+?)__(.+)$/.exec(toolName);
  if (canonical?.[1] && canonical[2]) {
    return { serverId: canonical[1], toolId: canonical[2] };
  }
  const cursor = /^MCP:([^:]+):(.+)$/.exec(toolName);
  return cursor?.[1] && cursor[2]
    ? { serverId: cursor[1], toolId: cursor[2] }
    : undefined;
}

function buildMetadata(input: HookRecord, extra: Record<string, unknown>): Record<string, unknown> {
  return omitUndefined({
    silmaril: { integration: PLUGIN_NAME, version: PLUGIN_VERSION },
    cursorHookEvent: readString(input.hook_event_name),
    conversationId: readString(input.conversation_id),
    generationId: readString(input.generation_id),
    toolUseId: readString(input.tool_use_id) ?? readString(input.tool_call_id),
    toolName: readString(input.tool_name),
    mcpServerName: readString(input.mcp_server_name),
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

export function effectiveMode(
  result: ClassificationResult,
  requestedMode?: FirewallMode,
): FirewallMode {
  // A supplied mode is the per-request pilot override. Keep it authoritative
  // across legacy or mixed-version backend responses.
  const returned = result.mode;
  if (requestedMode) return requestedMode;
  return returned === "shadow" || returned === "warn" || returned === "block" ? returned : "shadow";
}

function isMalicious(result: ClassificationResult): boolean {
  return result.prediction === "MALICIOUS"
    || readRecord(result.governance)?.action === "block";
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
