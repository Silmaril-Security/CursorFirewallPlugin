import { Firewall, HookLabel, type FirewallOptions } from "@silmaril-security/sdk";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
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
export const PLUGIN_VERSION = "0.2.5";
const MAX_STDIN_BYTES = 4 * 1024 * 1024;
const SAFE_BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content.";
const MAC_DEVICE_NAME_TIMEOUT_MS = 100;
const MAC_DEVICE_NAME_MAX_OUTPUT_BYTES = 1024;
const MAC_DEVICE_NAME_MAX_UTF16_UNITS = 256;
const MAC_DEVICE_NAME_CACHE_TTL_MS = 5 * 60 * 1000;
const MAC_DEVICE_NAME_FAILURE_RETRY_MS = 5 * 1000;
const MAC_DEVICE_NAME_CACHE_MAX_BYTES = 4096;
const MAC_DEVICE_NAME_CLEANUP_LIMIT = 128;
const MAC_DEVICE_NAME_MAX_EPOCH = 10_000_000_000;
const DEVICE_NAME_CACHE_GENERATION = /^cursor-device-name\.cache\.(0|[1-9][0-9]{0,15})$/;
const DEVICE_NAME_LOCK_GENERATION = /^cursor-device-name\.lock\.(0|[1-9][0-9]{0,15})$/;
const MAC_DEVICE_NAME_REFRESH_ARG = "--silmaril-refresh-device-name";
const MAC_DEVICE_NAME_LOCK_OWNER = /^[a-f0-9]{32}$/;
const MAC_DEVICE_NAME_FILE = "/usr/sbin/scutil";
const MAC_DEVICE_NAME_ARGS = ["--get", "ComputerName"] as const;
const MAC_DEVICE_NAME_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/;

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
  classify(text: string, options?: ClassifyOptions & { signal?: AbortSignal }): Promise<ClassificationResult>;
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
  nativeCapability: "none" | "deny" | "replace_mcp";
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
      // Leave time for native hook output within the host deadline.
      timeoutMs: Math.min(config.timeoutMs, 8000),
      ...(config.mode ? { mode: config.mode } : {}),
    });
    classified = await classifyTargets(firewall, targets, config.endpointId, AbortSignal.timeout(Math.min(config.timeoutMs, 8000)));
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
      const capability = parseMcpToolName(toolName ?? "", readString(input.mcp_server_name))
        ? "replace_mcp"
        : "none";
      return makeTarget(readTextOrSerialized(input.tool_output), HookLabel.TOOL_RESPONSE, "post_tool", capability);
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
  signal?: AbortSignal,
): Promise<Array<{ target: Target; result: ClassificationResult }>> {
  const [target] = targets;
  if (!target || targets.length !== 1) {
    throw new Error("Each Cursor hook event must produce exactly one classification target");
  }
  return [{
    target,
    result: await firewall.classify(target.text, { ...classifyOptions(target, endpointId), ...(signal ? { signal } : {}) }),
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
      return target.nativeCapability === "replace_mcp"
        ? {
            updated_mcp_tool_output: { error: SAFE_BLOCK_MESSAGE },
            additional_context: SAFE_BLOCK_MESSAGE,
          }
        : undefined;
    case "subagentStart":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    default:
      return undefined;
  }
}

function shouldNativeBlock(target: Target, result: ClassificationResult, config: RuntimeConfig, _input: HookRecord): boolean {
  return effectiveMode(result, config.mode) === "block"
    && isMalicious(result)
    && target.nativeCapability !== "none";
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
    ? target.nativeCapability === "replace_mcp" ? "content_replaced" : "block_returned"
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

type MacDeviceNameCommandInvocation = {
  file: string;
  args: readonly string[];
  timeoutMs: number;
  maxBuffer: number;
};

type MacDeviceNameCommand = (
  invocation: MacDeviceNameCommandInvocation,
) => string | Promise<string>;

type MacDeviceNameLookupDeps = {
  platform: NodeJS.Platform;
  now: () => number;
  command: MacDeviceNameCommand;
  homeDirectory: string;
  schedule: (owner: string, epoch: number) => void;
  closeFile: (fd: number) => void;
  refreshProgram?: string;
};

type MacDeviceNameLookupOverrides = {
  platform?: NodeJS.Platform;
  now?: () => number;
  command?: MacDeviceNameCommand;
  homeDirectory?: string;
  schedule?: (owner: string, epoch: number) => void;
  closeFile?: (fd: number) => void;
  refreshProgram?: string;
};

type DeviceNameCacheRecord = {
  v: 1;
  epoch?: number;
  name?: string;
  expiresAt?: number;
  retryAt?: number;
};

type DeviceNameLease = { owner: string; epoch: number };

type DeviceNameMemory =
  | { kind: "name"; value: string; expiresAt: number }
  | { kind: "retry"; retryAt: number };

function defaultMacDeviceNameCommand(invocation: MacDeviceNameCommandInvocation): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(invocation.file, [...invocation.args], {
      timeout: invocation.timeoutMs,
      maxBuffer: invocation.maxBuffer,
      encoding: "utf8",
      windowsHide: true,
    }, (error, stdout) => {
      if (error || typeof stdout !== "string") {
        reject(new Error("mac device name lookup failed"));
        return;
      }
      resolve(stdout);
    });
  });
}

function defaultScheduleMacDeviceNameRefresh(owner: string, epoch: number): void {
  if (!MAC_DEVICE_NAME_LOCK_OWNER.test(owner) || !validDeviceNameEpoch(epoch)) return;
  let child: ReturnType<typeof spawn>;
  try {
    child = spawn(
      macDeviceNameDeps.refreshProgram ?? process.execPath,
      [fileURLToPath(import.meta.url), MAC_DEVICE_NAME_REFRESH_ARG, owner, String(epoch)],
      {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
      },
    );
  } catch {
    // A refresh that cannot start must not delay classification.
    return;
  }
  // Spawn failures such as EMFILE are emitted asynchronously. Without this
  // listener the hook process treats them as an uncaught exception.
  child.on("error", () => undefined);
  try {
    child.unref();
  } catch {
    // Detaching the optional refresh must not affect classification.
  }
}

function normalizeMacDeviceName(output: string, maxOutputBytes: number): string | undefined {
  if (Buffer.byteLength(output, "utf8") > maxOutputBytes) {
    return undefined;
  }
  const name = output.trim();
  if (!name || name.length > MAC_DEVICE_NAME_MAX_UTF16_UNITS || MAC_DEVICE_NAME_CONTROL_CHARS.test(name)) {
    return undefined;
  }
  return name;
}

const defaultMacDeviceNameDeps: MacDeviceNameLookupDeps = {
  platform: process.platform,
  now: () => Date.now(),
  command: defaultMacDeviceNameCommand,
  homeDirectory: homedir(),
  schedule: defaultScheduleMacDeviceNameRefresh,
  closeFile: closeSync,
};

let macDeviceNameDeps: MacDeviceNameLookupDeps = { ...defaultMacDeviceNameDeps };
let macDeviceNameMemory: DeviceNameMemory | undefined;
let macDeviceNameRefresh: Promise<void> | undefined;
let macDeviceNameGeneration = 0;

export function setMacDeviceNameLookupForTests(overrides: MacDeviceNameLookupOverrides = {}): void {
  macDeviceNameGeneration += 1;
  macDeviceNameDeps = {
    platform: overrides.platform ?? process.platform,
    now: overrides.now ?? Date.now,
    command: overrides.command ?? defaultMacDeviceNameCommand,
    homeDirectory: overrides.homeDirectory ?? homedir(),
    schedule: overrides.schedule ?? defaultScheduleMacDeviceNameRefresh,
    closeFile: overrides.closeFile ?? closeSync,
    ...(overrides.refreshProgram ? { refreshProgram: overrides.refreshProgram } : {}),
  };
  macDeviceNameMemory = undefined;
  macDeviceNameRefresh = undefined;
}

export function flushMacDeviceNameRefreshForTests(): Promise<void> {
  return macDeviceNameRefresh ?? Promise.resolve();
}

export function refreshMacDeviceNameForTests(): Promise<void> {
  try {
    const lease = claimDeviceNameRefreshLease(macDeviceNameDeps.homeDirectory, macDeviceNameDeps.now());
    if (!lease) return Promise.resolve();
    return runMacDeviceNameRefreshForTests(lease.owner, lease.epoch);
  } catch {
    return Promise.resolve();
  }
}

export function runMacDeviceNameRefreshForTests(owner: string, epoch: number): Promise<void> {
  return refreshMacDeviceName(macDeviceNameGeneration, macDeviceNameDeps, owner, epoch);
}

function deviceNameStateDirectory(homeDirectory: string): string {
  return path.join(homeDirectory, "Library", "Application Support", "Silmaril");
}

function deviceNameCachePath(homeDirectory: string): string {
  return path.join(deviceNameStateDirectory(homeDirectory), "cursor-device-name.json");
}

function deviceNameEpochCachePath(homeDirectory: string, epoch: number): string {
  return path.join(deviceNameStateDirectory(homeDirectory), `cursor-device-name.cache.${epoch}`);
}

function deviceNameLockPath(homeDirectory: string, epoch: number): string {
  return path.join(deviceNameStateDirectory(homeDirectory), `cursor-device-name.lock.${epoch}`);
}

function validDeviceNameEpoch(epoch: number): boolean {
  return Number.isSafeInteger(epoch) && epoch >= 0 && epoch <= MAC_DEVICE_NAME_MAX_EPOCH;
}

function deviceNameEpoch(now: number): number | undefined {
  if (!Number.isFinite(now)) return undefined;
  const epoch = Math.floor(now / MAC_DEVICE_NAME_FAILURE_RETRY_MS);
  return validDeviceNameEpoch(epoch) ? epoch : undefined;
}

function loadDeviceNameCache(now: number): { name?: string; expiresAt?: number; retryAt?: number } {
  const records = deviceNameCacheCandidates(macDeviceNameDeps.homeDirectory, now);
  let selected: { name: string; expiresAt: number; epoch: number } | undefined;
  for (const record of records) {
    const name = freshCachedDeviceName(record, now);
    if (!name || typeof record.expiresAt !== "number") continue;
    const epoch = typeof record.epoch === "number" && Number.isFinite(record.epoch) ? record.epoch : -1;
    if (!selected || epoch >= selected.epoch) selected = { name, expiresAt: record.expiresAt, epoch };
  }
  if (selected) return { name: selected.name, expiresAt: selected.expiresAt };
  for (const record of records) {
    const retryAt = typeof record.retryAt === "number" && Number.isFinite(record.retryAt)
      ? record.retryAt
      : undefined;
    if (
      retryAt !== undefined
      && now < retryAt
      && retryAt - now <= MAC_DEVICE_NAME_FAILURE_RETRY_MS
    ) {
      return { retryAt };
    }
  }
  return {};
}

function deviceNameCacheCandidates(homeDirectory: string, now: number): DeviceNameCacheRecord[] {
  const records: DeviceNameCacheRecord[] = [];
  const epoch = deviceNameEpoch(now);
  if (epoch !== undefined) {
    for (const candidate of [epoch, epoch - 1]) {
      if (!validDeviceNameEpoch(candidate)) continue;
      const record = readDeviceNameEpochCache(homeDirectory, candidate);
      if (record) records.push(record);
    }
  }
  const shared = readDeviceNameCacheRecord(homeDirectory);
  if (shared) records.push(shared);
  return records;
}

function freshCachedDeviceName(record: DeviceNameCacheRecord, now: number): string | undefined {
  if (record.v !== 1) return undefined;
  const expiresAt = typeof record.expiresAt === "number" && Number.isFinite(record.expiresAt)
    ? record.expiresAt
    : undefined;
  const name = typeof record.name === "string"
    ? normalizeMacDeviceName(record.name, MAC_DEVICE_NAME_MAX_OUTPUT_BYTES)
    : undefined;
  if (
    name
    && expiresAt !== undefined
    && now < expiresAt
    && expiresAt - now <= MAC_DEVICE_NAME_CACHE_TTL_MS
  ) {
    return name;
  }
  return undefined;
}

function readDeviceNameCacheRecord(homeDirectory: string): DeviceNameCacheRecord | undefined {
  return readDeviceNameCacheObject(readBoundedDeviceNameJson(deviceNameCachePath(homeDirectory)));
}

function readDeviceNameEpochCache(homeDirectory: string, epoch: number): DeviceNameCacheRecord | undefined {
  if (!validDeviceNameEpoch(epoch)) return undefined;
  const record = readDeviceNameCacheObject(readBoundedDeviceNameJson(deviceNameEpochCachePath(homeDirectory, epoch)));
  if (!record || record.epoch !== epoch) return undefined;
  return record;
}

function readDeviceNameCacheObject(parsed: unknown): DeviceNameCacheRecord | undefined {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const record = parsed as DeviceNameCacheRecord;
  return record.v === 1 ? record : undefined;
}

function readBoundedDeviceNameJson(file: string): unknown {
  let fd: number | undefined;
  try {
    const linked = lstatSync(file);
    if (!linked.isFile() || linked.isSymbolicLink() || linked.size === 0 || linked.size > MAC_DEVICE_NAME_CACHE_MAX_BYTES) {
      return undefined;
    }
    fd = openSync(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAC_DEVICE_NAME_CACHE_MAX_BYTES) return undefined;
    const buffer = Buffer.alloc(stat.size);
    const bytesRead = readSync(fd, buffer, 0, stat.size, 0);
    return JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")) as unknown;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeOptionalDeviceNameFile(fd);
  }
}

function closeOptionalDeviceNameFile(fd: number): void {
  try {
    macDeviceNameDeps.closeFile(fd);
  } catch {
    // Closing the optional cache must not abort classification.
  }
}

function writeDeviceNameCacheFile(destination: string, record: DeviceNameCacheRecord): void {
  const directory = path.dirname(destination);
  const temporary = path.join(directory, `.${path.basename(destination)}.${process.pid}.tmp`);
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryStat = lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) return;
    chmodSync(directory, 0o700);
    const payload = JSON.stringify(record);
    if (Buffer.byteLength(payload) > MAC_DEVICE_NAME_CACHE_MAX_BYTES) return;
    writeFileSync(temporary, payload, { mode: 0o600, flag: "w" });
    chmodSync(temporary, 0o600);
    try {
      if (lstatSync(destination).isSymbolicLink()) unlinkSync(destination);
    } catch {
      // The cache file is absent.
    }
    renameSync(temporary, destination);
    chmodSync(destination, 0o600);
  } catch {
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file was not created.
    }
  }
}

function readDeviceNameLock(homeDirectory: string, epoch: number): DeviceNameLease | undefined {
  if (!validDeviceNameEpoch(epoch)) return undefined;
  const parsed = readBoundedDeviceNameJson(deviceNameLockPath(homeDirectory, epoch));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const record = parsed as Record<string, unknown>;
  const owner = typeof record.owner === "string" && MAC_DEVICE_NAME_LOCK_OWNER.test(record.owner)
    ? record.owner
    : undefined;
  if (record.v !== 1 || record.epoch !== epoch || !owner) return undefined;
  return { owner, epoch };
}

function deviceNameLeaseActive(homeDirectory: string, now: number): boolean {
  const epoch = deviceNameEpoch(now);
  return epoch !== undefined && readDeviceNameLock(homeDirectory, epoch) !== undefined;
}

function deviceNameLeaseHeldBy(homeDirectory: string, owner: string, epoch: number): boolean {
  return readDeviceNameLock(homeDirectory, epoch)?.owner === owner;
}

function claimDeviceNameRefreshLease(homeDirectory: string, now: number): DeviceNameLease | undefined {
  try {
    const epoch = deviceNameEpoch(now);
    if (epoch === undefined) return undefined;
    const directory = deviceNameStateDirectory(homeDirectory);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryStat = lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) return undefined;
    chmodSync(directory, 0o700);
    const owner = randomBytes(16).toString("hex");
    const payload = JSON.stringify({ v: 1, owner, epoch });
    const created = createExclusiveDeviceNameLock(deviceNameLockPath(homeDirectory, epoch), payload);
    return created === "created" ? { owner, epoch } : undefined;
  } catch {
    return undefined;
  }
}

function cleanupOlderDeviceNameGenerations(homeDirectory: string, epoch: number): void {
  try {
    const directory = deviceNameStateDirectory(homeDirectory);
    const linked = lstatSync(directory);
    if (!linked.isDirectory() || linked.isSymbolicLink()) return;
    const retired: { epoch: number; name: string }[] = [];
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const candidate = retiredDeviceNameGeneration(entry.name, epoch);
      if (candidate === undefined) continue;
      retired.push({ epoch: candidate, name: entry.name });
    }
    retired.sort((left, right) => left.epoch - right.epoch);
    for (const entry of retired.slice(0, MAC_DEVICE_NAME_CLEANUP_LIMIT)) {
      unlinkDeviceNameGeneration(path.join(directory, entry.name));
    }
  } catch {
    // Retaining an old name must not abort the refresh worker.
  }
}

function retiredDeviceNameGeneration(name: string, epoch: number): number | undefined {
  if (name === "cursor-device-name.lock") return -1;
  const cache = DEVICE_NAME_CACHE_GENERATION.exec(name);
  if (cache) {
    const candidate = canonicalDeviceNameEpoch(cache[1] ?? "");
    // The current bucket and the previous one are still readable.
    if (candidate === undefined || candidate >= epoch - 1) return undefined;
    return candidate;
  }
  const lock = DEVICE_NAME_LOCK_GENERATION.exec(name);
  if (!lock) return undefined;
  const candidate = canonicalDeviceNameEpoch(lock[1] ?? "");
  if (candidate === undefined || candidate >= epoch) return undefined;
  return candidate;
}

function canonicalDeviceNameEpoch(suffix: string): number | undefined {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(suffix)) return undefined;
  const epoch = Number(suffix);
  if (!validDeviceNameEpoch(epoch) || String(epoch) !== suffix) return undefined;
  return epoch;
}

function unlinkDeviceNameGeneration(file: string): void {
  try {
    const linked = lstatSync(file);
    if (linked.isDirectory() || (!linked.isFile() && !linked.isSymbolicLink())) return;
    unlinkSync(file);
  } catch {
    // This older generation is already gone or not removable.
  }
}

function createExclusiveDeviceNameLock(file: string, payload: string): "created" | "exists" | "failed" {
  let fd: number | undefined;
  try {
    fd = openSync(
      file,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const buffer = Buffer.from(payload);
    let offset = 0;
    while (offset < buffer.length) {
      const wrote = writeSync(fd, buffer, offset, buffer.length - offset);
      if (wrote <= 0) return "failed";
      offset += wrote;
    }
    return "created";
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? (error as { code?: unknown }).code
      : undefined;
    return code === "EEXIST" ? "exists" : "failed";
  } finally {
    if (fd !== undefined) closeOptionalDeviceNameFile(fd);
  }
}

function publishDeviceNameRecord(homeDirectory: string, epoch: number, record: DeviceNameCacheRecord): void {
  const stamped: DeviceNameCacheRecord = { ...record, v: 1, epoch };
  writeDeviceNameCacheFile(deviceNameEpochCachePath(homeDirectory, epoch), stamped);
  writeDeviceNameCacheFile(deviceNameCachePath(homeDirectory), stamped);
}

function newerDeviceNameIsPublished(homeDirectory: string, epoch: number, now: number): boolean {
  const shared = readDeviceNameCacheRecord(homeDirectory);
  if (
    shared
    && typeof shared.epoch === "number"
    && shared.epoch > epoch
    && freshCachedDeviceName(shared, now)
  ) {
    return true;
  }
  const nextEpoch = epoch + 1;
  if (!validDeviceNameEpoch(nextEpoch)) return false;
  const newer = readDeviceNameEpochCache(homeDirectory, nextEpoch);
  return Boolean(newer && freshCachedDeviceName(newer, now));
}

// Each Cursor event is a new process. A fresh per-user file supplies the last
// validated name without waiting on scutil. A cold or expired cache omits the
// name. One exclusive lock file per time bucket owns that refresh. The
// classification event only claims that lease. The detached worker later
// unlinks older generations. Lookup failures omit the name.
function readMacDeviceName(): string | undefined {
  try {
    if (macDeviceNameDeps.platform !== "darwin") return undefined;
    const now = macDeviceNameDeps.now();
    const fresh = rememberFreshDeviceName(now);
    if (fresh) return fresh;
    if (deviceNameRefreshPending(now)) return undefined;
    const lease = claimDeviceNameRefreshLease(macDeviceNameDeps.homeDirectory, macDeviceNameDeps.now());
    if (!lease) return undefined;
    const raced = rememberFreshDeviceName(macDeviceNameDeps.now());
    if (raced) return raced;
    const retryAt = macDeviceNameDeps.now() + MAC_DEVICE_NAME_FAILURE_RETRY_MS;
    macDeviceNameMemory = { kind: "retry", retryAt };
    if (!newerDeviceNameIsPublished(macDeviceNameDeps.homeDirectory, lease.epoch, macDeviceNameDeps.now())) {
      publishDeviceNameRecord(macDeviceNameDeps.homeDirectory, lease.epoch, { v: 1, retryAt });
    }
    startMacDeviceNameRefresh(lease.owner, lease.epoch);
    return undefined;
  } catch {
    return undefined;
  }
}

function rememberFreshDeviceName(now: number): string | undefined {
  const stored = loadDeviceNameCache(now);
  if (stored.name && stored.expiresAt !== undefined) {
    macDeviceNameMemory = { kind: "name", value: stored.name, expiresAt: stored.expiresAt };
    return stored.name;
  }
  if (macDeviceNameMemory?.kind === "name" && now < macDeviceNameMemory.expiresAt) {
    return macDeviceNameMemory.value;
  }
  return undefined;
}

function deviceNameRefreshPending(now: number): boolean {
  const stored = loadDeviceNameCache(now);
  const retryAt = stored.retryAt
    ?? (macDeviceNameMemory?.kind === "retry" ? macDeviceNameMemory.retryAt : undefined);
  return (retryAt !== undefined && now < retryAt)
    || Boolean(macDeviceNameRefresh)
    || deviceNameLeaseActive(macDeviceNameDeps.homeDirectory, now);
}

function startMacDeviceNameRefresh(owner: string, epoch: number): void {
  if (macDeviceNameRefresh) return;
  if (macDeviceNameDeps.command !== defaultMacDeviceNameCommand) {
    const generation = macDeviceNameGeneration;
    const deps = macDeviceNameDeps;
    macDeviceNameRefresh = refreshMacDeviceName(generation, deps, owner, epoch).finally(() => {
      if (generation === macDeviceNameGeneration) macDeviceNameRefresh = undefined;
    });
    return;
  }
  try {
    macDeviceNameDeps.schedule(owner, epoch);
  } catch {
    // Scheduling a refresh must not delay classification.
  }
}

async function refreshMacDeviceName(
  generation: number,
  deps: MacDeviceNameLookupDeps,
  owner: string,
  epoch: number,
): Promise<void> {
  try {
    if (!MAC_DEVICE_NAME_LOCK_OWNER.test(owner) || !validDeviceNameEpoch(epoch)) return;
    // A worker that starts after its bucket rolled must still delete older
    // generations. It must not publish a name or a failure for that bucket.
    cleanupOlderDeviceNameGenerations(deps.homeDirectory, epoch);
    if (!deviceNameLeaseHeldBy(deps.homeDirectory, owner, epoch) || deviceNameEpoch(deps.now()) !== epoch) return;
    let usable: string | undefined;
    try {
      const output = await deps.command({
        file: MAC_DEVICE_NAME_FILE,
        args: MAC_DEVICE_NAME_ARGS,
        timeoutMs: MAC_DEVICE_NAME_TIMEOUT_MS,
        maxBuffer: MAC_DEVICE_NAME_MAX_OUTPUT_BYTES,
      });
      usable = typeof output === "string"
        ? normalizeMacDeviceName(output, MAC_DEVICE_NAME_MAX_OUTPUT_BYTES)
        : undefined;
    } catch {
      usable = undefined;
    }
    if (generation !== macDeviceNameGeneration) return;
    commitDeviceNameRefresh(deps, owner, epoch, usable);
  } catch {
    // A refresh failure must not surface to classification.
  }
}

function commitDeviceNameRefresh(
  deps: MacDeviceNameLookupDeps,
  owner: string,
  epoch: number,
  usable: string | undefined,
): void {
  const finished = deps.now();
  // A bucket that has already ended must not publish. The next bucket has
  // its own lock file, and an older failure must not replace its name.
  if (deviceNameEpoch(finished) !== epoch) return;
  if (!deviceNameLeaseHeldBy(deps.homeDirectory, owner, epoch)) return;
  if (newerDeviceNameIsPublished(deps.homeDirectory, epoch, finished)) return;
  if (!usable) {
    if (freshCachedDeviceNameRecord(deps.homeDirectory, finished)) return;
    if (deviceNameEpoch(deps.now()) !== epoch) return;
    if (!deviceNameLeaseHeldBy(deps.homeDirectory, owner, epoch)) return;
    const retryAt = deps.now() + MAC_DEVICE_NAME_FAILURE_RETRY_MS;
    macDeviceNameMemory = { kind: "retry", retryAt };
    publishDeviceNameRecord(deps.homeDirectory, epoch, { v: 1, retryAt });
    return;
  }
  if (deviceNameEpoch(deps.now()) !== epoch || !deviceNameLeaseHeldBy(deps.homeDirectory, owner, epoch)) return;
  const expiresAt = deps.now() + MAC_DEVICE_NAME_CACHE_TTL_MS;
  macDeviceNameMemory = { kind: "name", value: usable, expiresAt };
  publishDeviceNameRecord(deps.homeDirectory, epoch, { v: 1, name: usable, expiresAt });
}

function freshCachedDeviceNameRecord(homeDirectory: string, now: number): boolean {
  return deviceNameCacheCandidates(homeDirectory, now).some((record) => freshCachedDeviceName(record, now) !== undefined);
}

function refreshLeaseArgument(argv: readonly string[]): DeviceNameLease | undefined {
  const index = argv.indexOf(MAC_DEVICE_NAME_REFRESH_ARG);
  const owner = index >= 0 ? argv[index + 1] : undefined;
  const epochText = index >= 0 ? argv[index + 2] : undefined;
  if (!owner || !MAC_DEVICE_NAME_LOCK_OWNER.test(owner) || !epochText || !/^[0-9]{1,15}$/.test(epochText)) {
    return undefined;
  }
  const epoch = Number(epochText);
  return validDeviceNameEpoch(epoch) ? { owner, epoch } : undefined;
}

export function withProvenance(
  metadata: Record<string, unknown>,
  endpointId?: string,
  governance?: GovernanceContext,
): Record<string, unknown> {
  const existingSilmaril = metadata.silmaril && typeof metadata.silmaril === "object" && !Array.isArray(metadata.silmaril)
    ? metadata.silmaril as Record<string, unknown>
    : {};
  const deviceName = readMacDeviceName();
  return {
    ...metadata,
    silmaril: {
      ...existingSilmaril,
      provenance: {
        schema_version: 1,
        ...(endpointId ? { endpoint_id: endpointId } : {}),
        harness: "cursor",
        ...(deviceName ? { device_name: deviceName } : {}),
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

if (isMainModule()) {
  if (process.argv.includes(MAC_DEVICE_NAME_REFRESH_ARG)) {
    const lease = refreshLeaseArgument(process.argv);
    if (lease) await refreshMacDeviceName(macDeviceNameGeneration, macDeviceNameDeps, lease.owner, lease.epoch);
  } else {
    await main();
  }
}
