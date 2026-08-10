import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

const MAX_EVENT_BYTES = 16 * 1024;
const MAX_SAFE_VALUE_LENGTH = 128;
const DEFAULT_DIRECTORY = ["Library", "Application Support", "Silmaril", "Evidence", "incoming"];

export type ProtectionHook = "user_input" | "pre_tool" | "post_tool" | "tool_result" | "llm_output" | "subagent" | "unknown";
export type ProtectionCategory = "credential_exposure" | "sensitive_data_exposure" | "code_execution" | "destructive_change" | "external_communication" | "privilege_change" | "unsafe_agent_control" | "other" | "unknown";

export type LocalProtectionEventV1 = {
  schemaVersion: 1;
  id: string;
  occurredAt: string;
  host: "cursor";
  hook: ProtectionHook;
  mode: "block" | "shadow";
  requestFingerprint?: string;
  sessionFingerprint?: string;
  toolDisplayName?: string;
  riskClass: ProtectionCategory;
  attemptedConsequence: { category: ProtectionCategory; summary: string };
  prediction: "benign" | "malicious" | "unknown" | "unavailable";
  modelScore?: number;
  modelThreshold?: number;
  policyDecision: "allow" | "monitor" | "block" | "unavailable";
  nativeAction: "none" | "allowed" | "block_returned" | "content_replaced" | "failed" | "unavailable";
  outcome: "not_observed";
  evidenceTruth: "plugin_reported" | "native_response_returned";
  evidenceCompleteness: "partial";
  provenance: {
    schemaVersion: 1;
    producer: string;
    producerVersion: string;
    pluginVersion: string;
    policyVersion: "cursor-plugin-policy-v1";
    observedAt: string;
  };
};

export type LocalEvidenceInput = {
  pluginName: string;
  pluginVersion: string;
  hook: ProtectionHook;
  mode: "block" | "shadow";
  requestId?: string;
  sessionId?: string;
  toolName?: string;
  classification: Record<string, unknown>;
  policyDecision: LocalProtectionEventV1["policyDecision"];
  nativeAction: LocalProtectionEventV1["nativeAction"];
  occurredAt?: Date;
};

const CONSEQUENCE_SUMMARIES: Record<ProtectionCategory, string> = {
  credential_exposure: "Potential credential exposure detected.",
  sensitive_data_exposure: "Potential sensitive-data exposure detected.",
  code_execution: "Potential unsafe code execution detected.",
  destructive_change: "Potential destructive change detected.",
  external_communication: "Potential unsafe external communication detected.",
  privilege_change: "Potential unsafe privilege change detected.",
  unsafe_agent_control: "Potential unsafe agent-control behavior detected.",
  other: "Potential harmful consequence detected.",
  unknown: "Potentially unsafe behavior detected.",
};

export function buildLocalProtectionEvent(input: LocalEvidenceInput): LocalProtectionEventV1 {
  const occurredAt = (input.occurredAt ?? new Date()).toISOString();
  const prediction = normalizePrediction(input.classification.prediction);
  const riskClass = normalizeCategory(input.classification.primaryOutcome ?? input.classification.primary_outcome);
  const event = {
    schemaVersion: 1,
    id: stableId("event", input.sessionId, input.requestId, occurredAt, randomUUID()),
    occurredAt,
    host: "cursor",
    hook: input.hook,
    mode: input.mode,
    requestFingerprint: fingerprint("request", input.requestId),
    sessionFingerprint: fingerprint("session", input.sessionId),
    toolDisplayName: safeToolName(input.toolName),
    riskClass,
    attemptedConsequence: { category: riskClass, summary: CONSEQUENCE_SUMMARIES[riskClass] },
    prediction,
    modelScore: unitInterval(input.classification.score),
    modelThreshold: unitInterval(input.classification.threshold),
    policyDecision: input.policyDecision,
    nativeAction: input.nativeAction,
    outcome: "not_observed",
    evidenceTruth: input.nativeAction === "block_returned" || input.nativeAction === "content_replaced"
      ? "native_response_returned"
      : "plugin_reported",
    evidenceCompleteness: "partial",
    provenance: {
      schemaVersion: 1,
      producer: bounded(input.pluginName) ?? "cursor-firewall-plugin",
      producerVersion: bounded(input.pluginVersion) ?? "unknown",
      pluginVersion: bounded(input.pluginVersion) ?? "unknown",
      policyVersion: "cursor-plugin-policy-v1",
      observedAt: occurredAt,
    },
  };
  return omitUndefined(event) as LocalProtectionEventV1;
}

export async function writeLocalProtectionEvent(
  event: LocalProtectionEventV1,
  env: Record<string, string | undefined> = process.env,
): Promise<string | undefined> {
  const directory = resolveLocalEventDirectory(env);
  const encoded = Buffer.from(`${JSON.stringify(event)}\n`, "utf8");
  if (encoded.byteLength > MAX_EVENT_BYTES) return undefined;

  const finalPath = path.join(directory, `event-${sha256(event.id)}.json`);
  const temporaryPath = path.join(directory, `.event-${sha256(event.id)}.${process.pid}.${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return undefined;
    await chmod(directory, 0o700);
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, finalPath);
    await chmod(finalPath, 0o600);
    return finalPath;
  } catch {
    await handle?.close().catch(() => undefined);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    return undefined;
  }
}

export function resolveLocalEventDirectory(env: Record<string, string | undefined> = process.env): string {
  const configured = env.SILMARIL_LOCAL_EVENT_DIR?.trim();
  if (configured) return configured;
  const configuredHome = env.HOME?.trim() || homedir();
  return path.join(configuredHome, ...DEFAULT_DIRECTORY);
}

function normalizePrediction(value: unknown): LocalProtectionEventV1["prediction"] {
  if (value === "MALICIOUS") return "malicious";
  if (value === "BENIGN") return "benign";
  if (value === undefined || value === null) return "unavailable";
  return "unknown";
}

function normalizeCategory(value: unknown): ProtectionCategory {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  const mapping: Record<string, ProtectionCategory> = {
    secret_exposure: "credential_exposure",
    credential_exposure: "credential_exposure",
    sensitive_data_exposure: "sensitive_data_exposure",
    data_exfiltration: "sensitive_data_exposure",
    code_execution: "code_execution",
    destructive_change: "destructive_change",
    destructive_action: "destructive_change",
    external_communication: "external_communication",
    privilege_change: "privilege_change",
    privilege_escalation: "privilege_change",
    unsafe_agent_control: "unsafe_agent_control",
  };
  return mapping[normalized] ?? (normalized ? "other" : "unknown");
}

function unitInterval(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? value : undefined;
}

function safeToolName(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || /(?:token|secret|password|api[_-]?key)\s*[:=]/iu.test(trimmed)) return undefined;
  return bounded(trimmed.replace(/[^A-Za-z0-9_.:/-]/gu, "_"));
}

function fingerprint(namespace: string, value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? sha256(`${namespace}:${value}`) : undefined;
}

function stableId(namespace: string, ...values: Array<string | undefined>): string {
  return `${namespace}-${sha256(values.filter(Boolean).join("\u0000"))}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function bounded(value: string, maxLength = MAX_SAFE_VALUE_LENGTH): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : undefined;
}

function omitUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}
