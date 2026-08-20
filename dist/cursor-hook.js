// node_modules/@silmaril-security/sdk/dist/index.js
import { randomUUID } from "crypto";
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
function parseErrorBody(body) {
  try {
    const parsed = JSON.parse(body);
    if (!parsed || typeof parsed !== "object") {
      return { details: void 0, error: void 0, apiMessage: void 0 };
    }
    const data = parsed;
    return {
      details: data.details && typeof data.details === "object" ? data.details : void 0,
      error: typeof data.error === "string" ? data.error : void 0,
      apiMessage: typeof data.message === "string" ? data.message : void 0
    };
  } catch {
    return { details: void 0, error: void 0, apiMessage: void 0 };
  }
}
var MAX_PROMPT_DISPLAY_LEN;
var FirewallBlockedException;
var PromptBlockedException;
var SilmarilApiError;
var init_exceptions = __esm({
  "src/exceptions.ts"() {
    "use strict";
    MAX_PROMPT_DISPLAY_LEN = 100;
    FirewallBlockedException = class _FirewallBlockedException extends Error {
      score;
      threshold;
      promptText;
      runId;
      hook;
      toolName;
      toolCallId;
      result;
      constructor(params) {
        super(_FirewallBlockedException.formatMessage(params));
        this.name = "FirewallBlockedException";
        this.score = params.score;
        this.threshold = params.threshold;
        this.promptText = params.promptText;
        this.runId = params.runId;
        this.hook = params.hook;
        this.toolName = params.toolName;
        this.toolCallId = params.toolCallId;
        this.result = params.result;
        Object.setPrototypeOf(this, _FirewallBlockedException.prototype);
      }
      static formatMessage(params) {
        const truncated = params.promptText.length > MAX_PROMPT_DISPLAY_LEN ? `${params.promptText.slice(0, MAX_PROMPT_DISPLAY_LEN)}...` : params.promptText;
        return `Request blocked by Silmaril Firewall (score=${params.score.toFixed(4)}, threshold=${params.threshold.toFixed(4)}): '${truncated}'`;
      }
    };
    PromptBlockedException = FirewallBlockedException;
    SilmarilApiError = class _SilmarilApiError extends Error {
      status;
      statusText;
      body;
      details;
      error;
      apiMessage;
      constructor(params) {
        const statusText = params.statusText ? ` ${params.statusText}` : "";
        super(`Silmaril API error ${params.status}${statusText}`);
        this.name = "SilmarilApiError";
        this.status = params.status;
        this.statusText = params.statusText;
        this.body = params.body;
        const parsed = parseErrorBody(params.body);
        this.details = params.details ?? parsed.details;
        this.error = params.error ?? parsed.error;
        this.apiMessage = params.apiMessage ?? parsed.apiMessage;
        Object.setPrototypeOf(this, _SilmarilApiError.prototype);
      }
    };
  }
});
function resolveHooks(hooks) {
  if (hooks === void 0) {
    return DEFAULT_HOOKS;
  }
  const resolved = /* @__PURE__ */ new Set();
  for (const h of hooks) {
    if (!FIREWALL_HOOK_VALUES.has(h)) {
      throw new Error(`Invalid FirewallHook value: ${String(h)}`);
    }
    resolved.add(h);
  }
  return resolved;
}
var HookLabel;
var FirewallHook;
var DEFAULT_HOOKS;
var INPUT_HOOKS;
var OUTPUT_HOOKS;
var ALL_HOOKS;
var FIREWALL_HOOK_TO_LABEL;
var FIREWALL_HOOK_VALUES;
var init_hooks = __esm({
  "src/hooks.ts"() {
    "use strict";
    HookLabel = {
      USER_INPUT: "user_input",
      SYSTEM_PROMPT: "system_prompt",
      TOOL_CALL: "tool_call",
      TOOL_RESPONSE: "tool_response",
      LLM_OUTPUT: "llm_output",
      UNKNOWN: "unknown"
    };
    FirewallHook = {
      LLM_START: "on_llm_start",
      CHAT_MODEL_START: "on_chat_model_start",
      TOOL_START: "on_tool_start",
      RETRIEVER_START: "on_retriever_start",
      LLM_END: "on_llm_end",
      TOOL_END: "on_tool_end",
      RETRIEVER_END: "on_retriever_end"
    };
    DEFAULT_HOOKS = /* @__PURE__ */ new Set([
      FirewallHook.LLM_START,
      FirewallHook.CHAT_MODEL_START
    ]);
    INPUT_HOOKS = /* @__PURE__ */ new Set([
      FirewallHook.LLM_START,
      FirewallHook.CHAT_MODEL_START,
      FirewallHook.TOOL_START,
      FirewallHook.RETRIEVER_START
    ]);
    OUTPUT_HOOKS = /* @__PURE__ */ new Set([
      FirewallHook.LLM_END,
      FirewallHook.TOOL_END,
      FirewallHook.RETRIEVER_END
    ]);
    ALL_HOOKS = /* @__PURE__ */ new Set([
      ...INPUT_HOOKS,
      ...OUTPUT_HOOKS
    ]);
    FIREWALL_HOOK_TO_LABEL = {
      [FirewallHook.CHAT_MODEL_START]: HookLabel.USER_INPUT,
      [FirewallHook.LLM_START]: HookLabel.USER_INPUT,
      [FirewallHook.TOOL_START]: HookLabel.TOOL_CALL,
      [FirewallHook.TOOL_END]: HookLabel.TOOL_RESPONSE,
      [FirewallHook.RETRIEVER_START]: HookLabel.TOOL_CALL,
      [FirewallHook.RETRIEVER_END]: HookLabel.TOOL_RESPONSE,
      [FirewallHook.LLM_END]: HookLabel.LLM_OUTPUT
    };
    FIREWALL_HOOK_VALUES = new Set(Object.values(FirewallHook));
  }
});
function extractTextFromPrompts(prompts) {
  return prompts.map((p) => p.trim()).filter((p) => p.length > 0).join("\n");
}
function extractTextFromToolInput(inputStr) {
  return inputStr.trim();
}
function extractTextFromLLMResult(response) {
  const parts = [];
  for (const genList of response.generations ?? []) {
    for (const gen of genList) {
      const text = (gen.text ?? "").trim();
      if (text) {
        parts.push(text);
      }
    }
  }
  return parts.join("\n");
}
function extractTextFromDocuments(documents) {
  const parts = [];
  for (const doc of documents) {
    const text = (doc.pageContent ?? "").trim();
    if (text) {
      parts.push(text);
    }
  }
  return parts.join("\n");
}
var init_extract = __esm({
  "src/utils/extract.ts"() {
    "use strict";
  }
});
var langchain_exports = {};
__export(langchain_exports, {
  createLangChainHandler: () => createLangChainHandler
});
function getMessageRole(message) {
  if (typeof message.role === "string") {
    return message.role.toLowerCase();
  }
  if (typeof message.type === "string") {
    return message.type.toLowerCase();
  }
  return "";
}
function extractMessageText(content) {
  if (content === void 0) {
    return "";
  }
  if (typeof content === "string") {
    return content;
  }
  const parts = [];
  for (const block of content) {
    if (typeof block === "string") {
      parts.push(block);
    } else if (block && block.type === "text") {
      parts.push(block.text ?? "");
    }
  }
  return parts.join(" ");
}
function findLastUserMessage2(messages) {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (USER_ROLES.has(getMessageRole(msg))) {
      return msg;
    }
  }
  return void 0;
}
async function createLangChainHandler(firewall, options = {}) {
  const { BaseCallbackHandler } = await import("@langchain/core/callbacks/base");
  const enabledHooks = resolveHooks(options.hooks);
  const failOpen = options.failOpen ?? true;
  const logger = options.logger ?? ((message, error) => {
    console.warn(`silmaril.firewall: ${message}`, error);
  });
  const shadowMode = options.shadowMode ?? firewall.shadowMode;
  const onClassify = options.onClassify;
  const fireOnClassify = (event) => {
    if (!onClassify) {
      return;
    }
    try {
      onClassify(event);
    } catch (err) {
      logger("onClassify callback threw", err);
    }
  };
  const classify = async (text, hookLabel, runId, toolName) => {
    let result;
    try {
      result = await firewall.classify(text, {
        hook: hookLabel,
        ...toolName !== void 0 ? { toolName } : {}
      });
    } catch (err) {
      if (!failOpen) {
        throw err;
      }
      logger("classification failed, allowing prompt through", err);
      return;
    }
    const threshold = result.threshold;
    const blocked = result.prediction === "MALICIOUS";
    const commonEventFields = {
      hook: hookLabel,
      ...toolName !== void 0 ? { toolName } : {},
      runId,
      text,
      result
    };
    fireOnClassify({
      ...commonEventFields,
      blocked,
      shadowMode
    });
    if (!blocked || shadowMode) {
      return;
    }
    throw new FirewallBlockedException({
      score: result.score,
      threshold,
      promptText: text,
      runId,
      hook: hookLabel,
      ...toolName !== void 0 ? { toolName } : {},
      result
    });
  };
  class SilmarilFirewallHandler extends BaseCallbackHandler {
    name = "silmaril_firewall_handler";
    raiseError = true;
    awaitHandlers = true;
    async handleChatModelStart(_llm, messages, runId) {
      if (!enabledHooks.has(FirewallHook.CHAT_MODEL_START)) {
        return;
      }
      const batches = messages;
      const flat = [];
      for (const batch of batches) {
        for (const m of batch) {
          flat.push(m);
        }
      }
      const lastUser = findLastUserMessage2(flat);
      if (!lastUser) {
        return;
      }
      const text = extractMessageText(lastUser.content).trim();
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.CHAT_MODEL_START], runId);
    }
    async handleLLMStart(_llm, prompts, runId) {
      if (!enabledHooks.has(FirewallHook.LLM_START)) {
        return;
      }
      const text = extractTextFromPrompts(prompts);
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_START], runId);
    }
    async handleToolStart(tool, inputStr, runId) {
      if (!enabledHooks.has(FirewallHook.TOOL_START)) {
        return;
      }
      const text = extractTextFromToolInput(inputStr);
      if (!text) {
        return;
      }
      const toolName = tool?.name;
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_START], runId, toolName);
    }
    async handleRetrieverStart(_retriever, query, runId) {
      if (!enabledHooks.has(FirewallHook.RETRIEVER_START)) {
        return;
      }
      const text = query.trim();
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_START], runId);
    }
    async handleLLMEnd(output, runId) {
      if (!enabledHooks.has(FirewallHook.LLM_END)) {
        return;
      }
      const text = extractTextFromLLMResult(output);
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.LLM_END], runId);
    }
    async handleToolEnd(output, runId, _parentRunId, _tags, _kwargs) {
      if (!enabledHooks.has(FirewallHook.TOOL_END)) {
        return;
      }
      const text = String(output).trim();
      if (!text) {
        return;
      }
      const toolName = _kwargs?.name;
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.TOOL_END], runId, toolName);
    }
    async handleRetrieverEnd(documents, runId) {
      if (!enabledHooks.has(FirewallHook.RETRIEVER_END)) {
        return;
      }
      const text = extractTextFromDocuments(documents);
      if (!text) {
        return;
      }
      await classify(text, FIREWALL_HOOK_TO_LABEL[FirewallHook.RETRIEVER_END], runId);
    }
  }
  return new SilmarilFirewallHandler();
}
var USER_ROLES;
var init_langchain = __esm({
  "src/adapters/langchain.ts"() {
    "use strict";
    init_exceptions();
    init_hooks();
    init_extract();
    USER_ROLES = /* @__PURE__ */ new Set(["human", "user"]);
  }
});
init_exceptions();
init_hooks();
function stringifyToolValue(value) {
  if (value === null || value === void 0) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function extractContentText(content) {
  if (typeof content === "string") {
    return content;
  }
  const parts = [];
  for (const block of content) {
    if (typeof block === "string") {
      parts.push(block);
    } else if (block && block.type === "text") {
      parts.push(block.text ?? "");
    }
  }
  return parts.join(" ");
}
function iterateToolResultParts(message) {
  if (typeof message.content === "string") {
    return [];
  }
  const out = [];
  for (const part of message.content) {
    if (typeof part === "string") {
      continue;
    }
    if (part.type === "tool-result") {
      const text = stringifyToolResult(part.result !== void 0 ? part.result : part.output);
      if (text.trim()) {
        out.push({ text, toolName: part.toolName, toolCallId: part.toolCallId });
      }
    }
  }
  return out;
}
function stringifyToolResult(value) {
  if (!isRecord(value)) {
    return stringifyToolValue(value);
  }
  if ((value.type === "text" || value.type === "error-text") && typeof value.value === "string") {
    return value.value;
  }
  if ((value.type === "json" || value.type === "error-json") && value.value !== void 0) {
    return stringifyToolValue(value.value);
  }
  if (value.type === "content" && Array.isArray(value.value)) {
    return value.value.map((part) => isRecord(part) && part.type === "text" && typeof part.text === "string" ? part.text : "").filter((text) => text.length > 0).join(" ");
  }
  return stringifyToolValue(value);
}
function findLastUserMessage(messages) {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role.toLowerCase() === "user") {
      return msg;
    }
  }
  return void 0;
}
function createMiddleware(firewall, options = {}) {
  const scanInput = options.scanInput ?? true;
  const scanOutput = options.scanOutput ?? false;
  const shadowMode = options.shadowMode ?? firewall.shadowMode;
  const classifyOrBlock = async (text, hook, context = { toolName: void 0, toolCallId: void 0 }) => {
    if (!text.trim()) {
      return;
    }
    const { toolName, toolCallId } = context;
    const result = await firewall.classify(
      text,
      toolName !== void 0 ? { hook, toolName } : { hook }
    );
    const threshold = result.threshold;
    const blocked = result.prediction === "MALICIOUS";
    const commonEventFields = {
      hook,
      ...toolName !== void 0 ? { toolName } : {},
      ...toolCallId !== void 0 ? { toolCallId } : {},
      text,
      result
    };
    options.onClassify?.({
      ...commonEventFields,
      blocked,
      shadowMode
    });
    if (!blocked || shadowMode) {
      return;
    }
    const err = new FirewallBlockedException({
      score: result.score,
      threshold,
      promptText: text,
      hook,
      ...toolName !== void 0 ? { toolName } : {},
      ...toolCallId !== void 0 ? { toolCallId } : {},
      result
    });
    options.onBlocked?.(err);
    throw err;
  };
  const scanPrompt = async (prompt) => {
    if (prompt.length === 0) {
      return;
    }
    const last = prompt[prompt.length - 1];
    const role = last.role.toLowerCase();
    if (role === "tool") {
      for (const { text: text2, toolName, toolCallId } of iterateToolResultParts(last)) {
        await classifyOrBlock(text2, HookLabel.TOOL_RESPONSE, { toolName, toolCallId });
      }
      return;
    }
    const lastUser = findLastUserMessage(prompt);
    if (!lastUser) {
      return;
    }
    const text = extractContentText(lastUser.content).trim();
    if (!text) {
      return;
    }
    await classifyOrBlock(text, HookLabel.USER_INPUT);
  };
  const scanGenerateResult = async (result) => {
    if (scanOutput && typeof result.text === "string" && result.text.length > 0) {
      await classifyOrBlock(result.text, HookLabel.LLM_OUTPUT);
    }
    if (options.scanToolCalls && Array.isArray(result.toolCalls)) {
      for (const call of result.toolCalls) {
        if (!call || typeof call !== "object") {
          continue;
        }
        const toolInput = call.args !== void 0 ? call.args : call.input;
        const args = typeof toolInput === "string" ? toolInput : stringifyToolValue(toolInput);
        const toolName = typeof call.toolName === "string" ? call.toolName : void 0;
        const toolCallId = typeof call.toolCallId === "string" ? call.toolCallId : void 0;
        if (args.trim()) {
          await classifyOrBlock(args, HookLabel.TOOL_CALL, { toolName, toolCallId });
        }
      }
    }
  };
  return {
    specificationVersion: "v3",
    middlewareVersion: "v2",
    async wrapGenerate({
      params,
      doGenerate
    }) {
      if (scanInput) {
        await scanPrompt(params.prompt ?? []);
      }
      const result = await doGenerate();
      await scanGenerateResult(result);
      return result;
    },
    async wrapStream({
      params,
      doStream
    }) {
      if (scanInput) {
        await scanPrompt(params.prompt ?? []);
      }
      const { stream, ...rest } = await doStream();
      if (!scanOutput) {
        return { stream, ...rest };
      }
      let buffered = "";
      const transformed = stream.pipeThrough(
        new TransformStream({
          transform(chunk, controller) {
            const part = chunk;
            if (part && part.type === "text-delta") {
              const delta = part.textDelta ?? part.delta ?? "";
              buffered += delta;
            }
            controller.enqueue(chunk);
          },
          async flush(controller) {
            if (!buffered.trim()) {
              return;
            }
            try {
              await classifyOrBlock(buffered, HookLabel.LLM_OUTPUT);
            } catch (err) {
              if (err instanceof FirewallBlockedException) {
                controller.enqueue({ type: "error", error: err });
                return;
              }
              throw err;
            }
          }
        })
      );
      return { stream: transformed, ...rest };
    }
  };
}
init_exceptions();
var Outcome = {
  Benign: "benign",
  InformationDisclosure: "information_disclosure",
  SecretExposure: "secret_exposure",
  ControlAbuse: "control_abuse",
  SystemCompromise: "system_compromise",
  ServiceDisruption: "service_disruption"
};
var PRIMARY_OUTCOMES = [
  Outcome.Benign,
  Outcome.InformationDisclosure,
  Outcome.SecretExposure,
  Outcome.ControlAbuse,
  Outcome.SystemCompromise,
  Outcome.ServiceDisruption
];
var HARMFUL_OUTCOMES = [
  Outcome.InformationDisclosure,
  Outcome.SecretExposure,
  Outcome.ControlAbuse,
  Outcome.SystemCompromise,
  Outcome.ServiceDisruption
];
var OUTCOME_DESCRIPTIONS = {
  [Outcome.Benign]: "No harmful firewall outcome detected.",
  [Outcome.InformationDisclosure]: "Exposes private data, documents, internal context, logs, traces, customer data, SQL rows, topology, or similar non-secret sensitive information.",
  [Outcome.SecretExposure]: "Exposes credentials, tokens, API keys, cookies, passwords, signing keys, OAuth secrets, session material, or webhook secrets.",
  [Outcome.ControlAbuse]: "Misuses authorized tools or user privileges to send, change, approve, delete, operate, or bypass policy/RBAC without a stronger outcome.",
  [Outcome.SystemCompromise]: "Enables privilege escalation, account takeover, hostile integration or plugin takeover, persistence, lateral movement, attacker webhook registration, or code/plugin execution.",
  [Outcome.ServiceDisruption]: "Causes downtime, lockout, degradation, alert suppression, destructive loops, resource exhaustion, cost spikes, or hidden outage evidence."
};
var PRIMARY_OUTCOME_SET = new Set(PRIMARY_OUTCOMES);
var HARMFUL_OUTCOME_SET = new Set(HARMFUL_OUTCOMES);
function isPrimaryOutcome(value) {
  return typeof value === "string" && PRIMARY_OUTCOME_SET.has(value);
}
function isHarmfulOutcome(value) {
  return typeof value === "string" && HARMFUL_OUTCOME_SET.has(value);
}
function normalizePrimaryOutcome(value, fieldName = "primary_outcome") {
  if (typeof value !== "string") {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return isPrimaryOutcome(value) ? value : value;
}
function normalizeHarmfulOutcome(value, fieldName = "outcome") {
  if (typeof value !== "string" || value === Outcome.Benign) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(value)}`);
  }
  return isHarmfulOutcome(value) ? value : value;
}
function normalizeHarmfulOutcomeMap(values, fieldName) {
  if (values === void 0 || values === null) {
    return void 0;
  }
  if (typeof values !== "object" || Array.isArray(values)) {
    throw new Error(`Firewall: invalid ${fieldName} ${JSON.stringify(values)}`);
  }
  const out = {};
  for (const [key, value] of Object.entries(values)) {
    const normalizedKey = normalizeHarmfulOutcome(key, `${fieldName} key`);
    if (typeof value !== "number") {
      throw new Error(`Firewall: invalid ${fieldName} value for ${JSON.stringify(key)}`);
    }
    out[normalizedKey] = value;
  }
  return Object.freeze(out);
}
function isHighSurrogate(code) {
  return code >= 55296 && code <= 56319;
}
function isLowSurrogate(code) {
  return code >= 56320 && code <= 57343;
}
function sanitizeText(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (isHighSurrogate(code)) {
      if (i + 1 < text.length && isLowSurrogate(text.charCodeAt(i + 1))) {
        out += text[i];
        out += text[i + 1];
        i++;
      }
      continue;
    }
    if (!isLowSurrogate(code)) {
      out += text[i];
    }
  }
  return out;
}
var SDK_VERSION = "0.5.0";
var DEFAULT_TIMEOUT_MS = 1e4;
var DEFAULT_MAX_RETRIES = 5;
var MAX_BACKOFF_SECONDS = 30;
var MAX_ERROR_BODY_BYTES = 1 << 16;
function blockResultFromResponse(data) {
  if (data.prediction !== "BENIGN" && data.prediction !== "MALICIOUS") {
    throw new Error("Firewall: response prediction must be BENIGN or MALICIOUS");
  }
  const result = {
    prediction: data.prediction,
    score: Number(data.score),
    threshold: Number(data.threshold)
  };
  if (data.primary_outcome !== void 0) {
    result.primaryOutcome = normalizePrimaryOutcome(data.primary_outcome);
  }
  if (data.outcome_scores !== void 0) {
    const outcomeScores = normalizeHarmfulOutcomeMap(data.outcome_scores, "outcome_scores");
    if (outcomeScores !== void 0) {
      result.outcomeScores = outcomeScores;
    }
  }
  if (data.detector_scores !== void 0) {
    const detectorScores = normalizeHarmfulOutcomeMap(data.detector_scores, "detector_scores");
    if (detectorScores !== void 0) {
      result.detectorScores = detectorScores;
    }
  }
  if (data.detector_counts !== void 0) {
    const detectorCounts = normalizeHarmfulOutcomeMap(data.detector_counts, "detector_counts");
    if (detectorCounts !== void 0) {
      result.detectorCounts = detectorCounts;
    }
  }
  return Object.freeze(result);
}
function isRecord2(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function withSdkMetadata(metadata, info) {
  const payload = { ...metadata ?? {} };
  const existing = payload.silmaril;
  if (existing !== void 0 && !isRecord2(existing)) {
    throw new Error("Firewall: metadata.silmaril must be an object when provided");
  }
  payload.silmaril = {
    ...isRecord2(existing) ? existing : {},
    sdk_language: "typescript",
    sdk_version: SDK_VERSION,
    request_id: info.requestId,
    ...info.inputIndex === void 0 ? {} : { input_index: info.inputIndex }
  };
  return payload;
}
async function readCappedErrorBody(response) {
  if (!response.body) {
    return response.text().then((body2) => body2.slice(0, MAX_ERROR_BODY_BYTES)).catch(() => "");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let remaining = MAX_ERROR_BODY_BYTES;
  try {
    while (remaining > 0) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
      chunks.push(chunk);
      remaining -= chunk.byteLength;
      if (chunk.byteLength < value.byteLength) {
        break;
      }
    }
  } catch {
    return "";
  } finally {
    await reader.cancel().catch(() => void 0);
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}
var Firewall = class {
  apiKey;
  apiUrl;
  timeoutMs;
  shadowMode;
  headers;
  constructor(options) {
    if (!options.apiKey) {
      throw new Error("Firewall: apiKey is required");
    }
    if (!options.apiUrl) {
      throw new Error("Firewall: apiUrl is required");
    }
    this.apiKey = options.apiKey;
    this.apiUrl = options.apiUrl;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (typeof this.timeoutMs !== "number" || !Number.isFinite(this.timeoutMs) || this.timeoutMs < 0) {
      throw new Error(`Firewall: timeoutMs must be a finite non-negative number, got ${this.timeoutMs}`);
    }
    this.shadowMode = options.shadowMode ?? false;
    this.headers = Object.freeze({
      "x-api-key": this.apiKey,
      "content-type": "application/json"
    });
  }
  async classify(text, options = {}) {
    const requestId = options.requestId ?? randomUUID();
    return this.classifySingle(sanitizeText(text), options, { requestId });
  }
  async classifyBatch(texts, options = {}) {
    if (texts.length === 0) {
      throw new Error("Firewall: texts must not be empty");
    }
    if (options.hooks !== void 0 && options.hooks.length !== texts.length) {
      throw new Error(
        `Firewall: hooks length ${options.hooks.length} does not match texts length ${texts.length}`
      );
    }
    if (options.toolNames !== void 0 && options.toolNames.length !== texts.length) {
      throw new Error(
        `Firewall: toolNames length ${options.toolNames.length} does not match texts length ${texts.length}`
      );
    }
    if (options.metadata !== void 0 && options.metadata.length !== texts.length) {
      throw new Error(
        `Firewall: metadata length ${options.metadata.length} does not match texts length ${texts.length}`
      );
    }
    const requestId = options.requestId ?? randomUUID();
    const payload = {
      texts: texts.map((text) => sanitizeText(text))
    };
    if (options.hooks && options.hooks.length > 0) {
      payload.hooks = options.hooks.map((h) => String(h));
    }
    if (options.toolNames && options.toolNames.length > 0) {
      payload.tool_names = options.toolNames.map((t) => t === void 0 ? null : t);
    }
    payload.metadata = texts.map(
      (_, index) => withSdkMetadata(options.metadata?.[index], {
        requestId,
        inputIndex: index
      })
    );
    const data = await this.postWithRetry(payload);
    return data.predictions.map((p) => blockResultFromResponse(p));
  }
  asLangChainHandler(options = {}) {
    return Promise.resolve().then(() => (init_langchain(), langchain_exports)).then(
      (m) => m.createLangChainHandler(this, options)
    );
  }
  asMiddleware(options = {}) {
    return createMiddleware(this, options);
  }
  async postWithRetry(payload, maxRetries = DEFAULT_MAX_RETRIES) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const response = await fetch(this.apiUrl, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(payload),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      if (response.status !== 429 || attempt === maxRetries) {
        if (!response.ok) {
          const body = await readCappedErrorBody(response);
          throw new SilmarilApiError({
            status: response.status,
            statusText: response.statusText,
            body
          });
        }
        return await response.json();
      }
      const waitSeconds = Math.min(2 ** attempt, MAX_BACKOFF_SECONDS);
      await new Promise((resolve) => setTimeout(resolve, waitSeconds * 1e3));
    }
    throw new Error("Firewall: exhausted retries (unreachable)");
  }
  async classifySingle(text, options, metadataInfo) {
    const payload = { text };
    if (options.hook !== void 0) {
      payload.hook = options.hook;
    }
    if (options.toolName !== void 0) {
      payload.tool_name = options.toolName;
    }
    payload.metadata = withSdkMetadata(options.metadata, metadataInfo);
    const data = await this.postWithRetry(payload);
    return blockResultFromResponse(data);
  }
};
init_exceptions();
init_hooks();

// src/cursor-hook.ts
import { createHash as createHash3 } from "node:crypto";
import { readFileSync as readFileSync2, realpathSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

// src/decision-cache.ts
import { createHash, randomUUID as randomUUID2 } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
var CACHE_VERSION = 1;
var DEFAULT_TTL_MS = 10 * 60 * 1e3;
var MAX_CACHE_BYTES = 4 * 1024;
var MAX_CACHE_FILES_SCANNED = 128;
async function writeOutputDecision(conversationId, generationId, classification, options = {}) {
  const directory = options.directory ?? defaultCacheDirectory();
  const decision = omitUndefined({
    version: CACHE_VERSION,
    createdAt: (options.now ?? /* @__PURE__ */ new Date()).toISOString(),
    conversationFingerprint: fingerprint("conversation", conversationId),
    generationFingerprint: fingerprint("generation", generationId),
    prediction: "MALICIOUS",
    score: unitInterval(classification.score),
    threshold: unitInterval(classification.threshold),
    primaryOutcome: boundedOutcome(classification.primaryOutcome ?? classification.primary_outcome)
  });
  const body = Buffer.from(`${JSON.stringify(decision)}
`, "utf8");
  if (body.byteLength > MAX_CACHE_BYTES) return false;
  const destination = path.join(directory, cacheFileName(conversationId, generationId));
  const temporary = path.join(directory, `.${path.basename(destination)}.${process.pid}.${randomUUID2()}.tmp`);
  let handle;
  try {
    await mkdir(directory, { recursive: true, mode: 448 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return false;
    await chmod(directory, 448);
    await cleanupExpiredOutputDecisions(directory, options.now ?? /* @__PURE__ */ new Date());
    handle = await open(temporary, "wx", 384);
    await handle.writeFile(body);
    await handle.sync();
    await handle.close();
    handle = void 0;
    await rename(temporary, destination);
    await chmod(destination, 384);
    return true;
  } catch {
    await handle?.close().catch(() => void 0);
    await rm(temporary, { force: true }).catch(() => void 0);
    return false;
  }
}
async function consumeOutputDecision(conversationId, generationId, options = {}) {
  const destination = path.join(options.directory ?? defaultCacheDirectory(), cacheFileName(conversationId, generationId));
  try {
    const encoded = await readFile(destination);
    await rm(destination, { force: true });
    if (encoded.byteLength > MAX_CACHE_BYTES) return void 0;
    const value = JSON.parse(encoded.toString("utf8"));
    if (!isCachedDecision(value)) return void 0;
    const age = (options.now ?? /* @__PURE__ */ new Date()).getTime() - Date.parse(value.createdAt);
    const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(age) || age < 0 || age > ttlMs) return void 0;
    if (value.conversationFingerprint !== fingerprint("conversation", conversationId)) return void 0;
    if (value.generationFingerprint !== fingerprint("generation", generationId)) return void 0;
    return value;
  } catch {
    await rm(destination, { force: true }).catch(() => void 0);
    return void 0;
  }
}
function defaultCacheDirectory(homeDirectory = homedir()) {
  return path.join(homeDirectory, "Library", "Application Support", "Silmaril", "Cache", "CursorFirewall");
}
async function cleanupExpiredOutputDecisions(directory, now) {
  let entries;
  try {
    entries = await readdir(directory);
  } catch {
    return;
  }
  for (const entry of entries.filter((name) => /^decision-[a-f0-9]{64}\.json$/u.test(name)).slice(0, MAX_CACHE_FILES_SCANNED)) {
    const candidate = path.join(directory, entry);
    try {
      const encoded = await readFile(candidate);
      if (encoded.byteLength > MAX_CACHE_BYTES) {
        await rm(candidate, { force: true });
        continue;
      }
      const value = JSON.parse(encoded.toString("utf8"));
      if (!isCachedDecision(value)) {
        await rm(candidate, { force: true });
        continue;
      }
      const age = now.getTime() - Date.parse(value.createdAt);
      if (!Number.isFinite(age) || age < 0 || age > DEFAULT_TTL_MS) await rm(candidate, { force: true });
    } catch {
      await rm(candidate, { force: true }).catch(() => void 0);
    }
  }
}
function cacheFileName(conversationId, generationId) {
  return `decision-${sha256(`${conversationId}\0${generationId}`)}.json`;
}
function isCachedDecision(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value;
  return record.version === 1 && record.prediction === "MALICIOUS" && typeof record.createdAt === "string" && typeof record.conversationFingerprint === "string" && typeof record.generationFingerprint === "string";
}
function boundedOutcome(value) {
  if (typeof value !== "string") return void 0;
  const normalized = value.trim().replace(/[^A-Za-z0-9_.-]/gu, "_");
  return normalized ? normalized.slice(0, 128) : void 0;
}
function unitInterval(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? value : void 0;
}
function fingerprint(namespace, value) {
  return sha256(`${namespace}:${value}`);
}
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function omitUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== void 0));
}

// src/runtime-config.ts
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { join } from "node:path";
var DEFAULT_TIMEOUT_MS2 = 2500;
var MIN_TIMEOUT_MS = 250;
var MAX_TIMEOUT_MS = 1e4;
var MAX_CONFIG_BYTES = 64 * 1024;
function resolveRuntimeConfig(env = process.env) {
  const fileResult = readFileConfig(configurationPath(env));
  if (fileResult.state === "invalid") return void 0;
  if (fileResult.state === "valid") {
    const file = fileResult.config;
    const enabled2 = file.enabled ?? true;
    if (!enabled2) return void 0;
    const apiKey2 = nonEmpty(file.apiKey);
    const apiUrl2 = nonEmpty(file.apiUrl);
    if (!apiKey2 || !apiUrl2) return void 0;
    const configuredEndpointId2 = endpointId(file.endpointId);
    return {
      apiKey: apiKey2,
      apiUrl: apiUrl2,
      ...configuredEndpointId2 ? { endpointId: configuredEndpointId2 } : {},
      timeoutMs: file.timeoutMs ?? DEFAULT_TIMEOUT_MS2,
      blockMalicious: file.blockMalicious ?? false,
      debug: parseBoolean(env.SILMARIL_DEBUG) ?? file.debug ?? false
    };
  }
  const enabled = parseBoolean(env.SILMARIL_ENABLED) ?? true;
  if (!enabled) return void 0;
  const apiKey = nonEmpty(env.SILMARIL_API_KEY);
  const apiUrl = nonEmpty(env.SILMARIL_API_URL);
  if (!apiKey || !apiUrl) return void 0;
  const configuredEndpointId = endpointId(env.SILMARIL_ENDPOINT_ID);
  return {
    apiKey,
    apiUrl,
    ...configuredEndpointId ? { endpointId: configuredEndpointId } : {},
    timeoutMs: integerInRange(env.SILMARIL_TIMEOUT_MS) ?? DEFAULT_TIMEOUT_MS2,
    blockMalicious: parseBoolean(env.SILMARIL_BLOCK_MALICIOUS) ?? false,
    debug: parseBoolean(env.SILMARIL_DEBUG) ?? false
  };
}
function configurationPath(env = process.env) {
  return nonEmpty(env.SILMARIL_CONFIG_PATH) ?? join(homedir2(), ".cursor", "silmaril-firewall.json");
}
function readFileConfig(path3) {
  let descriptor;
  try {
    descriptor = openSync(path3, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > MAX_CONFIG_BYTES || (metadata.mode & 63) !== 0) {
      return { state: "invalid" };
    }
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
      return { state: "invalid" };
    }
    const parsed = JSON.parse(readFileSync(descriptor, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { state: "invalid" };
    }
    const record = parsed;
    const config = {};
    const enabled = booleanValue(record.enabled);
    const apiKey = stringValue(record.apiKey);
    const apiUrl = stringValue(record.apiUrl);
    const endpointIdValue = stringValue(record.endpointId);
    const timeoutMs = typeof record.timeoutMs === "number" ? integerInRange(record.timeoutMs) : void 0;
    const blockMalicious = booleanValue(record.blockMalicious);
    const debug = booleanValue(record.debug);
    if (Object.hasOwn(record, "enabled") && enabled === void 0 || Object.hasOwn(record, "apiKey") && apiKey === void 0 || Object.hasOwn(record, "apiUrl") && apiUrl === void 0 || Object.hasOwn(record, "timeoutMs") && timeoutMs === void 0 || Object.hasOwn(record, "blockMalicious") && blockMalicious === void 0 || Object.hasOwn(record, "debug") && debug === void 0) {
      return { state: "invalid" };
    }
    if (enabled !== void 0) config.enabled = enabled;
    if (apiKey !== void 0) config.apiKey = apiKey;
    if (apiUrl !== void 0) config.apiUrl = apiUrl;
    if (endpointIdValue !== void 0) config.endpointId = endpointIdValue;
    if (timeoutMs !== void 0) config.timeoutMs = timeoutMs;
    if (blockMalicious !== void 0) config.blockMalicious = blockMalicious;
    if (debug !== void 0) config.debug = debug;
    return { state: "valid", config };
  } catch (error) {
    return isMissingFileError(error) ? { state: "missing" } : { state: "invalid" };
  } finally {
    if (descriptor !== void 0) closeSync(descriptor);
  }
}
function isMissingFileError(error) {
  return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT";
}
function integerInRange(value) {
  const parsed = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof parsed === "number" && Number.isInteger(parsed) && parsed >= MIN_TIMEOUT_MS && parsed <= MAX_TIMEOUT_MS ? parsed : void 0;
}
function parseBoolean(value) {
  if (typeof value !== "string") return void 0;
  if (/^(?:1|true|yes|on)$/iu.test(value.trim())) return true;
  if (/^(?:0|false|no|off)$/iu.test(value.trim())) return false;
  return void 0;
}
function nonEmpty(value) {
  if (typeof value !== "string") return void 0;
  const trimmed = value.trim();
  return trimmed || void 0;
}
function stringValue(value) {
  return typeof value === "string" ? value : void 0;
}
function endpointId(value) {
  const candidate = nonEmpty(value);
  return candidate && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(candidate) ? candidate : void 0;
}
function booleanValue(value) {
  return typeof value === "boolean" ? value : void 0;
}

// src/local-evidence.ts
import { createHash as createHash2, randomUUID as randomUUID3 } from "node:crypto";
import { chmod as chmod2, lstat as lstat2, mkdir as mkdir2, open as open2, rename as rename2, rm as rm2 } from "node:fs/promises";
import { homedir as homedir3 } from "node:os";
import path2 from "node:path";
var MAX_EVENT_BYTES = 16 * 1024;
var MAX_SAFE_VALUE_LENGTH = 128;
var DEFAULT_DIRECTORY = ["Library", "Application Support", "Silmaril", "Evidence", "incoming"];
var CONSEQUENCE_SUMMARIES = {
  credential_exposure: "Potential credential exposure detected.",
  sensitive_data_exposure: "Potential sensitive-data exposure detected.",
  code_execution: "Potential unsafe code execution detected.",
  destructive_change: "Potential destructive change detected.",
  external_communication: "Potential unsafe external communication detected.",
  privilege_change: "Potential unsafe privilege change detected.",
  unsafe_agent_control: "Potential unsafe agent-control behavior detected.",
  other: "Potential harmful consequence detected.",
  unknown: "Potentially unsafe behavior detected."
};
function buildLocalProtectionEvent(input) {
  const occurredAt = (input.occurredAt ?? /* @__PURE__ */ new Date()).toISOString();
  const prediction = normalizePrediction(input.classification.prediction);
  const riskClass = normalizeCategory(input.classification.primaryOutcome ?? input.classification.primary_outcome);
  const event = {
    schemaVersion: 1,
    id: stableId("event", input.sessionId, input.requestId, occurredAt, randomUUID3()),
    occurredAt,
    host: "cursor",
    hook: input.hook,
    mode: input.mode,
    requestFingerprint: runtimeRequestFingerprint(input.requestId) ?? fingerprint2("request", input.requestId),
    sessionFingerprint: fingerprint2("session", input.sessionId),
    toolDisplayName: safeToolName(input.toolName),
    riskClass,
    attemptedConsequence: { category: riskClass, summary: CONSEQUENCE_SUMMARIES[riskClass] },
    prediction,
    modelScore: unitInterval2(input.classification.score),
    modelThreshold: unitInterval2(input.classification.threshold),
    policyDecision: input.policyDecision,
    nativeAction: input.nativeAction,
    outcome: "not_observed",
    evidenceTruth: input.nativeAction === "block_returned" || input.nativeAction === "content_replaced" ? "native_response_returned" : "plugin_reported",
    evidenceCompleteness: "partial",
    provenance: {
      schemaVersion: 1,
      producer: bounded(input.pluginName) ?? "cursor-firewall-plugin",
      producerVersion: bounded(input.pluginVersion) ?? "unknown",
      pluginVersion: bounded(input.pluginVersion) ?? "unknown",
      policyVersion: "cursor-plugin-policy-v1",
      observedAt: occurredAt
    }
  };
  return omitUndefined2(event);
}
async function writeLocalProtectionEvent(event, env = process.env) {
  const directory = resolveLocalEventDirectory(env);
  const encoded = Buffer.from(`${JSON.stringify(event)}
`, "utf8");
  if (encoded.byteLength > MAX_EVENT_BYTES) return void 0;
  const finalPath = path2.join(directory, `event-${sha2562(event.id)}.json`);
  const temporaryPath = path2.join(directory, `.event-${sha2562(event.id)}.${process.pid}.${randomUUID3()}.tmp`);
  let handle;
  try {
    await mkdir2(directory, { recursive: true, mode: 448 });
    const directoryInfo = await lstat2(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return void 0;
    await chmod2(directory, 448);
    handle = await open2(temporaryPath, "wx", 384);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = void 0;
    await rename2(temporaryPath, finalPath);
    await chmod2(finalPath, 384);
    return finalPath;
  } catch {
    await handle?.close().catch(() => void 0);
    await rm2(temporaryPath, { force: true }).catch(() => void 0);
    return void 0;
  }
}
function resolveLocalEventDirectory(env = process.env) {
  const configured = env.SILMARIL_LOCAL_EVENT_DIR?.trim();
  if (configured) return configured;
  const configuredHome = env.HOME?.trim() || homedir3();
  return path2.join(configuredHome, ...DEFAULT_DIRECTORY);
}
function normalizePrediction(value) {
  if (value === "MALICIOUS") return "malicious";
  if (value === "BENIGN") return "benign";
  if (value === void 0 || value === null) return "unavailable";
  return "unknown";
}
function normalizeCategory(value) {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  const mapping = {
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
    unsafe_agent_control: "unsafe_agent_control"
  };
  return mapping[normalized] ?? (normalized ? "other" : "unknown");
}
function unitInterval2(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? value : void 0;
}
function safeToolName(value) {
  if (typeof value !== "string") return void 0;
  const trimmed = value.trim();
  if (!trimmed || /(?:token|secret|password|api[_-]?key)\s*[:=]/iu.test(trimmed)) return void 0;
  return bounded(trimmed.replace(/[^A-Za-z0-9_.:/-]/gu, "_"));
}
function fingerprint2(namespace, value) {
  return typeof value === "string" && value.trim() ? sha2562(`${namespace}:${value}`) : void 0;
}
function runtimeRequestFingerprint(value) {
  return typeof value === "string" && /^silmaril-runtime-check:[0-9a-f-]{36}$/iu.test(value) ? sha2562(value) : void 0;
}
function stableId(namespace, ...values) {
  return `${namespace}-${sha2562(values.filter(Boolean).join("\0"))}`;
}
function sha2562(value) {
  return createHash2("sha256").update(value).digest("hex");
}
function bounded(value, maxLength = MAX_SAFE_VALUE_LENGTH) {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : void 0;
}
function omitUndefined2(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== void 0));
}

// src/cursor-hook.ts
var PLUGIN_NAME = "cursor-firewall-plugin";
var PLUGIN_VERSION = "0.1.3";
var MAX_STDIN_BYTES = 4 * 1024 * 1024;
var MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024;
var MAX_TRANSCRIPT_SEGMENTS = 256;
var SAFE_BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content.";
var SAFE_FOLLOWUP_MESSAGE = "Silmaril Firewall blocked the previous output. Continue without using or reproducing the flagged content.";
var DEFAULT_DEPENDENCIES = {
  firewallConstructor: Firewall,
  evidenceEmitter: writeLocalProtectionEvent,
  decisionWriter: writeOutputDecision,
  decisionConsumer: consumeOutputDecision
};
async function runCursorHook(input, env = process.env, dependencies = {}) {
  const config = resolveRuntimeConfig(env);
  if (!config) {
    debugLog(env, "missing_config");
    return void 0;
  }
  const deps = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  const record = readRecord(input);
  const hookEventName = readString(record?.hook_event_name);
  if (!record || !hookEventName) return void 0;
  if (hookEventName === "stop") {
    return handleStop(record, config, env, deps);
  }
  const targets = buildCursorTargets(record);
  if (targets.length === 0) {
    debugLog(env, "unsupported_or_empty_event", { hookEventName });
    return void 0;
  }
  let classified;
  try {
    const firewall = new deps.firewallConstructor({
      apiKey: config.apiKey,
      apiUrl: config.apiUrl,
      timeoutMs: config.timeoutMs
    });
    classified = await classifyTargets(firewall, targets, config.endpointId);
  } catch (error) {
    debugLog(env, "classification_error", { hookEventName, targetCount: targets.length, ...safeErrorFields(error) });
    return void 0;
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
    deps.evidenceEmitter
  )));
  for (const { target, result } of classified) {
    debugClassification(env, target, result, blocking?.target === target);
  }
  return blocking ? buildBlockOutput(blocking.target, record) : void 0;
}
function buildCursorTargets(input) {
  const hookEventName = readString(input.hook_event_name);
  if (!hookEventName) return [];
  const sessionId = readString(input.conversation_id);
  const generationId = readString(input.generation_id);
  const makeTarget = (text, firewallHook, evidenceHook, capability, suffix = "0", toolName = readString(input.tool_name), toolUseId = readString(input.tool_use_id), extraMetadata = {}) => {
    if (!text?.trim()) return [];
    return [{
      hookEventName,
      text,
      firewallHook,
      evidenceHook,
      requestId: logicalRequestId(input, suffix),
      ...sessionId ? { sessionId } : {},
      ...generationId ? { generationId } : {},
      ...toolName ? { toolName } : {},
      ...toolUseId ? { toolUseId } : {},
      metadata: buildMetadata(input, extraMetadata),
      nativeCapability: capability
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
      return makeTarget(readString(input.text), HookLabel.LLM_OUTPUT, "llm_output", "none", "0", void 0, void 0, { source: "reasoning" });
    case "subagentStart":
      return makeTarget(readString(input.task), HookLabel.USER_INPUT, "subagent", "deny", "0", "Task", readString(input.tool_call_id), { source: "subagent_task" });
    case "subagentStop":
      return buildSubagentTargets(input);
    default:
      return [];
  }
}
async function classifyTargets(firewall, targets, endpointId2) {
  return Promise.all(targets.map(async (target) => ({
    target,
    result: await firewall.classify(target.text, classifyOptions(target, endpointId2))
  })));
}
async function handleAgentResponse(entry, config, env, deps) {
  if (!entry) return void 0;
  const { target, result } = entry;
  const shouldCache = config.blockMalicious && isMalicious(result) && target.sessionId && target.generationId;
  let cached = false;
  if (shouldCache && target.sessionId && target.generationId) {
    cached = await deps.decisionWriter(target.sessionId, target.generationId, result);
  }
  await emitEvidence(target, result, config, false, env, deps.evidenceEmitter);
  debugClassification(env, target, result, false, { decisionCached: cached });
  return void 0;
}
async function handleStop(input, config, env, deps) {
  if (!config.blockMalicious) return void 0;
  const conversationId = readString(input.conversation_id);
  const generationId = readString(input.generation_id);
  if (!conversationId || !generationId) return void 0;
  const decision = await deps.decisionConsumer(conversationId, generationId);
  if (!decision) return void 0;
  const enforceable = input.status === "completed" && readFiniteNumber(input.loop_count) === 0;
  const target = {
    hookEventName: "stop",
    text: "",
    firewallHook: HookLabel.LLM_OUTPUT,
    evidenceHook: "llm_output",
    requestId: logicalRequestId(input, "cached-output"),
    sessionId: conversationId,
    generationId,
    metadata: buildMetadata(input, { source: "cached_output_decision" }),
    nativeCapability: "followup"
  };
  const result = cachedDecisionResult(decision);
  await emitEvidence(target, result, config, enforceable, env, deps.evidenceEmitter);
  debugClassification(env, target, result, enforceable, { decisionCacheConsumed: true });
  return enforceable ? { followup_message: SAFE_FOLLOWUP_MESSAGE } : void 0;
}
function buildBlockOutput(target, input) {
  switch (target.hookEventName) {
    case "beforeSubmitPrompt":
      return { continue: false, user_message: SAFE_BLOCK_MESSAGE };
    case "preToolUse":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE, agent_message: SAFE_BLOCK_MESSAGE };
    case "beforeReadFile":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    case "postToolUse":
      return target.nativeCapability === "replace_mcp" ? { updated_mcp_tool_output: { error: SAFE_BLOCK_MESSAGE }, additional_context: SAFE_BLOCK_MESSAGE } : void 0;
    case "subagentStart":
      return { permission: "deny", user_message: SAFE_BLOCK_MESSAGE };
    case "subagentStop":
      return input.status === "completed" && readFiniteNumber(input.loop_count) === 0 ? { followup_message: SAFE_FOLLOWUP_MESSAGE } : void 0;
    default:
      return void 0;
  }
}
function shouldNativeBlock(target, result, config, input) {
  if (!config.blockMalicious || !isMalicious(result) || target.nativeCapability === "none") return false;
  if (target.nativeCapability === "followup") {
    return input.status === "completed" && readFiniteNumber(input.loop_count) === 0;
  }
  return true;
}
async function emitEvidence(target, result, config, nativeBlocked, env, emitter) {
  const malicious = isMalicious(result);
  const policyDecision = nativeBlocked ? "block" : malicious ? "monitor" : "allow";
  const nativeAction = nativeBlocked ? target.nativeCapability === "replace_mcp" ? "content_replaced" : "block_returned" : "allowed";
  const event = buildLocalProtectionEvent({
    pluginName: PLUGIN_NAME,
    pluginVersion: PLUGIN_VERSION,
    hook: target.evidenceHook,
    mode: config.blockMalicious ? "block" : "shadow",
    requestId: target.requestId,
    ...target.sessionId ? { sessionId: target.sessionId } : {},
    ...target.toolName ? { toolName: target.toolName } : {},
    classification: result,
    policyDecision,
    nativeAction
  });
  await Promise.resolve(emitter(event, env)).catch(() => void 0);
}
function buildSubagentTargets(input) {
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
    requestId: logicalRequestId(input, `subagent-${index}-${sha2563(segment.text)}`),
    ...readString(input.conversation_id) ? { sessionId: readString(input.conversation_id) } : {},
    ...readString(input.generation_id) ? { generationId: readString(input.generation_id) } : {},
    ...segment.toolName ? { toolName: segment.toolName } : {},
    metadata: buildMetadata(input, { source: segment.source, transcriptSegmentIndex: index }),
    nativeCapability: "followup"
  }));
}
function readCursorTranscriptSegments(transcriptPath) {
  if (!transcriptPath) return [];
  try {
    if (statSync(transcriptPath).size > MAX_TRANSCRIPT_BYTES) return [];
  } catch {
    return [];
  }
  let encoded;
  try {
    encoded = readFileSync2(transcriptPath, "utf8");
  } catch {
    return [];
  }
  const segments = [];
  const toolNames = /* @__PURE__ */ new Map();
  for (const line of encoded.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    let parsed;
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
        if (text) segments.push({ text, firewallHook: HookLabel.TOOL_CALL, evidenceHook: "subagent", source: "tool_call", ...toolName ? { toolName } : {} });
      } else if (type === "tool_result") {
        const toolUseId = readString(part.tool_use_id) ?? readString(part.tool_call_id);
        const toolName = toolUseId ? toolNames.get(toolUseId) : void 0;
        const text = stableStringify(part.content ?? part.result);
        if (text) segments.push({ text, firewallHook: HookLabel.TOOL_RESPONSE, evidenceHook: "subagent", source: "tool_result", ...toolName ? { toolName } : {} });
      }
    }
  }
  return segments.slice(-MAX_TRANSCRIPT_SEGMENTS);
}
function messageSegment(text, role) {
  return role === "assistant" ? { text, firewallHook: HookLabel.LLM_OUTPUT, evidenceHook: "subagent", source: "message" } : { text, firewallHook: HookLabel.USER_INPUT, evidenceHook: "subagent", source: "message" };
}
function classifyOptions(target, endpointId2) {
  return {
    hook: target.firewallHook,
    ...target.toolName ? { toolName: target.toolName } : {},
    metadata: withProvenance(target.metadata, endpointId2),
    requestId: target.requestId
  };
}
function withProvenance(metadata, endpointId2) {
  const existingSilmaril = metadata.silmaril && typeof metadata.silmaril === "object" && !Array.isArray(metadata.silmaril) ? metadata.silmaril : {};
  return {
    ...metadata,
    silmaril: {
      ...existingSilmaril,
      provenance: {
        schema_version: 1,
        ...endpointId2 ? { endpoint_id: endpointId2 } : {},
        harness: "cursor"
      }
    }
  };
}
function buildMetadata(input, extra) {
  return omitUndefined3({
    silmaril: { integration: PLUGIN_NAME, version: PLUGIN_VERSION },
    cursorHookEvent: readString(input.hook_event_name),
    conversationId: readString(input.conversation_id),
    generationId: readString(input.generation_id),
    toolUseId: readString(input.tool_use_id) ?? readString(input.tool_call_id),
    toolName: readString(input.tool_name),
    cursorVersion: readString(input.cursor_version),
    workspaceCount: Array.isArray(input.workspace_roots) ? input.workspace_roots.length : void 0,
    ...extra
  });
}
function logicalRequestId(input, suffix) {
  const runtimeMarker = readString(input.prompt)?.match(
    /\bsilmaril-runtime-check:[0-9a-f-]{36}\b/iu
  )?.[0];
  if (runtimeMarker) return runtimeMarker;
  return `cursor-${sha2563([
    readString(input.conversation_id) ?? "",
    readString(input.generation_id) ?? "",
    readString(input.hook_event_name) ?? "",
    readString(input.tool_use_id) ?? readString(input.tool_call_id) ?? "",
    suffix
  ].join("\0"))}`;
}
function cachedDecisionResult(decision) {
  return omitUndefined3({
    prediction: decision.prediction,
    score: decision.score,
    threshold: decision.threshold,
    primaryOutcome: decision.primaryOutcome
  });
}
function isMalicious(result) {
  return result.prediction === "MALICIOUS";
}
function stableStringify(value) {
  if (value === void 0 || value === null) return "";
  if (typeof value === "string") return value;
  const seen = /* @__PURE__ */ new WeakSet();
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
function readTextOrSerialized(value) {
  return typeof value === "string" ? value : stableStringify(value);
}
function parseBoolean2(value) {
  if (typeof value !== "string") return void 0;
  if (/^(?:1|true|yes|on)$/iu.test(value.trim())) return true;
  if (/^(?:0|false|no|off)$/iu.test(value.trim())) return false;
  return void 0;
}
function readRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : void 0;
}
function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : void 0;
}
function readFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : void 0;
}
function omitUndefined3(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== void 0));
}
function sha2563(value) {
  return createHash3("sha256").update(value).digest("hex");
}
function safeErrorFields(error) {
  return error instanceof Error ? { errorName: error.name, errorCode: readString(error.code) } : {};
}
function debugClassification(env, target, result, blocked, extra = {}) {
  debugLog(env, "classification_result", {
    hookEventName: target.hookEventName,
    hook: target.firewallHook,
    toolName: target.toolName,
    prediction: result.prediction,
    blocked,
    ...extra
  });
}
function debugLog(env, event, fields = {}) {
  if (!(parseBoolean2(env.SILMARIL_DEBUG) ?? false)) return;
  process.stderr.write(`[silmaril] ${JSON.stringify(omitUndefined3({ event, ...fields }))}
`);
}
async function readStdin() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > MAX_STDIN_BYTES) throw new Error("Cursor hook input exceeds size limit");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
async function main() {
  try {
    const encoded = await readStdin();
    if (!encoded.trim()) return;
    const output = await runCursorHook(JSON.parse(encoded));
    if (output) process.stdout.write(`${JSON.stringify(output)}
`);
  } catch (error) {
    debugLog(process.env, "hook_error", safeErrorFields(error));
  }
}
function isMainModule() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (isMainModule()) await main();
export {
  PLUGIN_NAME,
  PLUGIN_VERSION,
  buildCursorTargets,
  buildLocalProtectionEvent,
  configurationPath,
  consumeOutputDecision,
  readCursorTranscriptSegments,
  resolveLocalEventDirectory,
  resolveRuntimeConfig,
  runCursorHook,
  withProvenance,
  writeLocalProtectionEvent,
  writeOutputDecision
};
