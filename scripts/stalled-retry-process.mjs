import { writeSync } from "node:fs";
import * as hook from "../dist/cursor-hook.js";
hook.setMacDeviceNameLookupForTests({ platform: "linux" });
let attempts = 0;
globalThis.fetch = async () => ++attempts < 3
  ? new Response("throttled", { status: 429 })
  : new Response(new ReadableStream({ cancel: () => new Promise(() => {}) }), { status: 429 });
const env = process.env;
const started = performance.now();
let hookMS;
// Observe natural process exit after every SDK timer has drained, excluding startup.
process.once("exit", () => writeSync(1, JSON.stringify({ attempts, hookMS, processMS: performance.now() - started }) + "\n"));
await hook.runCursorHook({ hook_event_name: "beforeSubmitPrompt", prompt: "synthetic test" }, env);
hookMS = performance.now() - started;
