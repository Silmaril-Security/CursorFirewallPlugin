import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

const CACHE_VERSION = 1;
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_CACHE_BYTES = 4 * 1024;
const MAX_CACHE_FILES_SCANNED = 128;

export type CachedOutputDecision = {
  version: 1;
  createdAt: string;
  conversationFingerprint: string;
  generationFingerprint: string;
  prediction: "MALICIOUS";
  score?: number;
  threshold?: number;
  primaryOutcome?: string;
};

export async function writeOutputDecision(
  conversationId: string,
  generationId: string,
  classification: Record<string, unknown>,
  options: { directory?: string; now?: Date } = {},
): Promise<boolean> {
  const directory = options.directory ?? defaultCacheDirectory();
  const decision = omitUndefined({
    version: CACHE_VERSION,
    createdAt: (options.now ?? new Date()).toISOString(),
    conversationFingerprint: fingerprint("conversation", conversationId),
    generationFingerprint: fingerprint("generation", generationId),
    prediction: "MALICIOUS",
    score: unitInterval(classification.score),
    threshold: unitInterval(classification.threshold),
    primaryOutcome: boundedOutcome(classification.primaryOutcome ?? classification.primary_outcome),
  }) as CachedOutputDecision;
  const body = Buffer.from(`${JSON.stringify(decision)}\n`, "utf8");
  if (body.byteLength > MAX_CACHE_BYTES) return false;

  const destination = path.join(directory, cacheFileName(conversationId, generationId));
  const temporary = path.join(directory, `.${path.basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return false;
    await chmod(directory, 0o700);
    await cleanupExpiredOutputDecisions(directory, options.now ?? new Date());
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(body);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return true;
  } catch {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    return false;
  }
}

export async function consumeOutputDecision(
  conversationId: string,
  generationId: string,
  options: { directory?: string; now?: Date; ttlMs?: number } = {},
): Promise<CachedOutputDecision | undefined> {
  const destination = path.join(options.directory ?? defaultCacheDirectory(), cacheFileName(conversationId, generationId));
  try {
    const encoded = await readFile(destination);
    await rm(destination, { force: true });
    if (encoded.byteLength > MAX_CACHE_BYTES) return undefined;
    const value = JSON.parse(encoded.toString("utf8")) as unknown;
    if (!isCachedDecision(value)) return undefined;
    const age = (options.now ?? new Date()).getTime() - Date.parse(value.createdAt);
    const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(age) || age < 0 || age > ttlMs) return undefined;
    if (value.conversationFingerprint !== fingerprint("conversation", conversationId)) return undefined;
    if (value.generationFingerprint !== fingerprint("generation", generationId)) return undefined;
    return value;
  } catch {
    await rm(destination, { force: true }).catch(() => undefined);
    return undefined;
  }
}

export function defaultCacheDirectory(homeDirectory = homedir()): string {
  return path.join(homeDirectory, "Library", "Application Support", "Silmaril", "Cache", "CursorFirewall");
}

async function cleanupExpiredOutputDecisions(directory: string, now: Date): Promise<void> {
  let entries: string[];
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
      const value = JSON.parse(encoded.toString("utf8")) as unknown;
      if (!isCachedDecision(value)) {
        await rm(candidate, { force: true });
        continue;
      }
      const age = now.getTime() - Date.parse(value.createdAt);
      if (!Number.isFinite(age) || age < 0 || age > DEFAULT_TTL_MS) await rm(candidate, { force: true });
    } catch {
      await rm(candidate, { force: true }).catch(() => undefined);
    }
  }
}

function cacheFileName(conversationId: string, generationId: string): string {
  return `decision-${sha256(`${conversationId}\u0000${generationId}`)}.json`;
}

function isCachedDecision(value: unknown): value is CachedOutputDecision {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.version === 1
    && record.prediction === "MALICIOUS"
    && typeof record.createdAt === "string"
    && typeof record.conversationFingerprint === "string"
    && typeof record.generationFingerprint === "string";
}

function boundedOutcome(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().replace(/[^A-Za-z0-9_.-]/gu, "_");
  return normalized ? normalized.slice(0, 128) : undefined;
}

function unitInterval(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1 ? value : undefined;
}

function fingerprint(namespace: string, value: string): string {
  return sha256(`${namespace}:${value}`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function omitUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}
