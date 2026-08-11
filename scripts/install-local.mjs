import { randomUUID } from "node:crypto";
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_DIRECTORY_NAME = "silmaril-firewall";
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function installLocalPlugin({
  sourceRoot = repoRoot,
  localPluginsRoot = path.join(os.homedir(), ".cursor", "plugins", "local"),
} = {}) {
  const packageManifest = JSON.parse(await readFile(path.join(sourceRoot, "package.json"), "utf8"));
  const packageEntries = ["package.json", ...packageManifest.files];
  const target = path.join(localPluginsRoot, PLUGIN_DIRECTORY_NAME);

  await mkdir(localPluginsRoot, { recursive: true });
  const staging = await mkdtemp(path.join(localPluginsRoot, `.${PLUGIN_DIRECTORY_NAME}-staging-`));
  const backup = path.join(localPluginsRoot, `.${PLUGIN_DIRECTORY_NAME}-previous-${randomUUID()}`);
  let movedExisting = false;

  try {
    for (const entry of packageEntries) {
      const source = confinedPath(sourceRoot, entry);
      const destination = path.join(staging, entry);
      await mkdir(path.dirname(destination), { recursive: true });
      await cp(source, destination, { recursive: true, errorOnExist: true, force: false });
    }
    await rejectSymbolicLinks(staging);

    if (await exists(target)) {
      await rename(target, backup);
      movedExisting = true;
    }
    await rename(staging, target);
    if (movedExisting) await rm(backup, { recursive: true, force: true });
    return target;
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    if (movedExisting && !(await exists(target)) && await exists(backup)) {
      await rename(backup, target);
    }
    throw error;
  }
}

function confinedPath(root, entry) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, entry);
  if (resolved === resolvedRoot || !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`Package entry escapes source root: ${entry}`);
  }
  return resolved;
}

async function rejectSymbolicLinks(root) {
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const metadata = await lstat(current);
    if (metadata.isSymbolicLink()) throw new Error(`Packaged plugin contains a symbolic link: ${current}`);
    if (!metadata.isDirectory()) continue;
    const children = await readdir(current);
    pending.push(...children.map((child) => path.join(current, child)));
  }
}

async function exists(candidate) {
  try {
    await lstat(candidate);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function isDirectInvocation() {
  return Boolean(process.argv[1])
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  const destination = await installLocalPlugin();
  process.stdout.write(`Installed Silmaril Firewall at ${destination}\n`);
}
