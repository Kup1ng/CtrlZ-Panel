import {spawn, spawnSync, type ChildProcess} from "node:child_process";
import {createRequire} from "node:module";
import {createServer} from "node:net";

// A real `next start` of this app, for the specs whose subject is what the server does with its environment (a wrong CTRLZ_VERIFY_ORIGIN,
// a missing CTRLZ_LAB). The shared server of the run has both set the way the tests need them, so only a server of its own can show the other
// case. Shared by verify-origin.spec.ts and lab-off.spec.ts (gate-r4-10).

/** The preset port when the run was given a range of ports (an environment variable named by the caller), else any free one. */
export async function freePort(presetVariable: string): Promise<number> {
  const preset = Number(process.env[presetVariable]);
  if (preset > 0) return preset;
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const {port} = probe.address() as {port: number};
      probe.close(() => resolve(port));
    });
  });
}

/**
 * Without a shell, so that stopping it stops `next` itself and not only a wrapper. The app folder is where every run starts.
 * `env` is applied over the test process's environment, and a `undefined` value removes the variable: a server that must not have
 * CTRLZ_LAB gets none, even when the run that started the test has it set.
 */
export function startNext(port: number, env: Record<string, string | undefined>): ChildProcess {
  const image = process.env.E2E_STANDALONE_IMAGE;
  if (image) return startImage(image, port, env);
  const bin = createRequire(`${process.cwd()}/`).resolve("next/dist/bin/next");
  const merged: Record<string, string | undefined> = {...process.env, NEXT_TELEMETRY_DISABLED: "1", ...env};
  for (const key of Object.keys(merged)) if (merged[key] === undefined) delete merged[key];
  return spawn(process.execPath, [bin, "start", "-p", String(port)], {cwd: process.cwd(), env: merged as NodeJS.ProcessEnv, stdio: "ignore"});
}

// The merge item B2 (gate-r13-5): the same specs against the standalone `server.js` that deploy/docker/web.Dockerfile ships, with its
// public/ and .next/static beside it, which `next start` is not. E2E_STANDALONE_IMAGE names the image (ctrlz/web-panel:e2e); the container
// is published on the loopback only. Only the variables the test names reach it: the image's own environment is what a deployment has, and
// the test process's (a CTRLZ_LAB of the run) must not leak in, so an undefined value is simply not passed.
const containers = new WeakMap<ChildProcess, string>();
function startImage(image: string, port: number, env: Record<string, string | undefined>): ChildProcess {
  const name = `ctrlz-b2-${port}`;
  spawnSync("docker", ["rm", "-f", name], {stdio: "ignore"});
  const args = ["run", "--rm", "--name", name, "-p", `127.0.0.1:${port}:3000`, "--pull", "never"];
  for (const [key, value] of Object.entries(env)) if (value !== undefined) args.push("-e", `${key}=${value}`);
  const child = spawn("docker", [...args, image], {stdio: "ignore"});
  containers.set(child, name);
  return child;
}

export function stop(child: ChildProcess) {
  const container = containers.get(child);
  if (container) {
    spawnSync("docker", ["rm", "-f", container], {stdio: "ignore"});
    return;
  }
  if (child.exitCode !== null || child.pid === undefined) return;
  if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], {stdio: "ignore"});
  else child.kill("SIGKILL");
}

/** Waits for a file of public/ to answer: it is served even while the proxy cannot load, so it only says the server is up. */
export async function waitUntilUp(origin: string, child: ChildProcess) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`next start exited with ${child.exitCode} before it answered`);
    try {
      if ((await fetch(`${origin}/logo.png`)).status === 200) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("next start did not answer within 90 s");
}
