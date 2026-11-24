#!/usr/bin/env node
// Seeds the e2e stack once after `docker compose up` (spec 17.7). Run by step 10f of
// scripts/ci-web.sh against the real stack, once per stack (it bootstraps the first admin); its pure parts
// (the TOTP generator, the password shape) are also unit-tested in tools/web-lint/test/e2e-seed.test.ts.
//
//   node scripts/e2e-seed.mjs --out <dir> --env-file <file>
//
// `--env-file` is the environment file the stack was brought up with (ci-web.sh step 10c): it holds
// CTRLZ_SECRETS_DIR, so every compose call here resolves the same secrets and profile as `up` did
// (wp12-r1-1). Without it, Compose falls back to the default ../../secrets and the profile defaults.
//
// What it does, in the order of spec 17.7:
//   1. `docker compose run --rm --no-deps -v <tmp>:/out admin ctrlz-admin bootstrap ...` (AUTH 10.1),
//      which writes the first admin's one-time password to a file and prints only the path.
//   2. Over HTTPS at https://admin.localhost: login with that password, change it, enrol TOTP.
//   3. Waits for the next TOTP step (a spent step is refused), then opens the fresh window.
//   4. Sets the SMS gateway to `noop`, registration to open, and Passkey to panel.localhost.
//   5. Creates one tenant user, then logs in as it at https://panel.localhost and sets its own
//      password, so `session.stack.spec.ts` has a user that logs in with a phone and a password.
//
// Every value is generated per run and written to <dir>/seed.json (mode 0600). Nothing secret is
// printed: stdout holds the path, stderr holds fixed messages (fixed rule 8).
import {spawnSync} from "node:child_process";
import {createHmac, randomInt} from "node:crypto";
import {chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {request} from "node:https";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {setTimeout as sleep} from "node:timers/promises";
import {fileURLToPath, pathToFileURL} from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const composeDir = resolve(here, "../deploy/compose");
// The project name of the override files. It is never `ctrlz`, which the auth review's CI owns.
export const PROJECT = "ctrlz-e2e";
export const COMPOSE_FILES = ["docker-compose.yml", "e2e.yml", "e2e-stack.yml"];

const ADMIN_USERNAME = "e2e-admin";
const ADMIN_URL = "https://admin.localhost";
const PANEL_URL = "https://panel.localhost";

// RFC 4648 base32, upper case, no padding.
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The bytes of a base32 string. */
export function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of text.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("not base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP, HMAC-SHA1, 30 second step. `digits` is 6 for authenticator apps. */
export function totp(secretBase32, nowMs = Date.now(), {digits = 6, stepSeconds = 30} = {}) {
  const counter = Math.floor(nowMs / 1000 / stepSeconds);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", base32Decode(secretBase32)).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export const stepOf = (nowMs = Date.now(), stepSeconds = 30) => Math.floor(nowMs / 1000 / stepSeconds);

/** A password the strength check accepts: 20 random characters from four classes. */
export function generatePassword() {
  const classes = ["abcdefghjkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "-_.!"];
  const pool = classes.join("");
  const chars = classes.map((c) => c[randomInt(c.length)]);
  while (chars.length < 20) chars.push(pool[randomInt(pool.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

/** An Iranian mobile number in the local form, random per run: no SMS leaves the stack (`noop`). */
export const generatePhone = () => `0912${String(randomInt(0, 10_000_000)).padStart(7, "0")}`;

/** The argument vector of one `docker compose` call: the project, the env file of the stack, the files, then `args`. */
export function composeArgs(args, {envFile} = {}) {
  const files = COMPOSE_FILES.flatMap((f) => ["-f", join(composeDir, f)]);
  return ["compose", "-p", PROJECT, ...(envFile ? ["--env-file", envFile] : []), ...files, ...args];
}

function compose(args, envFile, options = {}) {
  return spawnSync("docker", composeArgs(args, {envFile}), {encoding: "utf8", ...options});
}

/**
 * What a failed spawnSync result says, as a class and never as output (the output may hold a path or a
 * value, fixed rule 8): docker missing, killed by a signal, or an exit status.
 */
export function describeRun(run) {
  if (run.error) return `docker could not be started (${run.error.code ?? "error"})`;
  if (run.signal) return `docker was stopped by ${run.signal}`;
  return `docker compose exited with status ${run.status}`;
}

/**
 * The pinned busybox of the Compose file (the image of `caddy-init`), the one image the stack already holds that has `cat`. Read from the file
 * so that no second copy of the digest exists (scripts/compose-smoke.sh does the same).
 */
export function readerImage(composeText) {
  const block = /^ {2}caddy-init:\n((?: {4}.*\n|\s*\n)*)/m.exec(composeText);
  return block ? /^ {4}image:\s*(\S+)/m.exec(block[1])?.[1] : undefined;
}

/**
 * The text of a file that a container wrote into a bind mount. `ctrlz-admin --out-file` creates it mode 0600 as uid 65532, which a
 * non-root host user cannot read on a Linux host (Docker Desktop hides this), so on EACCES it is read as root by a throw-away container, the
 * way scripts/compose-smoke.sh does (merge-r4-9). `read` and `run` are injectable for the test; `run` returns the text or throws.
 */
export function readContainerFile(dir, name, {read = (p) => readFileSync(p, "utf8"), run = runReader, image} = {}) {
  try {
    return read(join(dir, name));
  } catch (e) {
    if (e?.code !== "EACCES" && e?.code !== "EPERM") throw e;
  }
  const img = image ?? readerImage(readFileSync(join(composeDir, "docker-compose.yml"), "utf8"));
  if (!img) throw new Error("no image to read a file of the stack with");
  return run(dir, name, img);
}

function runReader(dir, name, image) {
  const run = spawnSync("docker", ["run", "--pull", "never", "--rm", "--network", "none", "-v", `${dir}:/out:ro`, image, "cat", `/out/${name}`], {encoding: "utf8"});
  if (run.status !== 0) throw new Error(`could not read ${name} from the out directory: ${describeRun(run)}`);
  return run.stdout;
}

/** Step 1. The password reaches us only through the file, as AUTH 10.1 requires. */
function bootstrapAdmin(dir, envFile) {
  mkdirSync(dir, {recursive: true, mode: 0o700});
  // The container runs as 65532 and the root is read-only, so the mount must be writable by it. Only the folder
  // that is mounted is open to every user; it sits inside `dir`, which stays 0700, so on a shared host no other
  // account can list it, plant an `otp` in it before the container writes, or read the first admin's one-time
  // password (merge-r1-11).
  const drop = join(dir, "drop");
  mkdirSync(drop, {recursive: true, mode: 0o700});
  chmodSync(drop, 0o777);
  const run = compose(["run", "--rm", "--no-deps", "-v", `${drop}:/out`, "admin", "ctrlz-admin", "bootstrap", "--username", ADMIN_USERNAME, "--out-file", "/out/otp"], envFile);
  if (run.status !== 0) throw new Error(`bootstrap failed: ${describeRun(run)} (a missing --env-file or secrets directory, or an admin that already exists: bring the stack down with -v first)`);
  const text = readContainerFile(drop, "otp");
  const m = /one-time password:\s*(\S+)/.exec(text);
  rmSync(join(drop, "otp"), {force: true});
  if (!m) throw new Error("the bootstrap file holds no one-time password");
  return m[1];
}

/** Caddy's local CA, read from its volume so HTTPS can be verified instead of switched off. */
async function caddyRoot(dir, envFile) {
  const target = join(dir, "caddy-root.crt");
  for (let i = 0; i < 60; i++) {
    const cp = compose(["cp", "caddy:/data/caddy/pki/authorities/local/root.crt", target], envFile);
    if (cp.status === 0 && existsSync(target)) return readFileSync(target);
    await sleep(1000);
  }
  throw new Error("Caddy's root certificate never appeared");
}

/** One HTTPS client per origin, with its own cookie jar. `*.localhost` is 127.0.0.1 (RFC 6761), whatever the resolver says. */
function client(origin, ca) {
  const jar = new Map();
  const host = new URL(origin).hostname;
  async function call(method, path, body) {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolveCall, reject) => {
      const req = request(
        {
          host,
          port: 443,
          method,
          path: `/api/v1${path}`,
          ca,
          lookup: (_h, _o, cb) => cb(null, [{address: "127.0.0.1", family: 4}]),
          headers: {
            Origin: origin,
            Accept: "application/json",
            ...(payload ? {"Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload)} : {}),
            ...(jar.size ? {Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ")} : {}),
          },
        },
        (res) => {
          for (const line of res.headers["set-cookie"] ?? []) {
            const [pair] = line.split(";");
            const eq = pair.indexOf("=");
            const name = pair.slice(0, eq).trim();
            const value = pair.slice(eq + 1).trim();
            if (value === "" || /max-age=0/i.test(line)) jar.delete(name);
            else jar.set(name, value);
          }
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let json = null;
            try {
              json = text ? JSON.parse(text) : null;
            } catch {
              // Not JSON: the status alone is reported.
            }
            resolveCall({status: res.statusCode ?? 0, json});
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
  return {call};
}

// A status line for an error: the code of the API's Problem body, never its text (R21).
const describe = (r) => `HTTP ${r.status}${r.json?.code ? ` ${r.json.code}` : ""}`;

async function expectStatus(label, r, ...ok) {
  if (!ok.includes(r.status)) throw new Error(`${label}: ${describe(r)}`);
  return r;
}

async function waitForApi(api, label) {
  for (let i = 0; i < 90; i++) {
    try {
      // Any answer from the API proves it is up. A wrong login is a 4xx, a dead upstream is a 5xx from Caddy.
      const r = await api.call("POST", "/auth/login", {username: "wait", password: "wait"});
      if (r.status < 500) return;
    } catch {
      // Caddy is not listening yet.
    }
    await sleep(1000);
  }
  throw new Error(`${label} did not come up`);
}

async function seed(out, envFile) {
  mkdirSync(out, {recursive: true, mode: 0o700});
  const work = mkdtempSync(join(tmpdir(), "ctrlz-e2e-seed-"));
  try {
    const oneTime = bootstrapAdmin(work, envFile);
    const ca = await caddyRoot(work, envFile);
    const admin = client(ADMIN_URL, ca);
    await waitForApi(admin, "the admin API");

    const adminPassword = generatePassword();
    const login = await expectStatus("admin login", await admin.call("POST", "/auth/login", {username: ADMIN_USERNAME, password: oneTime}), 200);
    if (login.json?.state !== "setup_required") throw new Error("the first login should require setup");
    await expectStatus("admin password", await admin.call("POST", "/me/password", {current_password: oneTime, new_password: adminPassword}), 204);

    const setup = await expectStatus("totp setup", await admin.call("POST", "/me/totp/setup", {}), 200);
    const secret = setup.json.secret;
    await expectStatus("totp confirm", await admin.call("POST", "/me/totp/confirm", {code: totp(secret)}), 204);
    const confirmedStep = stepOf();

    // A spent step is refused (AUTH 5), so the fresh window needs the next one.
    while (stepOf() <= confirmedStep) await sleep(500);
    await expectStatus("totp fresh", await admin.call("POST", "/auth/totp/fresh", {code: totp(secret)}), 200);

    // An empty body is a validation_failed (body/empty), and the noop row exists only once a PUT has created it: the price is the one
    // field it can take (it has no credentials), so the seed sends a zero price (found by the first run, merge item step 10f).
    await expectStatus("sms gateway", await admin.call("PUT", "/sms/gateways/noop", {cost_per_message: "0"}), 200);
    // The router sends nothing for a template the gateway has no mapping for (code no_template, the worker logs it and the message is
    // retried for ever), noop included, so every flow that sends a code needs the five mappings. Both locales: the router falls back to the
    // other one, but a test that asks for either must not depend on that. The ids and names are placeholders that only noop sees.
    for (const key of ["otp", "otp_reset", "otp_phone", "invite", "account_exists"]) {
      for (const locale of ["fa", "en"]) {
        const params = key === "account_exists" ? [] : ["code"];
        await expectStatus(`sms template ${key}/${locale}`, await admin.call("PUT", `/sms/gateways/noop/templates/${key}/${locale}`, {provider_template_id: "1", param_names: params}), 200);
      }
    }
    await expectStatus("sms routing", await admin.call("PUT", "/sms/routing", {primary: "noop"}), 200);
    await expectStatus("registration", await admin.call("PUT", "/settings/registration", {mode: "open"}), 200);
    await expectStatus("webauthn", await admin.call("PUT", "/settings/webauthn", {rp_id: "panel.localhost", enabled: true}), 200);

    const phone = generatePhone();
    // The locale is en: a signed-in user whose saved language differs from the URL is sent to their own language (spec 5), and the stack specs
    // sign in at /en/... and assert English text. A fa user made every one of them end up on /fa/ (found by the first real run).
    const created = await expectStatus("create user", await admin.call("POST", "/users", {phone, locale: "en"}), 201);
    const userOneTime = created.json.one_time_password;

    const panel = client(PANEL_URL, ca);
    const userLogin = await expectStatus("user login", await panel.call("POST", "/auth/login/password", {phone, password: userOneTime}), 200);
    if (userLogin.json?.status !== "authenticated") throw new Error("the one-time login should be authenticated");
    const userPassword = generatePassword();
    await expectStatus("user password", await panel.call("POST", "/account/password", {new_password: userPassword}), 204);

    const file = join(out, "seed.json");
    writeFileSync(file, JSON.stringify({admin: {username: ADMIN_USERNAME, password: adminPassword, totp_secret: secret}, user: {phone, password: userPassword}}), {mode: 0o600});
    chmodSync(file, 0o600);
    return file;
  } finally {
    rmSync(work, {recursive: true, force: true});
  }
}

const flag = (name) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
};

async function main() {
  const out = flag("--out");
  const envFile = flag("--env-file");
  if (!out) {
    console.error("usage: node scripts/e2e-seed.mjs --out <private directory> [--env-file <the stack's env file>]");
    process.exit(2);
  }
  try {
    console.log(await seed(resolve(out), envFile ? resolve(envFile) : undefined));
  } catch (e) {
    // The message names a step and a status, never a value.
    console.error(`e2e-seed: ${e instanceof Error ? e.message : "failed"}`);
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();

