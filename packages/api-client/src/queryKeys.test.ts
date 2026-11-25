import {readdirSync} from "node:fs";
import {join} from "node:path";
import {beforeAll, describe, expect, it} from "vitest";

// The words of ctrlz/no-secret-param (R21): the lint rule reads the source, this reads the keys that the source builds, so a key made in a way the
// selectors do not see still fails here.
import {SECRET_WORDS} from "../../../tools/web-lint/src/bans.ts";

// gate-r22-8: a screen never puts a secret in a query key (14.4). A query is kept in the cache for its gcTime and its key is readable there, in a
// heap snapshot and in the devtools of a shared PC. mutationDefaults.gcTime = 0 covers what a mutation carries; nothing covered the keys.
const SECRET = new RegExp(`(${SECRET_WORDS})`, "i");
// "passkeys" names a resource, so a constant element is a name and not a value. What is judged: the parameter names of a key factory, and every
// part of a key that a call builds from them.
const SOURCE = join(__dirname);
const modules = ["hooks", "admin"].flatMap((dir) =>
  readdirSync(join(SOURCE, dir))
    .filter((f) => /\.tsx?$/.test(f) && !/\.test\./.test(f))
    .map((f) => `./${dir}/${f}`),
);

type Found = {module: string; name: string; key: readonly unknown[]};
async function discover() {
  const options: Found[] = [];
  const factories: {module: string; name: string; member: string; fn: (...a: unknown[]) => unknown}[] = [];
  const constants: Found[] = [];
  for (const module of modules) {
    const exports = (await import(/* @vite-ignore */ module)) as Record<string, unknown>;
    for (const [name, value] of Object.entries(exports)) {
      if (/QueryOptions$/.test(name) && typeof value === "function") {
        const built = (value as () => {queryKey?: readonly unknown[]})();
        options.push({module, name, key: built.queryKey ?? []});
      } else if (/Keys$/.test(name) && value && typeof value === "object") {
        for (const [member, entry] of Object.entries(value)) {
          if (typeof entry === "function") factories.push({module, name, member, fn: entry as (...a: unknown[]) => unknown});
          else constants.push({module, name: `${name}.${member}`, key: entry as readonly unknown[]});
        }
      }
    }
  }
  return {options, factories, constants};
}

/** The parameter names of a function, read from its source, because that is where a factory says what goes into a key. */
const parameterNames = (fn: {toString(): string}): string[] => {
  const head = /^[^(]*\(([^)]*)\)|^(?:async\s*)?([\w$]+)\s*=>/.exec(fn.toString());
  return (head?.[1] ?? head?.[2] ?? "").split(",").map((p) => p.trim().replace(/^\.\.\./, "").split(/[\s:=]/)[0] ?? "").filter(Boolean);
};

describe("no query key holds a secret (gate-r22-8)", () => {
  // The first dynamic import of every hooks module is a cold transform and took about four of the five seconds a test is given when the machine was
  // idle; on a loaded one it timed out and the walk below never ran. It is paid once, here, with a bound of its own, and the tests read the result.
  let walked: Awaited<ReturnType<typeof discover>>;
  beforeAll(async () => {
    walked = await discover();
  }, 60_000);

  it("finds the queries of the app, so the walk cannot pass by finding nothing", () => {
    const {options, constants} = walked;
    // me, public config, notifications, announcements, passkeys, sessions and the admin's me.
    expect(options.length).toBeGreaterThanOrEqual(7);
    expect(constants.length).toBeGreaterThanOrEqual(7);
    for (const option of options) expect(Array.isArray(option.key) && option.key.length > 0, `${option.name} has a key`).toBe(true);
  });

  it("every key is made of strings and numbers, never of an object or an array that a form or a ticket could ride in", () => {
    const {options, constants} = walked;
    for (const {name, key} of [...options, ...constants]) {
      for (const part of key) {
        // A key part is a string or a number: an object or an array in a key is where a form's values slip in.
        expect(typeof part === "string" || typeof part === "number", `${name}: a key part of type ${typeof part}`).toBe(true);
      }
    }
  });

  it("a key factory takes no parameter that is named like a secret", () => {
    const {factories} = walked;
    for (const {module, name, member, fn} of factories) {
      for (const parameter of parameterNames(fn)) {
        expect(SECRET.test(parameter), `${module} ${name}.${member}(${parameter}) puts a value named like a secret in a key`).toBe(false);
      }
    }
  });

  it("the reader of parameter names sees a ticket and an OTP code, and not a profile id", () => {
    expect(parameterNames((ticket: string) => ["reset", ticket])).toEqual(["ticket"]);
    expect(parameterNames((id: string, otpCode: string) => ["x", id, otpCode])).toEqual(["id", "otpCode"]);
    expect(SECRET.test("ticket")).toBe(true);
    expect(SECRET.test("otpCode")).toBe(true);
    expect(SECRET.test("profileId")).toBe(false);
  });
});
