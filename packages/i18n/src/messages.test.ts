import {existsSync, readdirSync, readFileSync} from "node:fs";
import path from "node:path";

import {createTranslator} from "next-intl";
import {describe, expect, it} from "vitest";

import {loadMessages} from "./messages.ts";
import {
  APP_NAMESPACES,
  NAMESPACE_OWNER,
  PENDING_NAMESPACES,
  pickNamespaces,
  type Namespace,
} from "./namespaces.ts";

const root = path.resolve(import.meta.dirname, "..");
const dir = (locale: string) => path.join(root, "messages", locale);
const read = (locale: string, ns: string) =>
  JSON.parse(readFileSync(path.join(dir(locale), `${ns}.json`), "utf8")) as Tree;

type Tree = {[key: string]: string | Tree};

function flatten(tree: Tree, prefix = ""): [string, string][] {
  return Object.entries(tree).flatMap(([k, v]) =>
    typeof v === "string" ? [[prefix + k, v] as [string, string]] : flatten(v, `${prefix}${k}.`),
  );
}

const files = (locale: string) =>
  readdirSync(dir(locale))
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -5))
    .sort();

const allowed = new Set(
  readFileSync(path.join(root, "latin-allow.txt"), "utf8")
    .split("\n")
    .filter((l) => l.trim() && !l.startsWith("#"))
    .map((l) => l.split("#")[0]!.trim()),
);

// What is left of a message once ICU syntax is removed: argument names, the
// plural keywords and tag names are Latin by necessity and are not text.
function visibleText(message: string): string {
  return message
    .replace(/<\/?[A-Za-z][\w-]*>/g, "")
    .replace(/\{\s*[A-Za-z_]\w*\s*(,\s*(plural|select|selectordinal|number|date|time)\s*(,\s*[^{}]*)?)?/g, "{")
    .replace(/(?:=\d+|zero|one|two|few|many|other)\s*\{/g, "{");
}

const namespaces = files("fa");

describe("message files", () => {
  it("have the same namespaces in both languages", () => {
    expect(files("en")).toEqual(namespaces);
  });

  it("use only known namespaces", () => {
    for (const ns of namespaces) expect(Object.keys(NAMESPACE_OWNER)).toContain(ns);
  });

  it("agree with the pending list", () => {
    // A namespace is pending exactly while its file is missing.
    const missing = (Object.keys(NAMESPACE_OWNER) as Namespace[]).filter((ns) => !existsSync(path.join(dir("fa"), `${ns}.json`)));
    expect([...PENDING_NAMESPACES].sort()).toEqual(missing.sort());
  });

  it("have common, since every app needs it", () => expect(namespaces).toContain("common"));
});

describe.each(namespaces)("messages/%s", (ns) => {
  const fa = flatten(read("fa", ns));
  const en = flatten(read("en", ns));

  it("has the same keys in both languages", () => {
    expect(en.map(([k]) => k).sort()).toEqual(fa.map(([k]) => k).sort());
  });

  it("has no empty value and no dot in a key", () => {
    for (const [k, v] of [...fa, ...en]) {
      expect(v.trim(), k).not.toBe("");
      expect(k.split(".").every((part) => part.length > 0), k).toBe(true);
    }
    const raw = JSON.stringify(read("fa", ns)) + JSON.stringify(read("en", ns));
    expect(raw).not.toMatch(/"[^"]*\.[^"]*"\s*:/);
  });

  it("has no Latin letters in Persian outside the allowlist", () => {
    for (const [k, v] of fa) {
      const words = visibleText(v).match(/[A-Za-z]+/g) ?? [];
      for (const w of words) expect(allowed.has(w), `${ns}.${k}: "${w}"`).toBe(true);
    }
  });

  it("never says email (T-111)", () => {
    for (const [k, v] of [...fa, ...en]) {
      expect(v, k).not.toMatch(/e-?mail/i);
      expect(v, k).not.toMatch(/ایمیل|ای‌میل|پست الکترونیک/);
    }
    // Key names count too: nothing in the code may be named after email.
    for (const [k] of fa) expect(k, k).not.toMatch(/e-?mail/i);
  });

  it("has one and other in every plural", () => {
    for (const [k, v] of [...fa, ...en]) {
      if (/,\s*plural\s*,/.test(v)) {
        expect(v, k).toMatch(/\bone\s*\{/);
        expect(v, k).toMatch(/\bother\s*\{/);
      }
    }
  });

  it("is valid ICU in both languages", () => {
    for (const locale of ["fa", "en"] as const) {
      const errors: string[] = [];
      const t = createTranslator({
        locale,
        messages: {[ns]: read(locale, ns)} as never,
        onError: (e) => errors.push(e.message),
      });
      for (const [key, message] of flatten(read(locale, ns))) {
        const args: Record<string, unknown> = {};
        for (const m of message.matchAll(/\{\s*([A-Za-z_]\w*)\s*(?:,\s*(\w+))?/g)) {
          args[m[1]!] = m[2] === "plural" || m[2] === "number" ? 3 : "x";
        }
        for (const m of message.matchAll(/<([A-Za-z][\w-]*)>/g)) args[m[1]!] = (c: unknown) => c;
        (t as unknown as {rich: (k: string, v: unknown) => unknown}).rich(`${ns}.${key}`, args);
      }
      expect(errors, `${locale}/${ns}`).toEqual([]);
    }
  });
});

describe("namespaces per app", () => {
  it("keeps admin wording out of the panel and tenant wording out of the admin", () => {
    expect(APP_NAMESPACES.panel).not.toContain("admin");
    expect(APP_NAMESPACES.admin).not.toContain("account");
    expect(APP_NAMESPACES.admin).not.toContain("lab");
  });

  it("gives every app the common namespace", () => {
    for (const list of Object.values(APP_NAMESPACES)) expect(list).toContain("common");
  });

  it("picks only what the app may receive", () => {
    const all = {common: {a: "1"}, admin: {b: "2"}, account: {c: "3"}, rogue: {d: "4"}};
    expect(Object.keys(pickNamespaces(all, "panel")).sort()).toEqual(["account", "common"]);
    expect(Object.keys(pickNamespaces(all, "admin")).sort()).toEqual(["admin", "common"]);
  });
});

describe("loadMessages", () => {
  it("loads the namespaces that exist, per locale", async () => {
    for (const app of ["panel", "admin"] as const) {
      const fa = await loadMessages("fa", app);
      const en = await loadMessages("en", app);
      expect(Object.keys(fa).sort()).toEqual(namespaces.filter((n) => (APP_NAMESPACES[app] as readonly string[]).includes(n)).sort());
      expect(Object.keys(en)).toEqual(Object.keys(fa));
    }
  });

  it("returns the right language", async () => {
    expect((await loadMessages("fa", "panel")).common?.close).toBe("بستن");
    expect((await loadMessages("en", "panel")).common?.close).toBe("Close");
  });
});
