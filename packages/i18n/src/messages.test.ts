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

  // gate-r34-3: the lab wording is sent only where the lab pages are served.
  it("sends the lab namespace only when the lab is on", () => {
    const all = {common: {a: "1"}, lab: {e: "5"}};
    expect(Object.keys(pickNamespaces(all, "panel"))).toEqual(["common"]);
    expect(Object.keys(pickNamespaces(all, "panel", {lab: true})).sort()).toEqual(["common", "lab"]);
    expect(Object.keys(pickNamespaces(all, "admin", {lab: true}))).toEqual(["common"]);
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

describe("errors with a countdown", () => {
  const countdown = ["rate_limited", "too_many_attempts", "otp_limited", "otp_locked", "server_busy"];
  const t = (locale: "fa" | "en") =>
    createTranslator({locale, messages: {errors: read(locale, "errors")} as never, namespace: "errors" as never}) as unknown as (
      key: string,
      values: Record<string, unknown>,
    ) => string;

  // The `one` branch used to say "1 seconds" because it copied the `other` text.
  it.each(countdown)("%s names the unit in the singular for 1 and in the plural for 2 and 30 in English", (key) => {
    const en = t("en");
    expect(en(key, {retryAfterS: 1})).toMatch(/\b1 second\b(?!s)/);
    expect(en(key, {retryAfterS: 2})).toMatch(/\b2 seconds\b/);
    expect(en(key, {retryAfterS: 30})).toMatch(/\b30 seconds\b/);
    expect(en(key, {retryAfterS: 1})).not.toMatch(/seconds/);
  });

  it.each(countdown)("%s has a no-figure text for 0 and shows the figure otherwise in both languages", (key) => {
    for (const locale of ["fa", "en"] as const) {
      const text = t(locale);
      expect(text(key, {retryAfterS: 0}), `${locale} 0`).not.toMatch(/[0-9۰-۹]/);
      expect(text(key, {retryAfterS: 5}), `${locale} 5`).toMatch(/[5۵]/);
    }
  });
});

// merge-r4-10. The refusal of a save while a pair waits is read by the admin whose save it refused, who cannot have staged that pair and holds no
// fingerprint. The console says to discard it then (admin-r20-3); the line once offered Confirm first, which sends the owner looking for a way to
// confirm what a stolen session may have staged.
describe("fieldErrors.pending_exists of the admin", () => {
  const key = (locale: string) => ((read(locale, "admin") as Tree).fieldErrors as Tree).pending_exists as string;
  it("tells the refused admin to discard, and never offers to confirm", () => {
    expect(key("en")).toMatch(/discard/i);
    expect(key("en")).not.toMatch(/confirm it|or discard|confirm or/i);
    expect(key("en")).toMatch(/someone else/i);
  });
  it("says the same in Persian: it names the discard and the other session, and has no confirm-or-discard choice", () => {
    expect(key("fa")).toContain("دور بریزید");
    expect(key("fa")).toContain("نشست دیگری");
    expect(key("fa")).not.toContain("تأیید یا رد");
  });
});
