import {readdirSync, readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {ADMIN_SESSION_COOKIES, PANEL_SESSION_COOKIES} from "./prefixes.ts";

// gate-r5-3: the gate, the panel's not-found page and many specs spell the cookie names as literals, and the only other record of
// them is the API contract. If the Go side renames a cookie and regenerates the contract, mock-mode runs would stay green (they use
// the same literals) and the first signed-in visitor after the deploy would be redirected to /login in a loop. The contract is in this
// repository, so the names are compared with it here, and every `__Host-...` literal of the web tier is compared with the contract too.

const root = (path: string) => fileURLToPath(new URL(`../../../../${path}`, import.meta.url));
const read = (path: string) => readFileSync(root(path), "utf8");

const COOKIE = /__Host-[A-Za-z0-9_-]+/g;

/** The cookie named by the apiKey security scheme of a contract (components.securitySchemes, `in: cookie`). */
function schemeCookie(yaml: string, scheme: string): string | undefined {
  const block = new RegExp(`^  securitySchemes:\\n(?:    .*\\n|\\n)*`, "m").exec(yaml)?.[0] ?? "";
  const entry = new RegExp(`^    ${scheme}:\\n((?:      .*\\n)+)`, "m").exec(block)?.[1] ?? "";
  if (!/^\s+in: cookie$/m.test(entry)) return undefined;
  return /^\s+name: (\S+)$/m.exec(entry)?.[1];
}

/** The `__Host-` names that one path of the contract mentions. */
function pathCookies(yaml: string, path: string): string[] {
  const start = yaml.indexOf(`\n  ${path}:\n`);
  if (start < 0) return [];
  const rest = yaml.slice(start + 1);
  const next = /\n  \/\S*:\n|\n[a-z]\w*:\n/.exec(rest.slice(1));
  const section = next ? rest.slice(0, next.index + 1) : rest;
  return [...new Set(section.match(COOKIE) ?? [])];
}

const panelYaml = read("api/openapi.yaml");
const adminYaml = read("api/admin-openapi.yaml");

describe("the gate's cookie names are the API contract's (gate-r5-3)", () => {
  it("the panel's session cookie is the one the contract's security scheme names", () => {
    expect(schemeCookie(panelYaml, "session")).toBe(PANEL_SESSION_COOKIES[0]);
  });

  it("the panel's refresh cookie is the one /auth/refresh reads", () => {
    expect(pathCookies(panelYaml, "/auth/refresh")).toEqual([PANEL_SESSION_COOKIES[1]]);
  });

  it("the admin's session cookie is the one the admin contract's security scheme names", () => {
    expect(schemeCookie(adminYaml, "admin")).toBe(ADMIN_SESSION_COOKIES[0]);
  });

  it("each contract names those cookies and no other __Host- cookie, so a new one is a decision for the gate", () => {
    expect([...new Set(panelYaml.match(COOKIE))].sort()).toEqual([...PANEL_SESSION_COOKIES].sort());
    expect([...new Set(adminYaml.match(COOKIE))].sort()).toEqual([...ADMIN_SESSION_COOKIES].sort());
  });

  it("the helpers find something: a contract with another name would fail", () => {
    const renamed = panelYaml.replace("name: __Host-ctrlz_session", "name: __Host-ctrlz_sid");
    expect(schemeCookie(renamed, "session")).toBe("__Host-ctrlz_sid");
    expect(schemeCookie(renamed, "session")).not.toBe(PANEL_SESSION_COOKIES[0]);
    expect(schemeCookie(panelYaml, "no-such-scheme")).toBeUndefined();
    expect(pathCookies(panelYaml, "/no/such/path")).toEqual([]);
  });

  it("every __Host- literal in the web tier's specs and tests is a name from a contract", () => {
    const known = new Set<string>([...PANEL_SESSION_COOKIES, ...ADMIN_SESSION_COOKIES]);
    const files = [...sourceFiles("apps/panel/e2e"), ...sourceFiles("apps/admin/e2e"), ...sourceFiles("packages/ui/src/proxy"), ...sourceFiles("packages/api-client/src")];
    expect(files.length).toBeGreaterThan(20);
    const stray: string[] = [];
    for (const file of files.filter((f) => !f.endsWith("cookieNames.test.ts"))) {
      for (const name of new Set(readFileSync(file, "utf8").match(COOKIE) ?? [])) if (!known.has(name)) stray.push(`${file.slice(root("").length)}: ${name}`);
    }
    expect(stray).toEqual([]);
  });
});

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (path: string) => {
    for (const entry of readdirSync(path, {withFileTypes: true})) {
      const full = `${path}/${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && entry.name !== "generated") walk(full);
      } else if (/\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith(".d.ts")) {
        out.push(full);
      }
    }
  };
  walk(root(dir));
  return out;
}
