/// <reference types="node" />
import {readdirSync, readFileSync, statSync} from "node:fs";
import path from "node:path";

import {beforeAll, describe, expect, it} from "vitest";

// wp4-r15-1 and wp4-r16-2. A "logout" message takes every other tab down, live ones included, so only a
// logout the server answered may post it. That is `logoutAndLeave`, which passes broadcast: true to
// `logoutLocal` itself. The safe value is the default of `logoutLocal` (no option means no message), so
// a forgotten option fails closed, and this test is the backstop: no call outside api-client's
// session.ts may name `broadcast` with anything but `false`, whatever its shape. The test reads the
// sources, so a new leave path that tries to opt in fails here, not in a user's second tab.

// packages/ (ui, api-client, any other package) and apps/ (the pages of WP8 to WP11 live there).
const packages = path.resolve(__dirname, "../../..");
const roots = [packages, path.resolve(packages, "../apps")];

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".next" || name === "generated") continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) sources(full, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/**
 * The argument text of every `logoutLocal(...)` call, found by counting parentheses, so a call in an
 * arrow expression (`() => logoutLocal({queryClient, locale})`), with no `;` after it, or on several
 * lines is read to its own closing parenthesis and no further.
 */
export function logoutLocalCalls(text: string): string[] {
  const calls: string[] = [];
  const code = stripComments(text);
  for (const m of code.matchAll(/(?<![\w.])logoutLocal\(/g)) {
    let depth = 1;
    let i = m.index! + m[0].length;
    const start = i;
    let quote = "";
    for (; i < code.length && depth > 0; i++) {
      const c = code[i]!;
      if (quote) {
        if (c === "\\") i++;
        else if (c === quote) quote = "";
      } else if (c === '"' || c === "'" || c === "`") quote = c;
      else if (c === "(") depth++;
      else if (c === ")") depth--;
    }
    calls.push(code.slice(start, i - 1));
  }
  return calls;
}

/** True when the call's arguments name `broadcast` with anything but the literal false. */
export function optsIn(args: string): boolean {
  return [...args.matchAll(/\bbroadcast\b(?!\s*:\s*false\b)/g)].length > 0;
}

describe("the call finder", () => {
  it("reads an arrow-expression call that has no ';' after it", () => {
    const text = "const a = <B onPress={() => logoutLocal({queryClient, locale}, {broadcast: true})} />;\nfoo({broadcast: false});";
    expect(logoutLocalCalls(text)).toEqual(["{queryClient, locale}, {broadcast: true}"]);
  });

  it("stops at its own closing parenthesis, over several lines and with parentheses in strings", () => {
    const text = [
      "function f() {",
      "  logoutLocal(",
      "    {queryClient, locale},",
      "    {next: currentNext(\"panel\"), label: \")\"},",
      "  )",
      "  other({broadcast: true});",
      "}",
    ].join("\n");
    const calls = logoutLocalCalls(text);
    expect(calls).toHaveLength(1);
    expect(optsIn(calls[0]!)).toBe(false);
  });

  it("ignores comments and method calls of other objects", () => {
    expect(logoutLocalCalls("// logoutLocal({broadcast: true})\n/* logoutLocal(x) */\nsession.logoutLocal(a)")).toEqual([]);
  });

  it("flags true, a variable, a shorthand and a spread, and lets false pass", () => {
    expect(optsIn("c, {broadcast: true}")).toBe(true);
    expect(optsIn("c, {broadcast: shouldTell}")).toBe(true);
    expect(optsIn("c, {broadcast}")).toBe(true);
    expect(optsIn("c, {...options, broadcast: !x}")).toBe(true);
    expect(optsIn("c, {broadcast: false, next}")).toBe(false);
    expect(optsIn("c")).toBe(false);
    expect(optsIn("c, {next}")).toBe(false);
  });
});

describe("logoutLocal and the logout broadcast", () => {
  // Read once per file, not once per test: three tests re-read about 216 files each, which took 9 s under load (gate-r3-1).
  let cache: {file: string; text: string}[] | undefined;
  const scanned = () => (cache ??= roots.flatMap((r) => sources(r)).map((file) => ({file, text: readFileSync(file, "utf8")})));
  const files = () => scanned().map((s) => s.file);
  // Primed in beforeAll with its own time limit, so the walk is not charged to whichever case runs first: on a busy machine the whole
  // suite runs in parallel with the browsers, and one walk of the growing tree passed the 5 s default of one case (wp10-r5).
  beforeAll(() => {
    scanned();
  }, 60_000);
  const isSession = (f: string) => f.endsWith(path.join("api-client", "src", "session.ts")); // its own definition and logoutAndLeave

  it("is never asked to broadcast outside session.ts", () => {
    const calls: string[] = [];
    for (const {file, text} of scanned()) {
      if (isSession(file)) continue;
      for (const args of logoutLocalCalls(text)) {
        if (optsIn(args)) calls.push(`${path.relative(packages, file)}: logoutLocal(${args.trim()})`);
      }
    }
    expect(calls).toEqual([]);
  });

  it("is not imported under another name, which the call finder would not see", () => {
    const aliased = scanned()
      .filter((s) => !isSession(s.file))
      .filter((s) => /\blogoutLocal\s+as\s+\w+/.test(stripComments(s.text)));
    expect(aliased.map((s) => path.relative(packages, s.file))).toEqual([]);
  });

  it("finds the calls it is meant to check", () => {
    const all = scanned().filter((s) => /logoutLocal\(/.test(s.text));
    expect(all.map((s) => path.basename(s.file))).toEqual(expect.arrayContaining(["SessionGate.tsx", "handleApiError.ts", "me.ts"]));
  });

  it("scans the apps as well as the packages", () => {
    const all = files();
    expect(all.some((f) => f.includes(`${path.sep}apps${path.sep}panel${path.sep}`))).toBe(true);
    expect(all.some((f) => f.includes(`${path.sep}apps${path.sep}admin${path.sep}`))).toBe(true);
  });
});
