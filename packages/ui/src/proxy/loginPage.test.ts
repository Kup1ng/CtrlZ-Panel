import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {afterEach, describe, expect, it} from "vitest";

import {hasLoginPage} from "./loginPage.ts";

const dirs: string[] = [];
function app(files: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "ctrlz-login-"));
  dirs.push(dir);
  for (const f of files) {
    mkdirSync(join(dir, f, ".."), {recursive: true});
    writeFileSync(join(dir, f), "export default null;\n");
  }
  return dir;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, {recursive: true, force: true});
});

describe("hasLoginPage (wp5-r16-2)", () => {
  it("finds the page at the plain path and inside a route group", () => {
    expect(hasLoginPage(app(["src/app/[locale]/login/page.tsx"]))).toBe(true);
    expect(hasLoginPage(app(["src/app/[locale]/(auth)/login/page.tsx"]))).toBe(true);
    expect(hasLoginPage(app(["src/app/[locale]/(public)/login/page.ts"]))).toBe(true);
  });
  it("does not take a page that is not the login, a login folder without a page, a deeper folder, or a folder that is not a group", () => {
    expect(hasLoginPage(app(["src/app/[locale]/page.tsx", "src/app/[locale]/layout.tsx"]))).toBe(false);
    expect(hasLoginPage(app(["src/app/[locale]/(auth)/login/layout.tsx"]))).toBe(false);
    expect(hasLoginPage(app(["src/app/[locale]/(auth)/x/login/page.tsx"]))).toBe(false);
    expect(hasLoginPage(app(["src/app/[locale]/auth/login/page.tsx"]))).toBe(false);
  });
  it("is false for an app with no folder at all", () => {
    expect(hasLoginPage(app([]))).toBe(false);
  });
});

describe("hasLoginPage on the real panel", () => {
  it("sees the panel's login, which lives in the (auth) group", () => {
    expect(hasLoginPage(fileURLToPath(new URL("../../../../apps/panel", import.meta.url)))).toBe(true);
  });
});
