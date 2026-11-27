import {readFileSync} from "node:fs";
import {afterEach, describe, expect, it, vi} from "vitest";

import {ensureThemeApplied} from "./useTheme.ts";

// Gate round 11 (gate-r11-1). The classes of a first visit with mode `system` come from ThemeScript, and a script that React creates on the
// client does not run: on Next's 404 shell (rebuilt by client recovery, gate-r2-1) nothing added them, and a dark OS got a light page. The
// client applies them when it mounts and finds none. The browser case is apps/panel/e2e/theme-script.spec.ts.

function fakeRoot(initial: string[] = ["font-dana"]) {
  const classes = new Set(initial);
  const attrs = new Map<string, string>();
  const root = {
    classList: {
      contains: (c: string) => classes.has(c),
      add: (...names: string[]) => void names.forEach((n) => classes.add(n)),
      remove: (...names: string[]) => void names.forEach((n) => classes.delete(n)),
    },
    setAttribute: (k: string, v: string) => void attrs.set(k, v),
    removeAttribute: (k: string) => void attrs.delete(k),
  };
  return {root: root as unknown as HTMLElement, classes, attrs};
}

function osPrefers(dark: boolean) {
  vi.stubGlobal("matchMedia", (q: string) => ({matches: q.includes("dark") && dark, addEventListener: () => undefined}));
  vi.stubGlobal("requestAnimationFrame", () => 0);
}

afterEach(() => vi.unstubAllGlobals());

describe("ensureThemeApplied", () => {
  it("applies the dark theme for the system mode on a dark OS, and keeps the font class", () => {
    osPrefers(true);
    const {root, classes, attrs} = fakeRoot();
    ensureThemeApplied(root, "system");
    expect([...classes].sort()).toEqual(["dark", "flat-dark", "font-dana"]);
    expect(attrs.get("data-theme")).toBe("dark");
  });

  it("applies the light theme for the system mode on a light OS", () => {
    osPrefers(false);
    const {root, classes, attrs} = fakeRoot();
    ensureThemeApplied(root, "system");
    expect([...classes].sort()).toEqual(["flat-light", "font-dana", "light"]);
    expect(attrs.get("data-theme")).toBe("light");
  });

  it("a mode that names a theme wins over the OS", () => {
    osPrefers(true);
    const {root, classes} = fakeRoot();
    ensureThemeApplied(root, "light");
    expect(classes.has("flat-light")).toBe(true);
    expect(classes.has("dark")).toBe(false);
  });

  it("does nothing when the server or ThemeScript already put a theme on the page", () => {
    osPrefers(true);
    const {root, classes, attrs} = fakeRoot(["font-dana", "light", "flat-light"]);
    ensureThemeApplied(root, "system");
    expect([...classes]).toEqual(["font-dana", "light", "flat-light"]);
    expect(attrs.size).toBe(0);
  });
});

describe("the client fallback is mounted for every page of both apps", () => {
  it("AppProviders renders EnsureTheme", () => {
    // Read from the source: the component sits in the one provider that both root layouts use, so the 404 shell, the fatal state's retry
    // and every page get it. Removing it would leave the e2e case as the only guard.
    const source = readFileSync(new URL("../providers/AppProviders.tsx", import.meta.url), "utf8");
    expect(source).toMatch(/<EnsureTheme\s*\/>/);
  });
});
