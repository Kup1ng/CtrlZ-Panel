import {describe, expect, it} from "vitest";

import {baseUrlFor, defineE2eConfig, readMode} from "./config.ts";

describe("readMode", () => {
  it("defaults to mock and refuses a mistyped mode instead of running the wrong one", () => {
    expect(readMode(undefined)).toBe("mock");
    expect(readMode("")).toBe("mock");
    expect(readMode("stack")).toBe("stack");
    expect(readMode("lab")).toBe("lab");
    expect(() => readMode("stak")).toThrow(/E2E_MODE/);
  });
});

describe("baseUrlFor", () => {
  it("uses the ports of the spec in mock mode and the Caddy hosts in stack mode", () => {
    expect(baseUrlFor("panel", "mock")).toBe("http://localhost:3410");
    expect(baseUrlFor("admin", "mock")).toBe("http://localhost:3411");
    expect(baseUrlFor("panel", "stack")).toBe("https://panel.localhost");
    expect(baseUrlFor("admin", "stack")).toBe("https://admin.localhost");
    expect(baseUrlFor("panel", "mock", "http://localhost:9")).toBe("http://localhost:9");
  });
});

describe("defineE2eConfig", () => {
  it("mock mode: a functional project and the 12 matrix projects, two workers at most", () => {
    const config = defineE2eConfig("panel", {});
    const names = (config.projects ?? []).map((p) => p.name);
    expect(names).toHaveLength(13);
    expect(names[0]).toBe("functional");
    expect(names).toContain("w375-fa-dark");
    expect(names).toContain("w1280-en-light");
    expect(config.workers).toBe(2);
    expect(config.use?.baseURL).toBe("http://localhost:3410");
    expect(config.use?.channel).toBe("chrome");
    expect(config.webServer).toBeUndefined();
    expect(defineE2eConfig("panel", {E2E_WORKERS: "8"}).workers).toBe(2);
    expect(defineE2eConfig("panel", {E2E_WORKERS: "1"}).workers).toBe(1);
  });
  it("starts next start on the app's port only when asked, and only the panel gets the lab flag", () => {
    const panel = defineE2eConfig("panel", {E2E_START_SERVER: "1"});
    const admin = defineE2eConfig("admin", {E2E_START_SERVER: "1"});
    expect(panel.webServer).toMatchObject({command: "pnpm exec next start -p 3410", env: {CTRLZ_LAB: "1"}});
    expect(admin.webServer).toMatchObject({command: "pnpm exec next start -p 3411"});
    expect((admin.webServer as {env: object}).env).not.toHaveProperty("CTRLZ_LAB");
  });
  it("stack mode and lab mode run one worker and their own specs only", () => {
    const stack = defineE2eConfig("panel", {E2E_MODE: "stack"});
    expect(stack.workers).toBe(1);
    expect(stack.projects?.map((p) => p.name)).toEqual(["stack"]);
    expect(stack.use?.baseURL).toBe("https://panel.localhost");
    const lab = defineE2eConfig("panel", {E2E_MODE: "lab"});
    expect(lab.workers).toBe(1);
    expect(lab.projects?.map((p) => p.name)).toEqual(["lab"]);
  });
  it("never retries: a pass on the second try would hide a race", () => {
    expect(defineE2eConfig("panel", {}).retries).toBe(0);
  });
});
