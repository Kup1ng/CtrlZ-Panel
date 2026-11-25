import {afterEach, describe, expect, it, vi} from "vitest";
import type {FullResult, TestCase, TestResult} from "@playwright/test/reporter";

import AxeSummary from "./axeReporter.ts";

const test = (...annotations: {type: string; description?: string}[]) => ({annotations}) as unknown as TestCase;

afterEach(() => vi.restoreAllMocks());

describe("the axe run summary (T-473)", () => {
  it("prints the known failures and the incomplete results of the run, counted, and nothing else", () => {
    const out: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => void out.push(a.join(" ")));
    const r = new AxeSummary();
    r.onTestEnd(test({type: "axe-known", description: "dialogs: color-contrast: .muted"}), {} as TestResult);
    r.onTestEnd(test({type: "axe-known", description: "dialogs: color-contrast: .muted"}, {type: "axe-incomplete", description: "dialogs: color-contrast (3 nodes)"}, {type: "skip"}), {} as TestResult);
    r.onEnd({} as FullResult);
    const text = out.join("\n");
    expect(text).toContain("known failures met in this run (axe-known.json, DESIGN.md Q1 to Q4) (1):");
    expect(text).toContain("dialogs: color-contrast: .muted x2");
    expect(text).toContain("incomplete, left to a manual look (1)");
    expect(text).toContain("dialogs: color-contrast (3 nodes)");
    expect(text).not.toContain("skip");
  });

  it("prints nothing when no test met either", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const r = new AxeSummary();
    r.onTestEnd(test({type: "slow"}), {} as TestResult);
    r.onEnd({} as FullResult);
    expect(log).not.toHaveBeenCalled();
  });
});
