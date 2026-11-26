import {describe, expect, it} from "vitest";

import {HEIGHTS, MATRIX, projectName, readMatrix} from "./matrix.ts";

describe("the matrix of spec 17.1", () => {
  it("has 12 projects: three widths, two languages, two themes", () => {
    expect(MATRIX).toHaveLength(12);
    expect(new Set(MATRIX.map(projectName)).size).toBe(12);
    expect(projectName({width: 375, lang: "fa", theme: "dark"})).toBe("w375-fa-dark");
  });
  it("uses the heights of the spec", () => {
    expect(HEIGHTS).toEqual({375: 812, 768: 1024, 1280: 800});
  });
  it("reads a project's metadata back, and nothing else", () => {
    const m = {width: 768, lang: "en", theme: "light"} as const;
    expect(readMatrix({matrix: m})).toEqual(m);
    expect(readMatrix({})).toBeNull();
    expect(readMatrix(undefined)).toBeNull();
    expect(readMatrix({matrix: {width: 500, lang: "en", theme: "light"}})).toBeNull();
  });
});
