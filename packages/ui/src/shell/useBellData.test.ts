import {describe, expect, it} from "vitest";

import {safeInternalPath} from "./useBellData.ts";

const BACKSLASH = String.fromCharCode(92);

describe("safeInternalPath", () => {
  it("follows an app path", () => {
    expect(safeInternalPath("/preferences/account")).toBe("/preferences/account");
    expect(safeInternalPath("/profiles?x=1#y")).toBe("/profiles?x=1#y");
  });

  it("ignores anything that could leave the app", () => {
    for (const link of [
      "//evil.example/x",
      "https://evil.example",
      "javascript:alert(1)",
      `/${BACKSLASH}evil.example`,
      `${BACKSLASH}${BACKSLASH}evil.example`,
      "profiles",
      "/ok\nHeader: x",
      "/ok\u0000",
      "",
      undefined,
      null,
    ]) {
      expect(safeInternalPath(link as string | undefined | null), String(link)).toBeUndefined();
    }
  });
});
