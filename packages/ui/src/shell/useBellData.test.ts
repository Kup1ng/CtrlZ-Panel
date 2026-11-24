import {describe, expect, it} from "vitest";

import {safeInternalPath} from "./useBellData.ts";

const BACKSLASH = String.fromCharCode(92);

describe("safeInternalPath", () => {
  it("follows an app path", () => {
    expect(safeInternalPath("/preferences/account")).toBe("/preferences/account");
    expect(safeInternalPath("/profiles?x=1#y")).toBe("/profiles?x=1#y");
    expect(safeInternalPath("/endpoints/abc.def")).toBe("/endpoints/abc.def");
    expect(safeInternalPath("/analytics")).toBe("/analytics");
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
      // Dot segments: the URL parser removes them and what is left is protocol-relative (wp4-r17-1).
      "/..//x.example/a",
      "/profiles/..//x.example",
      "/%2e%2e//x.example",
      "/%2E%2E/x",
      "/a/../..//x.example",
      "/profiles/../preferences",
      "/profiles/./x",
      "/profiles/%2e%2e/x",
      "/profiles/%252e%252e/x",
      // A trailing space is trimmed by the URL parser, which then folds the dot segment (wp4-r18-1).
      "/profiles/.. ",
      "/profiles/%2e%2e ",
      "/preferences/.%2E ",
      "/profiles/%2f%2fx.example",
      "/profiles/%5cx.example",
      // Outside every known panel prefix.
      "/unknown/page",
      "/",
      "",
      undefined,
      null,
    ]) {
      expect(safeInternalPath(link as string | undefined | null), String(link)).toBeUndefined();
    }
  });
});
