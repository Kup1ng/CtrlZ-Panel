import {readdirSync, readFileSync} from "node:fs";
import path from "node:path";
import {describe, expect, it} from "vitest";

import {hrefWithNext} from "./authHref.ts";

describe("hrefWithNext", () => {
  it("carries a next the proxy accepts, encoded", () => {
    expect(hrefWithNext("/register", "/endpoints/abc")).toBe("/register?next=%2Fendpoints%2Fabc");
    expect(hrefWithNext("/login", "/profiles?tab=1")).toBe("/login?next=%2Fprofiles%3Ftab%3D1");
  });

  it("drops a next the proxy would refuse, so a link cannot launder it", () => {
    for (const bad of ["//evil.example", "https://evil.example", "/profiles/../x", "/other", "", null, undefined]) {
      expect(hrefWithNext("/invite", bad)).toBe("/invite");
    }
  });
});

// wp8-r9-5, the class: a link from one page of the sign-in family to another that does not go through the helper
// forgets `next`. Every `href="/login|register|invite|forgot-password"` in these files must be `href={href(...)}`.
describe("the links between the sign-in pages", () => {
  const dir = import.meta.dirname;
  const files = readdirSync(dir).filter((f) => /\.tsx$/.test(f) && !/\.test\./.test(f));
  const bare = /href="\/(login|register|invite|forgot-password)"/;

  it("none is written as a bare path", () => {
    const offenders = files.filter((f) => bare.test(readFileSync(path.join(dir, f), "utf8")));
    expect(offenders).toEqual([]);
  });

  it("the scan sees a bare link", () => {
    expect(bare.test('<Link href="/register">x</Link>')).toBe(true);
    expect(bare.test("<Link href={href(\"/register\")}>x</Link>")).toBe(false);
  });
});
