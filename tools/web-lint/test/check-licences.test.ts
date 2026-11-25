import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

import {checkLicences, expressionAllowed, parseAllow} from "../check-licences.mjs";

const allow = `
type MIT # the bulk
type ISC # permissive
type CC0-1.0 # dedication
package heroui-pro # build-time CLI
package @img/sharp-* # optional binaries
`;

const pkg = (name: string) => ({name, versions: ["1.0.0"]});

describe("check-licences (spec 16.2 step 8)", () => {
  it("passes listed types, SPDX expressions made of them, and named packages", () => {
    const listing = {
      MIT: [pkg("a")],
      "(MIT OR CC0-1.0)": [pkg("b")],
      "MIT AND ISC": [pkg("c")],
      UNLICENSED: [pkg("heroui-pro")],
      "Apache-2.0 AND LGPL-3.0-or-later": [pkg("@img/sharp-win32-x64")],
    };
    expect(checkLicences(listing, allow)).toEqual([]);
  });

  it("fails a new licence type, and an expression with one part that is not listed", () => {
    const found = checkLicences({GPL3: [pkg("x")], "MIT AND GPL-3.0-only": [pkg("y")], MIT: [pkg("z")]}, allow.replace(/package .*\n/g, ""));
    expect(found.join("\n")).toContain("x@1.0.0");
    expect(found.join("\n")).toContain("y@1.0.0");
    expect(found.join("\n")).not.toContain("z@1.0.0");
  });

  it("fails a package that is not named when its licence is not allowed, even if its neighbour is", () => {
    expect(checkLicences({UNLICENSED: [pkg("someone-else")]}, allow).join("\n")).toContain("someone-else");
  });

  it("fails an allow line that matches nothing, so a stale exception does not wait for the next package of that name", () => {
    const found = checkLicences({MIT: [pkg("a")]}, allow);
    expect(found.join("\n")).toContain('"heroui-pro"');
    expect(found.join("\n")).toContain('"@img/sharp-*"');
  });

  it("refuses an allow line with no reason, or one it cannot read", () => {
    expect(parseAllow("type MIT\n").problems.join()).toContain("no reason");
    expect(parseAllow("allow MIT # why\n").problems.join()).toContain("not");
  });

  it("reads an expression", () => {
    const types = new Set(["MIT", "ISC"]);
    expect(expressionAllowed("MIT AND ISC", types)).toBe(true);
    expect(expressionAllowed("(MIT OR ISC)", types)).toBe(true);
    expect(expressionAllowed("MIT AND GPL", types)).toBe(false);
    expect(expressionAllowed("Unknown", types)).toBe(false);
  });

  it("the real allow file is well formed", () => {
    const text = readFileSync(fileURLToPath(new URL("../licences.allow.txt", import.meta.url)), "utf8");
    expect(parseAllow(text).problems).toEqual([]);
  });
});
