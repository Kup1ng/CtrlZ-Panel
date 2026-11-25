import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// A class test for wp10-r1-1. `form.fail(error, {field})` puts the failure under a field even when the error has no
// `fields` of its own, so a field named by a failure the code did not check shows a 500, a busy server or a dropped
// connection as "this value is wrong" and sends the admin to rewrite a correct value. Every such call in the admin app
// has to sit behind a `hasCode(...)` of the codes that are about that field.

const root = join(__dirname);

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}

describe("fail with a field in the admin app", () => {
  it("is only called for an error that was checked with hasCode", () => {
    const loose: string[] = [];
    for (const file of sources(root)) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (!/\.fail\([^)]*\{[^}]*field:/.test(line)) return;
        // The check is on this line or in the few above it (an `if` and its block).
        const near = lines.slice(Math.max(0, i - 3), i + 1).join("\n");
        if (!/hasCode\(/.test(near)) loose.push(`${file}:${i + 1}`);
      });
    }
    expect(loose).toEqual([]);
  });
});
