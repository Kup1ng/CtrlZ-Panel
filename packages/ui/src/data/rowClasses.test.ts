import {readdirSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {describe, expect, it} from "vitest";

// Spec 6: a component that needs a rounded square or a thin control names a row of radius.table.ts
// and never types the formula, so a change of the ratio or the cap reaches every copy (wp7-r1-4). The
// scan covers the data rows and the feedback states, where the copies were found.
function sources(dir: string): string[] {
  return readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
    e.isDirectory() ? sources(join(dir, e.name)) : /\.(tsx?|css)$/.test(e.name) && !/\.test\./.test(e.name) ? [join(dir, e.name)] : [],
  );
}

describe("row corners", () => {
  for (const dir of ["../data", "../feedback"]) {
    for (const file of sources(fileURLToPath(new URL(dir, import.meta.url)))) {
      it(`${file.split(/[\\/]src[\\/]/)[1]} types no corner formula`, () => {
        expect(readFileSync(file, "utf8")).not.toMatch(/radius-control-(ratio|cap)|rounded-\[/);
      });
    }
  }
});
