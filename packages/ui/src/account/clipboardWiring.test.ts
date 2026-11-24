import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

import {describe, expect, it} from "vitest";

// gate-r8-8. The clipboard wipe is wired by the component that offers a Copy: nothing in the module can know that a dialog closed. A
// browser test per dialog is in account.spec.ts, but a new dialog would have none, so this reads the source: whoever calls
// copyOneTimeSecret must be in a reviewed file, and every component there that calls it must also mount the wipe. The reviewed files are the
// panel's account dialogs (TotpRow) and the admin's one CopyButton, which every admin copy of a one-time value goes through (merge of WP10).
const root = fileURLToPath(new URL("../../../..", import.meta.url));

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".next" || name === "generated") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name)) out.push(path);
  }
  return out;
}

describe("the clipboard wipe is wired wherever a Copy of a one-time secret is offered (gate-r8-8)", () => {
  const files = [...sources(join(root, "packages/ui/src")), ...sources(join(root, "apps/panel/src")), ...sources(join(root, "apps/admin/src"))];
  const REVIEWED = ["packages/ui/src/account/TotpRow.tsx", "packages/ui/src/admin/shared/CopyButton.tsx"];
  const callers = files.filter((f) => /\bcopyOneTimeSecret\(/.test(readFileSync(f, "utf8")));

  it("is called from the reviewed files only, so a new caller has to extend this test", () => {
    expect(callers.map((f) => f.slice(root.length).replaceAll("\\", "/")).sort()).toEqual([...REVIEWED].sort());
  });

  it("is mounted by every component of the panel file that calls it, or by the component that renders it", () => {
    const text = readFileSync(callers.find((f) => f.endsWith("TotpRow.tsx"))!, "utf8");
    // Top-level components and hooks start at column 0.
    const blocks = text.split(/^(?=(?:export )?function )/m);
    const nameOf = (block: string) => /^(?:export )?function (\w+)/.exec(block)?.[1] ?? "";
    const mounts = (block: string) => block.includes("useWipeCopiedOnClose();");
    const withCopy = blocks.filter((b) => /\bcopyOneTimeSecret\(/.test(b));
    expect(withCopy.length).toBeGreaterThanOrEqual(2);
    for (const block of withCopy) {
      const name = nameOf(block);
      // The dialog's own component closes with the dialog, so a child that is rendered inside one that mounts the wipe is covered by it.
      const covered = mounts(block) || blocks.some((other) => other !== block && mounts(other) && new RegExp("<" + name + "\\b").test(other));
      expect(covered, name + " offers a Copy of a one-time secret and nothing wipes it when its dialog closes").toBe(true);
    }
    // Both dialogs that show the codes mount the wipe themselves or through CodesView, which mounts it.
    const codesView = blocks.find((b) => nameOf(b) === "CodesView")!;
    expect(mounts(codesView)).toBe(true);
    for (const block of blocks.filter((b) => ["EnableWizard", "RegenerateDialog"].includes(nameOf(b)))) expect(mounts(block) || block.includes("<CodesView"), nameOf(block)).toBe(true);
  });

  it("is mounted by the admin's CopyButton, which is on screen exactly as long as the value it copies", () => {
    const text = readFileSync(callers.find((f) => f.endsWith("CopyButton.tsx"))!, "utf8");
    expect(text).toContain("useWipeCopiedOnClose();");
    // Nothing in the admin may write to the clipboard on its own: ctrlz/no-storage says so too, and this keeps the pair of them honest.
    expect(text).not.toContain("navigator.clipboard");
  });
});
