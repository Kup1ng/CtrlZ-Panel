import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// T-310 is wired once: every primary Button that acts is a PrimaryButton, which buzzes before its handler. A page that writes
// `<Button variant="primary">` again would act with no pulse, so this scan fails it.
const root = join(__dirname, "..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "node_modules" ? [] : sources(path);
    return /\.tsx$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}

describe("PrimaryButton (T-310)", () => {
  it("is the only file that gives a Button variant=\"primary\", and it buzzes before the handler", () => {
    const apps = join(root, "../../../apps");
    const files = [...sources(root), ...sources(apps)].filter((file) => !file.endsWith("PrimaryButton.tsx"));
    const direct = files.filter((file) => /variant="primary"/.test(readFileSync(file, "utf8"))).map((file) => file.slice(root.length + 1));
    expect(direct).toEqual([]);
    const own = readFileSync(join(root, "forms/PrimaryButton.tsx"), "utf8");
    expect(own).toMatch(/buzz\(\);\s*onPress\?\.\(event\);/);
  });

  it("is what SubmitButton and the create button of the page header are made of", () => {
    expect(readFileSync(join(root, "forms/SubmitButton.tsx"), "utf8")).toMatch(/<PrimaryButton\b/);
    expect(readFileSync(join(root, "shell/PageHeader.tsx"), "utf8")).toMatch(/<PrimaryButton\b[\s\S]*?onPress=\{onCreate\}/);
  });
});
