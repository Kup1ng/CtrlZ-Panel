import {readFileSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// T-546, T-561. The runbook exists twice: the file docs/runbooks/p4-nodes.md of the Panel repository, which the operator reads at a
// terminal, and the page `/runbook` in the admin app, whose text is nodes.json `runbook.*`, so that the link from the Nodes page never
// leaves the origin. They are written apart, so what keeps them one runbook is that every list has the same steps in the file, in
// English and in Persian. A step added to one place only fails here.

const doc = readFileSync(join(__dirname, "../../../../../docs/runbooks/p4-nodes.md"), "utf8");
const messages = join(__dirname, "../../../../i18n/messages");

type Runbook = {
  compromise: {steps: Record<string, string>};
  retire: {steps: Record<string, string>};
  free: {steps: Record<string, string>};
};
type Nodes = {runbook: Runbook; replacement: {steps: Record<string, string>}};

/** The lines of a `## <title>` section of the file that start like a list item (`1.` or `-`), by kind. */
function items(title: string, kind: "numbered" | "bullet"): number {
  const start = doc.indexOf(`\n## ${title}\n`);
  if (start < 0) throw new Error(`no section "${title}" in docs/runbooks/p4-nodes.md`);
  const rest = doc.slice(start + 1).split("\n").slice(1);
  const end = rest.findIndex((line) => line.startsWith("## "));
  const body = end < 0 ? rest : rest.slice(0, end);
  const mark = kind === "numbered" ? /^\d+\. / : /^- /;
  return body.filter((line) => mark.test(line)).length;
}

describe("docs/runbooks/p4-nodes.md and the runbook page", () => {
  for (const locale of ["en", "fa"]) {
    const nodes = JSON.parse(readFileSync(join(messages, locale, "nodes.json"), "utf8")) as Nodes;
    const count = (steps: Record<string, string>) => Object.keys(steps).length;

    it(`has the compromise steps of the page in ${locale}, in numbered order`, () => {
      expect(count(nodes.runbook.compromise.steps)).toBe(8);
      expect(items("Compromise", "numbered")).toBe(count(nodes.runbook.compromise.steps));
    });

    it(`has the retire steps of the page in ${locale}`, () => {
      expect(items("Retire a node", "numbered")).toBe(count(nodes.runbook.retire.steps));
    });

    it(`has the free DNS cases of the page in ${locale}`, () => {
      expect(count(nodes.runbook.free.steps)).toBe(3);
      expect(items("Free DNS", "bullet")).toBe(count(nodes.runbook.free.steps));
    });

    it(`has the replacement order of the Nodes page in ${locale}`, () => {
      expect(items("Replacement order", "numbered")).toBe(count(nodes.replacement.steps));
    });
  }

  it("names the free outgoing interface option the installer takes", () => {
    expect(doc).toContain("--free-outgoing-ip");
  });
});
