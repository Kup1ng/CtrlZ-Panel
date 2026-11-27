import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

import en from "../../../../i18n/messages/en/nodes.json";
import fa from "../../../../i18n/messages/fa/nodes.json";

// GP-r1-2. NodeSummary renders t(`node.mode.${node.resolve_mode}`), so every value the admin API can send must have a message in both
// languages: a value without one shows the raw key. The values are read from the generated type of the contract, so a new value
// without its words fails here.
const values = (() => {
  const src = readFileSync(new URL("../../../../api-client/src/generated/admin.d.ts", import.meta.url), "utf8");
  const m = /resolve_mode: ((?:"[a-z_]+"(?: \| )?)+);/.exec(src);
  if (!m) throw new Error("resolve_mode is not in the admin contract");
  return [...(m[1] ?? "").matchAll(/"([a-z_]+)"/g)].map((x) => x[1] ?? "");
})();

describe("node.mode messages", () => {
  it("has a message for every resolve_mode of the admin contract, in both languages", () => {
    expect(values).toContain("hybrid");
    for (const v of values) {
      expect(Object.keys(en.node.mode), v).toContain(v);
      expect(Object.keys(fa.node.mode), v).toContain(v);
    }
  });
});
