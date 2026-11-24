import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

// wp8-r20-1. The behaviour is proved in the browser (apps/panel/e2e/auth.round10.spec.ts); these are the source rules
// that keep it from being undone: a page that holds a secret only in its own state carries it across the language
// switch, and does not hold the switch off for it.
const read = (rel: string) => readFileSync(path.resolve(import.meta.dirname, rel), "utf8");

describe("the language switch carries a fragment that the page offers", () => {
  it("builds the destination's fragment from the offered one, and from the address bar only when none is offered", () => {
    const source = read("localeSwitch.ts");
    expect(source).toMatch(/carriedFragment \? `#\$\{encodeURIComponent\(carriedFragment\)\}` : window\.location\.hash/);
    expect(source.indexOf("carriedFragment ?")).toBeLessThan(source.indexOf("window.location.replace"));
  });

  it("the invite page offers its token and does not hold the switch off before the confirm step", () => {
    const source = read("../auth/InviteFlow.tsx");
    expect(source).toMatch(/useCarryAcrossLocaleSwitch\(/);
    expect(source).not.toMatch(/useReportAuthHolding/);
  });

  // wp8-r21-3: a token the visitor pasted must never reach a URL, so the offer is conditioned on the token having come
  // from the link, and pasting another or restarting clears that.
  it("the invite page offers only the token of a link, and pasting over it takes the offer back", () => {
    const source = read("../auth/InviteFlow.tsx");
    expect(source).toMatch(/useCarryAcrossLocaleSwitch\(fromLink && /);
    expect(source).toMatch(/setFromLink\(true\)/);
    // Pasting another, starting again, and a fragment that is not a token (the token that came from a link is gone, webi-r1-8).
    expect(source.match(/setFromLink\(false\)/g)).toHaveLength(3);
  });
});
