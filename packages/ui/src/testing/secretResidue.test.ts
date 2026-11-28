import {describe, expect, it} from "vitest";

import type {TrailEntry} from "./guardLogic.ts";
import {findResidue, type ResidueSnapshot} from "./secretResidue.ts";

const clean = (): ResidueSnapshot => ({
  url: "http://localhost:3420/fa/account?helpPane=account",
  historyState: '{"__NA":true,"key":"abc"}',
  cookie: "sidebar_state=true; ctrlz_theme=dark; __Host-ctrlz_session=x",
  windowName: "",
  local: [["ctrlz.haptics", "1"]],
  session: [
    ["ctrlz_clip_pending", "1"],
    ["ctrlz.dialog.pushed.helpPane", "1"],
  ],
  caches: [],
  databases: [],
});

const SECRET = "JBSWY3DPEHPK3PXP";

describe("findResidue (gate-r16-8)", () => {
  it("finds nothing on a page that holds only what our code writes", () => {
    expect(findResidue(clean(), [SECRET, "Correct-Horse-9"])).toEqual([]);
  });

  it.each([
    ["the address", (s: ResidueSnapshot) => (s.url += `?secret=${SECRET}`)],
    ["the address, percent-encoded", (s: ResidueSnapshot) => (s.url += `#${encodeURIComponent("Correct Horse/9")}`)],
    ["history.state", (s: ResidueSnapshot) => (s.historyState = JSON.stringify({code: SECRET}))],
    ["window.name", (s: ResidueSnapshot) => (s.windowName = SECRET)],
    ["a cookie", (s: ResidueSnapshot) => (s.cookie += `; x=${SECRET}`)],
    ["a localStorage value", (s: ResidueSnapshot) => s.local.push(["ctrlz.haptics2", SECRET])],
    ["a sessionStorage value", (s: ResidueSnapshot) => (s.session[0] = ["ctrlz_clip_pending", SECRET])],
    ["a storage key", (s: ResidueSnapshot) => s.session.push([`ctrlz.${SECRET}`, "1"])],
    ["a Cache Storage url", (s: ResidueSnapshot) => s.caches.push(`http://x/?t=${SECRET}`)],
    ["an IndexedDB name", (s: ResidueSnapshot) => s.databases.push(SECRET)],
  ])("finds a secret in %s", (_place, put) => {
    const snapshot = clean();
    put(snapshot);
    expect(findResidue(snapshot, ["Correct Horse/9", SECRET]).length).toBeGreaterThan(0);
  });

  describe("the record of what the flow wrote (gate-r17-5)", () => {
    const entry = (kind: TrailEntry["kind"], text: string): TrailEntry => ({kind, text});

    it("finds a secret in each kind of entry, on a page that is clean at the end", () => {
      for (const [kind, label] of [
        ["history", "a history.pushState or replaceState call"],
        ["navigated", "the address of a navigation"],
        ["console", "a console message"],
        ["pageerror", "a page error"],
      ] as const) {
        const found = findResidue(clean(), ["other-secret", SECRET], [entry("navigated", "http://x/fa/login"), entry(kind, `pushState ?t=${SECRET} {}`)]);
        expect(found, kind).toEqual([`${label} (entry #1 of the flow's record) holds secret #1`]);
        expect(JSON.stringify(found)).not.toContain(SECRET);
      }
    });

    it("finds a percent-encoded secret, and reports one line for each place and secret", () => {
      const trail = [entry("console", `a ${encodeURIComponent("Correct Horse/9")}`), entry("console", "Correct Horse/9 again"), entry("history", "replaceState Correct Horse/9 {}")];
      expect(findResidue(clean(), ["Correct Horse/9"], trail)).toHaveLength(2);
    });

    it("exempts the address of the link that the visitor arrived with, and judges what comes after the page strips it (gate-r17-5)", () => {
      const link = [entry("navigated", `http://x/fa/invite#${SECRET}`), entry("history", `replaceState /fa/invite#${SECRET} {"__NA":true}`)];
      const stripped = entry("history", 'replaceState /fa/invite {"__NA":true}');
      expect(findResidue(clean(), [SECRET], [...link, stripped], [SECRET])).toEqual([]);
      // The same secret, written again after the strip: a real leak.
      const again = entry("history", `pushState /fa/invite?x={"t":"${SECRET}"}`);
      expect(findResidue(clean(), [SECRET], [...link, stripped, again], [SECRET])).toEqual([
        "a history.pushState or replaceState call (entry #3 of the flow's record) holds secret #0",
      ]);
      // Without the exemption the link itself is found, so the option is what lets it through.
      expect(findResidue(clean(), [SECRET], [...link, stripped])).toHaveLength(2);
      // A console line is never part of the link.
      expect(findResidue(clean(), [SECRET], [...link, stripped, entry("console", SECRET)], [SECRET])).toHaveLength(1);
      // A page that never strips holds it in the address, which has no exemption.
      const unstripped = clean();
      unstripped.url += `#${SECRET}`;
      expect(findResidue(unstripped, [SECRET], link, [SECRET])).toEqual(["the address holds secret #0"]);
    });

    // gate-r18-5: the exemption is the link, which is a navigation and a history call that writes the address back. Nothing else written before the page
    // strips the secret is part of it, so each of these must be reported although it comes before the strip.
    it("judges a console line, a page error and a history state that holds the secret even before the strip (gate-r18-5)", () => {
      const nav = entry("navigated", `http://x/fa/invite#${SECRET}`);
      const link = entry("history", `replaceState /fa/invite#${SECRET} {"__NA":true}`);
      const strip = entry("history", 'replaceState /fa/invite {"__NA":true}');
      const place = {console: "a console message", pageerror: "a page error"} as const;
      for (const kind of ["console", "pageerror"] as const) {
        expect(findResidue(clean(), [SECRET], [nav, entry(kind, `hash ${SECRET}`), link, strip], [SECRET]), kind).toEqual([`${place[kind]} (entry #1 of the flow's record) holds secret #0`]);
      }
      // A clean address with the secret in the state (a push instead of a replace, the code left in a back entry).
      const pushed = entry("history", `pushState /fa/invite {"invite":"${SECRET}"}`);
      expect(findResidue(clean(), [SECRET], [nav, pushed, link, strip], [SECRET])).toEqual([
        "a history.pushState or replaceState call (entry #1 of the flow's record) holds secret #0",
      ]);
      // The strip itself carrying the code in its state: the address is clean, so it is where judging starts, and it is found.
      const stripWithState = entry("history", `pushState /fa/invite {"invite":"${SECRET}"}`);
      expect(findResidue(clean(), [SECRET], [nav, link, stripWithState], [SECRET])).toHaveLength(1);
      // An address that still holds the secret and a state that holds it too is not the link.
      const both = entry("history", `pushState /fa/invite#${SECRET} {"invite":"${SECRET}"}`);
      expect(findResidue(clean(), [SECRET], [nav, both, strip], [SECRET])).toHaveLength(1);
      // The control: the same trail with only the link entries is clean.
      expect(findResidue(clean(), [SECRET], [nav, link, strip], [SECRET])).toEqual([]);
    });

    it("reports a second secret on an entry that is exempt for the first (gate-r18-5)", () => {
      const nav = entry("navigated", `http://x/fa/invite#${SECRET}`);
      const both = entry("history", `replaceState /fa/invite#${SECRET} {"pw":"Correct-Horse-9"}`);
      const strip = entry("history", "replaceState /fa/invite {}");
      expect(findResidue(clean(), [SECRET, "Correct-Horse-9"], [nav, both, strip], [SECRET])).toEqual([
        "a history.pushState or replaceState call (entry #1 of the flow's record) holds secret #1",
      ]);
    });

    it("refuses an arrivedWith value that is not one of the secrets", () => {
      expect(() => findResidue(clean(), [SECRET], [], ["other"])).toThrow(/not one of the secrets/);
    });

    it("finds nothing in a record that holds no secret", () => {
      expect(findResidue(clean(), [SECRET], [entry("history", 'replaceState  {"__NA":true}'), entry("console", "ok")])).toEqual([]);
    });
  });

  it("names the place and the position, and never the secret", () => {
    const snapshot = clean();
    snapshot.session.push(["ctrlz.reset", SECRET]);
    const found = findResidue(snapshot, ["other-secret", SECRET]);
    expect(found).toEqual(["sessionStorage value of ctrlz.reset holds secret #1"]);
    expect(JSON.stringify(found)).not.toContain(SECRET);
  });

  it("refuses a storage key or a cookie that our code does not write, whatever it holds", () => {
    const snapshot = clean();
    snapshot.local.push(["draft", "hello"]);
    snapshot.cookie += "; analytics_id=1";
    snapshot.caches.push("http://x/y");
    snapshot.databases.push("db");
    expect(findResidue(snapshot, [SECRET])).toEqual([
      "the cookie analytics_id is not one that our code writes",
      "localStorage key draft is not one that our code writes",
      "Cache Storage has entries: the apps write none",
      "IndexedDB has databases: the apps write none",
    ]);
  });

  it("refuses a secret too short to mean anything, so the check cannot pass or fail for nothing", () => {
    expect(() => findResidue(clean(), [""])).toThrow(/shorter than 4/);
    expect(() => findResidue(clean(), ["123"])).toThrow(/shorter than 4/);
  });
});
