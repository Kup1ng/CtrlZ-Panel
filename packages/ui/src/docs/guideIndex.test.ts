import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {PANEL_ROUTES} from "../testing/routes.ts";
import {GUIDE_SECTIONS} from "./guideIndex.ts";

const messages = (lang: "fa" | "en") => JSON.parse(readFileSync(path.resolve(import.meta.dirname, `../../../i18n/messages/${lang}/api.json`), "utf8")) as {docsPage: {sections: Record<string, string>; entries: Record<string, {title: string; text: string}>}};

describe("the index of /docs (spec p3 10, T-125)", () => {
  const entries = GUIDE_SECTIONS.flatMap((section) => section.entries);

  it("points only at pages of the panel: an absolute path of an allowed route, never an address", () => {
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(entry.href, entry.id).toMatch(/^\/[a-z]/);
      expect(entry.href, entry.id).not.toMatch(/^\/\/|:/);
      expect(PANEL_ROUTES, entry.id).toContain(entry.href);
    }
  });

  it("has a title and a line for each entry and a name for each section, in both languages", () => {
    for (const lang of ["fa", "en"] as const) {
      const {sections, entries: texts} = messages(lang).docsPage;
      for (const section of GUIDE_SECTIONS) expect(sections[section.id], `${lang}: ${section.id}`).toBeTruthy();
      for (const entry of entries) {
        expect(texts[entry.id]?.title, `${lang}: ${entry.id}`).toBeTruthy();
        expect(texts[entry.id]?.text, `${lang}: ${entry.id}`).toBeTruthy();
      }
      expect(Object.keys(texts).sort(), lang).toEqual(entries.map((e) => e.id).sort());
    }
  });
});
