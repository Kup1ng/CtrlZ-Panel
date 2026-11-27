import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {SHARE_TYPE_KEYS, isKnownShareType, shareTypeIcon} from "./shareTypes.ts";

const messages = (lang: "fa" | "en") => JSON.parse(readFileSync(path.resolve(import.meta.dirname, `../../../i18n/messages/${lang}/setup.json`), "utf8")) as {share: {types: Record<string, string>}};

describe("the type names of the share page (spec p3 7.2)", () => {
  it("has a name in both languages for each of the 30 types of the seed, and no other", () => {
    expect(SHARE_TYPE_KEYS).toHaveLength(30);
    for (const lang of ["fa", "en"] as const) expect(Object.keys(messages(lang).share.types).sort(), lang).toEqual([...SHARE_TYPE_KEYS].sort());
  });

  it("draws a type of our own icons, and the generic one for a type a later migration adds", () => {
    expect(shareTypeIcon("windows")).toBe("desktop");
    expect(shareTypeIcon("openwrt")).toBe("router");
    expect(shareTypeIcon("apple_tv")).toBe("tv");
    expect(shareTypeIcon("brand_new_type")).toBe("router");
    expect(isKnownShareType("brand_new_type")).toBe(false);
  });
});
