import {describe, expect, it} from "vitest";

import enRules from "../../../../i18n/messages/en/rules.json";
import faRules from "../../../../i18n/messages/fa/rules.json";

// WCAG 2.5.3 Label in Name for the buttons of the Profile Options rows (S2-r1-1): a voice-control user says what the button shows, so the
// accessible name must contain its visible text. The Cancel and Save buttons build their names in code from `common` (visible word, colon,
// message), and the Disable and ECS choices put the choice first, so only the names in the table below can drift.

type Tree = {[key: string]: string | Tree};
const messages = {en: enRules as Tree, fa: faRules as Tree};
const lookup = (tree: Tree, key: string) => key.split(".").reduce<string | Tree | undefined>((node, part) => (typeof node === "object" ? node[part] : undefined), tree);

// [visible text key, accessible name key], both in `rules`.
const PAIRS: [string, string][] = [
  ["options.learnMore", "options.learnMoreAria"],
  ["options.ttl.edit", "options.editAria"],
  ["options.ttl.useDefault", "options.ttl.useDefaultAria"],
];

function text(locale: "en" | "fa", key: string): string {
  const found = lookup(messages[locale], key);
  if (typeof found !== "string") throw new Error(`${locale}: no message ${key}`);
  return found;
}

// Case and the Persian/Arabic letter forms do not matter to a person saying the words; placeholders are not words.
const plain = (value: string) => value.replace(/\{[^}]*\}/g, " ").replace(/\u064a/g, "\u06cc").replace(/\u0643/g, "\u06a9").toLocaleLowerCase();

describe("label in name, Profile Options", () => {
  for (const locale of ["en", "fa"] as const) {
    for (const [visible, aria] of PAIRS) {
      it(`${locale}: ${aria} contains the text ${visible} shows`, () => {
        expect(plain(text(locale, aria))).toContain(plain(text(locale, visible)).trim());
      });
    }
  }
});
