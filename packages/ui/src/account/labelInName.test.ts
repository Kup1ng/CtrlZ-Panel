import {readdirSync, readFileSync} from "node:fs";
import path from "node:path";
import {describe, expect, it} from "vitest";

import enAccount from "../../../i18n/messages/en/account.json";
import enCommon from "../../../i18n/messages/en/common.json";
import faAccount from "../../../i18n/messages/fa/account.json";
import faCommon from "../../../i18n/messages/fa/common.json";

// WCAG 2.5.3 Label in Name (wp9-r3-4): a voice-control user says what the button shows, so the accessible name of a
// button must contain its visible text. InlineEditRow documents it for `editAriaLabel`; this is the one test that
// keeps every row of the Account page to it, in both languages, and finds a row that is added without a line here.

type Tree = {[key: string]: string | Tree};
const messages = {
  en: {account: enAccount as Tree, common: enCommon as Tree},
  fa: {account: faAccount as Tree, common: faCommon as Tree},
};
const lookup = (tree: Tree, key: string) => key.split(".").reduce<string | Tree | undefined>((node, part) => (typeof node === "object" ? node[part] : undefined), tree);

// [visible text key, accessible name key]. "common.edit" is the default text of an InlineEditRow button.
const PAIRS: [string, string][] = [
  ["common.edit", "account.phone.editAria"],
  ["account.password.change", "account.password.changeAria"],
  ["account.password.set", "account.password.setAria"],
  ["account.sessions.manage", "account.sessions.manageAria"],
  ["account.passkeys.add", "account.passkeys.addAria"],
  ["account.passkeys.rename", "account.passkeys.renameAria"],
  ["account.passkeys.delete", "account.passkeys.deleteAria"],
  ["account.sessions.end", "account.sessions.endAria"],
];

function text(locale: "en" | "fa", key: string): string {
  const [ns, ...rest] = key.split(".");
  const found = lookup(messages[locale][ns as "account" | "common"], rest.join("."));
  if (typeof found !== "string") throw new Error(`${locale}: no message ${key}`);
  return found;
}

// Case and the Persian/Arabic letter forms do not matter to a person saying the words; placeholders are not words.
const plain = (value: string) => value.replace(/\{[^}]*\}/g, " ").replace(/\u064a/g, "\u06cc").replace(/\u0643/g, "\u06a9").toLocaleLowerCase();

describe("label in name", () => {
  for (const locale of ["en", "fa"] as const) {
    for (const [visible, aria] of PAIRS) {
      it(`${locale}: ${aria} contains the text ${visible} shows`, () => {
        expect(plain(text(locale, aria))).toContain(plain(text(locale, visible)).trim());
      });
    }
  }

  it("every editAriaLabel of the Account page is in the table above", () => {
    const used = new Set<string>();
    for (const file of readdirSync(import.meta.dirname).filter((name) => name.endsWith(".tsx"))) {
      const source = readFileSync(path.join(import.meta.dirname, file), "utf8");
      for (const match of source.matchAll(/editAriaLabel=\{([^\n]*)\}/g)) {
        for (const key of match[1]!.matchAll(/t\("([A-Za-z.]+)"/g)) used.add(`account.${key[1]}`);
      }
    }
    expect(used.size).toBeGreaterThan(4);
    const listed = new Set(PAIRS.map(([, aria]) => aria));
    expect([...used].filter((key) => !listed.has(key))).toEqual([]);
  });
});
