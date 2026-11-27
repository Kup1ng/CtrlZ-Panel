import {readdirSync, readFileSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// A class test for wp10-r3-1. A field code the UI has no line for reads as "It is not valid." (useFieldErrorText), which is
// wrong for a perfectly valid value (a money cap while a gateway has no price) and hides what to do. The admin API names
// its field codes in `errValidation(field, "code")` and nowhere else, so every code the handlers can answer is read from
// the source and must have a line in `admin.fieldErrors` (or the shared `errors.fields`), in both languages.

const root = join(__dirname, "../../../..");
const handlers = join(root, "internal/adminapi");

// Codes the handlers pick in a helper and hand to `errValidation` or `FieldError` as a variable, which the call patterns below cannot
// see: the reason a role cannot be given (`notConfiguredCode`), the reason a password is refused (`code = "..."` in preparePassword) and
// the reasons of the strength check (`Reason = "..."`). Read from those places so a new one is not missed (P1 web merge, B4).
const pwstrength = join(root, "internal/auth/pwstrength/pwstrength.go");

function codes(): string[] {
  const found = new Set<string>();
  for (const name of readdirSync(handlers)) {
    if (!name.endsWith(".go") || name.endsWith("_test.go")) continue;
    const source = readFileSync(join(handlers, name), "utf8");
    for (const match of source.matchAll(/errValidation\(\s*[^,()]+,\s*"([a-z_]+)"\s*\)/g)) found.add(match[1]!);
    for (const match of source.matchAll(/FieldError\{[^}]*Code:\s*"([a-z_]+)"/g)) found.add(match[1]!);
    for (const match of source.matchAll(/\bcode\s*=\s*"([a-z_]+)"(?!\s*\+)/g)) found.add(match[1]!);
  }
  const sms = readFileSync(join(handlers, "routes_sms.go"), "utf8");
  const helper = sms.match(/func \(s \*Server\) notConfiguredCode\([^)]*\) string \{[\s\S]*?\n\}\n/)?.[0] ?? "";
  for (const match of helper.matchAll(/return "([a-z_]+)"/g)) found.add(match[1]!);
  for (const match of readFileSync(pwstrength, "utf8").matchAll(/\bReason = "([a-z_]+)"/g)) found.add(match[1]!);
  return [...found].sort();
}

const read = (locale: string, file: string): Record<string, unknown> => JSON.parse(readFileSync(join(root, `packages/i18n/messages/${locale}/${file}`), "utf8")) as Record<string, unknown>;
// The admin's own texts first (wp10-r5-2), then the shared ones, as useFieldErrorText reads them.
// A code that means different things on different fields is keyed by field (`body.too_long`, wp10-r18-1): it has text when any field does.
const fields = (locale: string): Record<string, string> => {
  const text: Record<string, string> = {...((read(locale, "errors.json") as {fields: Record<string, string>}).fields)};
  for (const [key, value] of Object.entries(read(locale, "admin.json").fieldErrors as Record<string, string | Record<string, string>>)) {
    if (typeof value === "string") text[key] = value;
    else for (const [code, line] of Object.entries(value)) text[code] ??= line;
  }
  return text;
};

describe("admin field codes", () => {
  const all = codes();

  it("finds the codes it is meant to guard (a scan that finds nothing would pass for ever)", () => {
    expect(all).toEqual(expect.arrayContaining(["price_required", "same_as_primary", "public_suffix", "not_panel_host", "out_of_range", "too_long", "pending_confirmation", "too_short", "contains_phone"]));
  });

  for (const locale of ["fa", "en"]) {
    it(`every code the admin API answers has text in ${locale}, and it is not the generic line`, () => {
      const text = fields(locale);
      const missing = all.filter((code) => !text[code]);
      expect(missing).toEqual([]);
      const generic = all.filter((code) => code !== "invalid" && text[code] === text.invalid);
      expect(generic).toEqual([]);
    });
  }
});

// wp10-r19-1. The real API answers a refused value as `validation_failed` with `fields: [{name, code}]`, and useApiForm reads
// the field entries, so a page's own fallback sentence (`form.fail(error, {field, message})`) is reached only by an answer
// without `fields`. A sentence a page has for a field is therefore also the field's `invalid` line in admin.fieldErrors, or
// the admin reads the shared "It is not valid." for the one case the page knows how to explain. Read from the source, so a
// new `validation_failed` fallback is caught without anyone remembering this list. (A fallback for another code, such as the
// setup page's `invalid_credentials` on the one-time password, carries no `fields`, so it needs no such line.)
const adminSrc = join(__dirname);
function sources(dir: string): string[] {
  return readdirSync(dir, {withFileTypes: true}).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith(".tsx") ? [path] : [];
  });
}
const lookup = (tree: unknown, path: string): unknown => path.split(".").reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], tree);

describe("a field's own sentence is also its invalid line (wp10-r19-1)", () => {
  const pairs = new Map<string, string>([["rp_id", "settings.webauthn.rpMalformed"]]);
  for (const file of sources(adminSrc)) {
    for (const match of readFileSync(file, "utf8").matchAll(/validation_failed"\)\)\s*\w+\.fail\([^,()]+,\s*\{\s*field:\s*"(\w+)",\s*message:\s*t\("([\w.]+)"\)/g)) pairs.set(match[1]!, match[2]!);
  }

  it("finds the fallbacks it is meant to guard", () => {
    expect([...pairs.keys()]).toEqual(expect.arrayContaining(["body", "rp_id"]));
  });

  for (const locale of ["fa", "en"]) {
    it(`every field with its own sentence has the same words as its invalid line in ${locale}`, () => {
      const admin = read(locale, "admin.json");
      for (const [field, key] of pairs) {
        const own = lookup(admin, key);
        const line = lookup(admin.fieldErrors, `${field}.invalid`);
        expect(typeof own, `${key} is a message`).toBe("string");
        expect(line, `admin.fieldErrors.${field}.invalid`).toBe(own);
      }
    });
  }
});
