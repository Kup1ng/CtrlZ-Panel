import {readdirSync, readFileSync} from "node:fs";
import path from "node:path";
import {describe, expect, it} from "vitest";

// wp8-r7-5: two keys of auth.json sat unused for a round (forgot.useRecovery, forgot.useApp), because the Forgot
// step reads the shared second-factor labels. A translator who edits a string that nothing shows has changed
// nothing, and does not find out. Every key of the user auth namespace must be named by the code that shows it.

const root = path.resolve(import.meta.dirname, "../../../..");
type Tree = {[key: string]: string | Tree};
const flatten = (tree: Tree, prefix = ""): string[] =>
  Object.entries(tree).flatMap(([k, v]) => (typeof v === "string" ? [prefix + k] : flatten(v, `${prefix}${k}.`)));
const sources = (dir: string): string[] =>
  readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
    e.isDirectory()
      ? e.name === "node_modules"
        ? []
        : sources(path.join(dir, e.name))
      : /\.tsx?$/.test(e.name) && !/\.test\./.test(e.name)
        ? [readFileSync(path.join(dir, e.name), "utf8")]
        : [],
  );

// A key is used when some file names it in full. A key built at run time (`strength.level${score}`) is found by the
// prefix of its template literal, but only in a file that reads the auth namespace: errorText.ts builds
// `fields.${code}` for the errors namespace, and that must not make every auth key under `fields.` look used
// (wp8-r9-2).
const readsAuth = (file: string) => /(?:useTranslations|getTranslations)\(\s*["']auth["']\s*\)/.test(file);
function usedIn(files: string[]) {
  const code = files.join("\n");
  const prefixes = files.filter(readsAuth).flatMap((f) => [...f.matchAll(/`([a-zA-Z.]+)\$\{/g)].map((m) => m[1]!));
  return (key: string) =>
    code.includes(`"${key}"`) ||
    code.includes(`'${key}'`) ||
    code.includes(`\`${key}\``) ||
    prefixes.some((prefix) => key.startsWith(prefix));
}

describe("the auth messages", () => {
  const files = [...sources(path.join(root, "packages/ui/src")), ...sources(path.join(root, "apps/panel/src"))];
  const used = usedIn(files);

  for (const locale of ["fa", "en"]) {
    it(`every key of ${locale}/auth.json is used by the code (wp8-r7-5)`, () => {
      const tree = JSON.parse(readFileSync(path.join(root, "packages/i18n/messages", locale, "auth.json"), "utf8")) as Tree;
      expect(flatten(tree).filter((key) => !used(key))).toEqual([]);
    });
  }

  it("the scan does find an unused key", () => {
    expect(used("forgot.useRecovery")).toBe(false);
    expect(used("login.twoFactor.useRecovery")).toBe(true);
    expect(used("strength.level3")).toBe(true);
  });

  // wp8-r9-2: a template prefix of another namespace must not clear a key of this one.
  it("a template literal of a file that reads another namespace does not make an auth key look used", () => {
    const errors = 'const t = useTranslations("errors"); t(`fields.${code}`);';
    const auth = 'const t = useTranslations("auth"); t(`strength.level${score}`); t("fields.phone.label");';
    const check = usedIn([errors, auth]);
    expect(check("fields.password.unused")).toBe(false);
    expect(check("fields.recovery.required")).toBe(false);
    expect(check("fields.phone.label")).toBe(true);
    expect(check("strength.level2")).toBe(true);
    // The same template in a file that does read auth counts.
    expect(usedIn(['useTranslations("auth"); t(`fields.${code}`);'])("fields.password.unused")).toBe(true);
  });

  it("the real errors helper is not an auth file, and the real run-time keys come from auth files", () => {
    const errorText = files.find((f) => f.includes("`fields.${"));
    expect(errorText).toBeDefined();
    expect(readsAuth(errorText!)).toBe(false);
    expect(files.some((f) => readsAuth(f) && f.includes("`strength.level${"))).toBe(true);
  });
});
