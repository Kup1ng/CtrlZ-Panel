import {readdirSync, readFileSync} from "node:fs";
import path from "node:path";
import {describe, expect, it, vi} from "vitest";

const calls: {path: string; body: Record<string, unknown>}[] = [];
vi.mock("@ctrlz/api-client/client.ts", () => ({
  api: {
    POST: async (route: string, init: {body: Record<string, unknown>}) => {
      calls.push({path: route, body: init.body});
      return {data: {}, response: {status: 200}};
    },
  },
}));
vi.mock("@ctrlz/api-client/core.ts", () => ({required: (result: {data: unknown}) => result.data}));

import {authApi} from "../auth/authApi.ts";
import {cleanName, hasInvisible, hasInvisiblePassword, nameLength, stripInvisible} from "./invisible.ts";

// wp8-r10-1: the API schemas refuse any string with a control, format or private-use character (pattern ^[^\p{C}]*$)
// with a bare 400, so what a visitor pastes must not reach them.

const LRM = "\u200e";
const RLM = "\u200f";
const ZWNJ = "\u200c";

describe("stripInvisible", () => {
  it("drops the format and control characters a paste brings along, and nothing else", () => {
    expect(stripInvisible(`${LRM}0912 345-6789${RLM}`)).toBe("0912 345-6789");
    expect(stripInvisible(`+98${ZWNJ}912\u202a3456789\u202c\u2066\ufeff`)).toBe("+989123456789");
    expect(stripInvisible("\t0912\n")).toBe("0912");
    expect(stripInvisible("۰۹۱۲ ۳۴۵")).toBe("۰۹۱۲ ۳۴۵");
  });

  // wp8-r13-2: the API's \p{C} (Go) is Cc, Cf, Co and Cs. A code point that is unassigned (Cn) is accepted there,
  // so it must pass here; U+0378 has been unassigned in every Unicode version so far.
  it("keeps an unassigned code point, like the API's pattern does", () => {
    expect(stripInvisible("0912͸")).toBe("0912͸");
  });
});

describe("hasInvisible", () => {
  it("sees what the schema refuses, and lets a space and Persian letters pass", () => {
    for (const bad of [LRM, RLM, ZWNJ, "a\u0000b", "x\u202ey", "\ue000"]) expect(hasInvisible(`pass${bad}word`)).toBe(true);
    for (const ok of ["pass word", "گذرواژه ی", "p@ss-w0rd", "ÄÖ ß", "", "pass͸word"]) expect(hasInvisible(ok)).toBe(false);
  });
});

// merge-r1-7: main's schemas let U+200C through for every password and password.Normalize removes it at set and at verify (D64
// zwnj-fields), so the half-space is the one invisible character a password may hold, and it is sent as typed.
describe("hasInvisiblePassword", () => {
  it("lets the half-space pass and refuses every other control, format and private-use character", () => {
    for (const ok of [`pass${ZWNJ}word`, "می‌خواهم-Orchid-2026", ZWNJ, "pass word", ""]) expect(hasInvisiblePassword(ok)).toBe(false);
    for (const bad of [LRM, RLM, "a\u0000b", "x‮y", "", "a​b"]) expect(hasInvisiblePassword(`pass${bad}word`)).toBe(true);
    expect(hasInvisiblePassword(`pass${ZWNJ}${RLM}word`)).toBe(true);
  });
  it("leaves hasInvisible as it was, for the fields whose pattern has no exception", () => {
    expect(hasInvisible(`admin${ZWNJ}`)).toBe(true);
  });
});

describe("authApi sends a clean phone", () => {
  it("on every route that carries one", async () => {
    calls.length = 0;
    const dirty = `${LRM}09123456789${RLM}`;
    await authApi.loginPassword({phone: dirty, password: "x", remember_me: false});
    await authApi.requestOtp({purpose: "login", phone: dirty, locale: "fa"});
    await authApi.loginOtp({phone: dirty, challenge_id: "c", code: "123456", remember_me: false});
    await authApi.register({phone: dirty, challenge_id: "c", code: "123456", locale: "fa"});
    await authApi.resetVerify({phone: dirty, challenge_id: "c", code: "123456"});
    expect(calls.map((c) => c.path)).toHaveLength(5);
    for (const call of calls) expect(call.body.phone).toBe("09123456789");
  });

  it("leaves a body with no phone alone", async () => {
    calls.length = 0;
    await authApi.requestOtp({purpose: "invite", invite_token: "ABC", locale: "en"});
    expect(calls[0]?.body).toEqual({purpose: "invite", invite_token: "ABC", locale: "en"});
  });
});

// The class for passwords: a password is not changed for the visitor, so every submit of a form that has a
// PasswordField must refuse one with an invisible character before it goes out. The count is per file: a form
// with two password fields (the forced change) needs two checks.
describe("every password field is checked before it is sent", () => {
  // wp9-r1-7: the whole of packages/ui/src, not one folder. The Account page keeps its new-password form in
  // account/, and a folder-by-folder list would let the next screen with a PasswordField slip past.
  const root = path.resolve(import.meta.dirname, "..");
  const walk = (dir: string): string[] =>
    readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
      e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith(".tsx") && !e.name.includes(".test.") ? [path.join(dir, e.name)] : [],
    );
  const files = walk(root).map((f) => path.relative(root, f).split(path.sep).join("/"));
  const count = (text: string, re: RegExp) => (text.match(re) ?? []).length;

  it("no form has more PasswordFields than hasInvisible checks", () => {
    const short: string[] = [];
    for (const f of files) {
      const text = readFileSync(path.join(root, f), "utf8");
      const fields = count(text, /<PasswordField\b/g);
      // A form with a PasswordField calls hasInvisiblePassword for a password. hasInvisible is for the fields whose pattern has
      // no half-space exception (gateway credentials), and a PasswordField in that file counts it.
      const checks = count(text, /\bhasInvisible(?:Password)?\(/g);
      if (checks < fields) short.push(`${f}: ${fields} fields, ${checks} checks`);
    }
    expect(short).toEqual([]);
  });

  it("the scan sees the forms it is meant to (a rename cannot empty it)", () => {
    const withFields = files.filter((f) => /<PasswordField\b/.test(readFileSync(path.join(root, f), "utf8")));
    expect(withFields.sort()).toEqual([
      "account/PasswordRow.tsx",
      "admin/auth/AdminLoginFlow.tsx",
      "admin/auth/SetupFlow.tsx",
      "admin/shell/AdminAccountDialog.tsx",
      "admin/sms/GatewaysTab.tsx",
      "auth/ChangePasswordForm.tsx",
      "auth/ForgotFlow.tsx",
      "auth/LoginFlow.tsx",
      "auth/ReauthPanel.tsx",
      "auth/RegisterConfirm.tsx",
    ]);
  });
});

// wp8-r11-1, the OTP field. input-otp slices a paste to six characters and drops the whole paste, silently, when
// the result fails the digit pattern, so a mark in front of the code (a Persian message wraps it in RLM) must be
// gone before that check. The class: every way text enters the field is cleaned, and the field is the only one.
describe("the code field strips invisible characters on every path", () => {
  it("a pasted code wrapped in RLM, LRM, ZWNJ or ZWSP keeps its six digits", async () => {
    const {dropSeparators} = await import("./OtpField.tsx");
    expect(dropSeparators(`${RLM}123456`)).toBe("123456");
    expect(dropSeparators(`${LRM}123${ZWNJ}456${RLM}`)).toBe("123456");
    expect(dropSeparators("\u200b123\u200b 456")).toBe("123456");
    // Persian digits and the separators of round 1 still work.
    expect(dropSeparators(`${RLM}۱۲۳-۴۵۶`)).toBe("۱۲۳۴۵۶");
    // A letter is not an invisible character: it still fails the pattern, so the paste is dropped.
    expect(dropSeparators(`${RLM}12a456`)).toBe("12a456");
  // The import pulls in the whole HeroUI Pro barrel: 30 s alone, over 80 s on a loaded machine (gate-r3-1).
  }, 180_000);

  it("the paste transformer and the change handler both go through stripInvisible", () => {
    const source = readFileSync(path.resolve(import.meta.dirname, "OtpField.tsx"), "utf8");
    expect(source).toMatch(/dropSeparators = [^\n]*stripInvisible\(/);
    expect(source).toMatch(/pasteTransformer=\{dropSeparators\}/);
    expect(source).toMatch(/onChangeCapture=\{cleanInput\}/);
    expect(source).toMatch(/function cleanInput[\s\S]*stripInvisible\(input\.value\)/);
  });

  it("no code input is built outside OtpField", () => {
    const root = path.resolve(import.meta.dirname, "..");
    const walk = (dir: string): string[] =>
      readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
        e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith(".tsx") && !e.name.includes(".test.") ? [path.join(dir, e.name)] : [],
      );
    // The token lab (WP11) draws one InputOTP as a specimen of the radius table. It sends nothing, and it is closed
    // unless CTRLZ_LAB is set, so it is not a code input of the product.
    const users = walk(root)
      .filter((f) => !f.includes(`${path.sep}lab${path.sep}`))
      .filter((f) => /<InputOTP\b/.test(readFileSync(f, "utf8")));
    expect(users.map((f) => path.basename(f))).toEqual(["OtpField.tsx"]);
  });
});

// wp9-r6-1: a name is not a secret, so the invisible characters are dropped, and the limit is counted the way the
// server counts it (runes).
describe("cleanName and nameLength", () => {
  it("drops format characters and trims, and keeps the letters", () => {
    expect(cleanName(`  ${LRM}لپتاپ${RLM} `)).toBe("لپتاپ");
    expect(cleanName(`${ZWNJ}${RLM}`)).toBe("");
    expect(cleanName("Work laptop")).toBe("Work laptop");
    expect(cleanName("x‮y⁦z﻿ ")).toBe("xyz");
  });
  // B5, review round 1: the schema of a name lets U+200C through, but RenamePasskey removes it before it stores the name
  // (routes_passkey.go, D64 zwnj-fields), so the client sends the name the way it will be listed.
  it("drops the half-space, wherever it is, like the server does", () => {
    expect(cleanName(`لپ${ZWNJ}تاپ`)).toBe("لپتاپ");
    expect(cleanName(`  ${LRM}لپ${ZWNJ}تاپ${RLM} `)).toBe("لپتاپ");
    expect(cleanName(`${ZWNJ}${ZWNJ}`)).toBe("");
  });
  // merge-r1-9: the trim runs after the invisible characters are gone, so a half-space cannot hide a space from it, and the
  // API's pattern (the first character is not a separator) never sees a name that starts or ends with one.
  it("trims a space that a half-space was hiding", () => {
    expect(cleanName(`${ZWNJ} ab`)).toBe("ab");
    expect(cleanName(`ab ${ZWNJ}`)).toBe("ab");
    expect(cleanName(` ${ZWNJ} ${ZWNJ}ab${ZWNJ} ${ZWNJ} `)).toBe("ab");
    expect(cleanName(`a${ZWNJ} ${ZWNJ}b`)).toBe("a b");
  });
  it("counts what is sent, so the limit of 64 is the server's count", () => {
    expect(nameLength(cleanName(`لپ${ZWNJ}تاپ`))).toBe(5);
    expect(nameLength(cleanName(`${"a".repeat(64)}${ZWNJ}${ZWNJ}`))).toBe(64);
  });
  it("counts code points, not UTF-16 units", () => {
    expect(nameLength("\u{1f600}".repeat(40))).toBe(40);
    expect("\u{1f600}".repeat(40).length).toBe(80);
    expect(nameLength("لپتاپ")).toBe(5);
  });
});

// The class: a text field whose value goes to the API must clean it. A file with a TextField or Input is either
// listed here with the reason it needs nothing, or it calls one of the helpers. A new free-text field cannot skip it.
describe("every free-text field is cleaned before it is sent", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const walk = (dir: string): string[] =>
    readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
      e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith(".tsx") && !e.name.includes(".test.") ? [path.join(dir, e.name)] : [],
    );
  const exempt: Record<string, string> = {
    "account/HomeCountries.tsx": "a search box of a ComboBox: only the chosen country key is sent",
    "auth/InviteFlow.tsx": "the pasted link goes through inviteTokenFromPaste, which drops every invisible character and white space and then accepts only the 140 characters of the token alphabet",
    "auth/SecondFactorInput.tsx": "the recovery code goes through changeGrouped, which keeps letters and digits only",
    "forms/PasswordField.tsx": "checked by hasInvisible in each form (the password scan above)",
    "lab/TokenLab.tsx": "specimens of the radius table (spec 6.3) on a page that is closed unless CTRLZ_LAB is set: nothing typed there is sent anywhere",
    "admin/shared/IntegerField.tsx": "parseInteger (integer.ts) accepts digits and grouping only and strips invisible characters, anything else is invalid and never a value, and a number is sent, never the text",
    "admin/sms/LimitsTab.tsx": "the money cap is checked against the digits-only pattern of the document before it is sent, which no invisible character passes",
    "admin/sms/TemplatesTab.tsx": "the body goes through cleanProse (everything invisible but the half-space is dropped, as the prose pattern allows) and the template id and parameter names are checked against the document's own patterns",
  };
  it("uses cleanName, stripInvisible or hasInvisible, or says why not", () => {
    const missing: string[] = [];
    for (const file of walk(root)) {
      const rel = path.relative(root, file).split(path.sep).join("/");
      const text = readFileSync(file, "utf8");
      if (!/<(TextField|Input)\b/.test(text) || rel in exempt) continue;
      if (!/\b(cleanName|stripInvisible|hasInvisible)\(/.test(text)) missing.push(rel);
    }
    expect(missing).toEqual([]);
  });
  it("the passkey name fields use cleanName and nameLength, and no length check is left on a raw string", () => {
    const text = readFileSync(path.join(root, "account/PasskeysSection.tsx"), "utf8");
    expect((text.match(/cleanName\(name\)/g) ?? []).length).toBe(2);
    expect((text.match(/nameLength\(next\)/g) ?? []).length).toBe(2);
    expect(text).not.toMatch(/next\.length > NAME_MAX/);
    expect(text).not.toMatch(/name\.trim\(\)/);
  });
});
