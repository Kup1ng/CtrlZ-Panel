import {readdirSync, readFileSync} from "node:fs";
import ts from "typescript";
import {NextIntlClientProvider} from "next-intl";
import {renderToString} from "react-dom/server";
import {describe, expect, it} from "vitest";

import {AuthForm} from "./AuthForm.tsx";
import {OtpField, OTP_LENGTH} from "./OtpField.tsx";
import {PasswordField, supportsTextSecurity} from "./PasswordField.tsx";
import {PhoneField} from "./PhoneField.tsx";
import {secondsLeft} from "./useCountdown.ts";
import type {ApiForm} from "./useApiForm.ts";

// The server render of the fields (spec 10.3): what the browser gets before React runs, which is where the
// attributes that password managers and phones look at have to be right.

const messages = {
  auth: {
    fields: {
      phone: {label: "Mobile number", placeholder: "09123456789"},
      password: {label: "Password", show: "Show", hide: "Hide", showLabel: "Show password", hideLabel: "Hide password"},
    },
  },
};

const render = (node: React.ReactNode) =>
  renderToString(
    <NextIntlClientProvider locale="en" messages={messages}>
      {node}
    </NextIntlClientProvider>,
  );

describe("OtpField", () => {
  const html = render(<OtpField label="Code" value="" onChange={() => undefined} onComplete={() => undefined} />);

  it("is six slots, left to right whatever the page direction", () => {
    expect(OTP_LENGTH).toBe(6);
    expect(html).toContain('dir="ltr"');
    expect((html.match(/data-slot="input-otp-slot"|input-otp__slot/g) ?? []).length).toBeGreaterThanOrEqual(6);
  });

  it("keeps page translation away from the digits: every slot and the input sit inside an element with translate=\"no\" (gate-r28-6)", () => {
    // input-otp sets translate="no" on its own container (data-input-otp-container), so the typed digits, which are text nodes of the slots,
    // are not sent to a translation service. That is the library's doing and not ours, so this pins it: a version that drops the attribute fails
    // here, and then OtpField must put it on its wrapper. A depth walk over the markup: the element that says translate="no" must contain the
    // input and every slot.
    const open = html.indexOf('translate="no"');
    expect(open, "no element says translate=no").toBeGreaterThan(-1);
    const start = html.lastIndexOf("<div", open);
    let depth = 0;
    let end = -1;
    for (const m of html.slice(start).matchAll(/<div\b|<\/div>/g)) {
      depth += m[0] === "</div>" ? -1 : 1;
      if (depth === 0) {
        end = start + m.index! + m[0].length;
        break;
      }
    }
    const inside = html.slice(start, end);
    expect((inside.match(/data-slot="input-otp-slot"|input-otp__slot/g) ?? []).length).toBe((html.match(/data-slot="input-otp-slot"|input-otp__slot/g) ?? []).length);
    expect(inside).toMatch(/<input\b/);
  });

  it("asks the phone for the SMS code and a numeric keyboard", () => {
    expect(html).toMatch(/autocomplete="one-time-code"/i);
    expect(html).toMatch(/inputmode="numeric"/i);
  });

  it("admits Persian and Arabic-Indic digits in the pattern", () => {
    const pattern = /pattern="([^"]*)"/.exec(html)?.[1] ?? "";
    const re = new RegExp(pattern.replace(/&amp;/g, "&"));
    for (const ok of ["123456", "۱۲۳۴۵۶", "٠١٢٣٤٥", ""]) expect(re.test(ok), ok).toBe(true);
    for (const bad of ["12a", "1 2", "12-3"]) expect(re.test(bad), bad).toBe(false);
  });

  it("marks itself invalid and describes itself by the message", () => {
    const bad = render(<OtpField label="Code" value="" onChange={() => undefined} onComplete={() => undefined} errorMessage="Wrong" />);
    expect(bad).toContain('aria-invalid="true"');
    expect(bad).toContain("Wrong");
    expect(bad).toContain('role="alert"');
  });
});

describe("PhoneField and PasswordField", () => {
  it("the phone is a telephone field, left to right, with the telephone autofill", () => {
    const html = render(<PhoneField value="" onChange={() => undefined} />);
    expect(html).toContain('type="tel"');
    expect(html).toMatch(/autocomplete="tel"/i);
    expect(html).toContain('dir="ltr"');
    expect(html).not.toMatch(/type="email"/);
  });

  it("the password says whether it is new, and starts hidden", () => {
    const current = render(<PasswordField value="" onChange={() => undefined} autoComplete="current-password" />);
    const fresh = render(<PasswordField value="" onChange={() => undefined} autoComplete="new-password" />);
    expect(current).toMatch(/autocomplete="current-password"/i);
    expect(fresh).toMatch(/autocomplete="new-password"/i);
    expect(current).toContain('type="password"');
  });

  it("a write-only secret is masked by CSS only where the browser reports it can, and is a password input otherwise (wp10-r3-5)", () => {
    // The server render cannot know, so it is the fail-closed one: a real password input that the browser masks itself.
    const html = render(<PasswordField name="gw_key" value="" onChange={() => undefined} autoComplete="off" />);
    expect(html).toContain('type="password"');
    expect(html).toMatch(/autocomplete="new-password"/i);
    expect(html).not.toContain("text-security");
    expect(html).toContain('data-1p-ignore="true"');
  });

  it("supportsTextSecurity says no without a CSS global, without supports, when supports says no, or when it throws", () => {
    expect(supportsTextSecurity(undefined)).toBe(false);
    expect(supportsTextSecurity({})).toBe(false);
    expect(supportsTextSecurity({supports: () => false})).toBe(false);
    expect(supportsTextSecurity({supports: () => { throw new Error("no"); }})).toBe(false);
    expect(supportsTextSecurity({supports: (p, v) => p === "-webkit-text-security" && v === "disc"})).toBe(true);
  });

  it("the show toggle has a name that follows its state and no aria-pressed, which together read as the opposite (wp8-r3-4)", () => {
    const html = render(<PasswordField value="" onChange={() => undefined} autoComplete="current-password" />);
    expect(html).toContain('aria-label="Show password"');
    expect(html).not.toContain("aria-pressed");
  });

  it("is never spell-checked, so the shown password does not go to a cloud spell checker (wp8-r1-11)", () => {
    for (const autoComplete of ["current-password", "new-password"] as const) {
      const html = render(<PasswordField value="" onChange={() => undefined} autoComplete={autoComplete} />);
      expect(html).toMatch(/spellcheck="false"/i);
      expect(html).toMatch(/autocorrect="off"/i);
      expect(html).toMatch(/autocapitalize="none"/i);
    }
  });

  // wp8-r6-4, r7-2: PasswordField hides itself when it is disabled, not when the form fires `submit`, so a form that
  // never disables it while it sends would leave a shown password shown. This catches every caller. It reads the
  // JSX with the compiler, not with a pattern: a prop value that holds a "/>" of its own does not end the tag early,
  // and a constant (`false`, `undefined`) is refused, since only a state that follows the call hides the password.
  it("every use of PasswordField passes isDisabled bound to a state, which hides a shown password when the form sends (wp8-r6-4)", () => {
    const root = new URL("../", import.meta.url);
    const files = (dir: URL): URL[] =>
      readdirSync(dir, {withFileTypes: true}).flatMap((e) =>
        e.isDirectory() ? files(new URL(`${e.name}/`, dir)) : /.tsx$/.test(e.name) && !/.test./.test(e.name) ? [new URL(e.name, dir)] : [],
      );
    let uses = 0;
    for (const file of files(root)) {
      const found = passwordFieldUses(readFileSync(file, "utf8"));
      uses += found.length;
      for (const use of found) expect(use.problem, `${file.pathname}:${use.line}`).toBeNull();
    }
    expect(uses).toBeGreaterThanOrEqual(5);
  });

  it("the PasswordField scan refuses a missing, constant or spread-only isDisabled and reads past a tag inside a prop (wp8-r7-2)", () => {
    const problem = (jsx: string) => passwordFieldUses(`const x = ${jsx};`)[0]?.problem;
    expect(problem("<PasswordField value={v} />")).toMatch(/no isDisabled/);
    expect(problem("<PasswordField isDisabled={false} />")).toMatch(/constant/);
    expect(problem("<PasswordField isDisabled={undefined} />")).toMatch(/constant/);
    expect(problem("<PasswordField isDisabled />")).toMatch(/constant/);
    expect(problem('<PasswordField isDisabled="no" />')).toMatch(/constant/);
    expect(problem("<PasswordField {...rest} />")).toMatch(/no isDisabled/);
    expect(problem("<PasswordField isDisabled={pending} />")).toBeNull();
    expect(problem("<PasswordField isDisabled={form.pending || offline} />")).toBeNull();
    // A self-closing element inside a prop must not end the tag early and hide the prop after it.
    expect(problem("<PasswordField description={<Hint />} isDisabled={pending} />")).toBeNull();
    expect(problem("<PasswordField description={<Hint />} />")).toMatch(/no isDisabled/);
    expect(passwordFieldUses("const x = <><PasswordField isDisabled={a} /><PasswordField /></>;")).toHaveLength(2);
  });

  it("shows a message it was given and is invalid with it", () => {
    const html = render(<PhoneField value="" onChange={() => undefined} error="Enter your mobile number." />);
    expect(html).toContain("Enter your mobile number.");
    expect(html).toContain('aria-invalid="true"');
  });
});

describe("AuthForm", () => {
  it("is a POST in the server render, so an early submit never puts a password in the URL (wp8-r2-9)", () => {
    const form = {attachForm: () => undefined, blocked: false} as unknown as ApiForm;
    const html = render(
      <AuthForm form={form} onSubmit={() => undefined}>
        <input name="password" type="password" />
      </AuthForm>,
    );
    const tag = /<form[ >][^>]*>?/i.exec(html)?.[0] ?? "";
    expect(tag).toMatch(/method="post"/i);
    expect(tag).not.toMatch(/method="get"/i);
  });
});

describe("secondsLeft", () => {
  it("rounds up, so the last fraction of a second still shows a 1", () => {
    expect(secondsLeft(10_000, 9_001)).toBe(1);
    expect(secondsLeft(10_000, 9_000)).toBe(1);
    expect(secondsLeft(10_000, 10_000)).toBe(0);
    expect(secondsLeft(10_000, 12_000)).toBe(0);
    expect(secondsLeft(40_000, 10_000)).toBe(30);
  });
});

/** Every <PasswordField> of a source text, with what is wrong with its isDisabled prop, or null. */
function passwordFieldUses(source: string): {line: number; problem: string | null}[] {
  const file = ts.createSourceFile("x.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const uses: {line: number; problem: string | null}[] = [];
  const visit = (node: ts.Node) => {
    if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) && node.tagName.getText(file) === "PasswordField") {
      const prop = node.attributes.properties.find((a): a is ts.JsxAttribute => ts.isJsxAttribute(a) && a.name.getText(file) === "isDisabled");
      const value = prop?.initializer;
      const expression = value && ts.isJsxExpression(value) ? value.expression : undefined;
      const constant =
        !!prop &&
        (!expression ||
          ts.isLiteralExpression(expression) ||
          expression.kind === ts.SyntaxKind.TrueKeyword ||
          expression.kind === ts.SyntaxKind.FalseKeyword ||
          expression.kind === ts.SyntaxKind.NullKeyword ||
          (ts.isIdentifier(expression) && expression.text === "undefined"));
      uses.push({
        line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1,
        problem: !prop ? "no isDisabled prop" : constant ? "isDisabled is a constant, not a state that follows the call" : null,
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return uses;
}

// wp8-r17-5: the account name the password manager saves a new password under.
describe("AccountNameField", () => {
  it("renders a read-only, visually hidden username field that carries the phone and stays out of the tab order", async () => {
    const {AccountNameField} = await import("./AccountNameField.tsx");
    const html = render(<AccountNameField phone="09123456789" />);
    expect(html).toMatch(/autoComplete="username"|autocomplete="username"/i);
    expect(html).toContain('value="09123456789"');
    expect(html).toMatch(/readOnly=""|readonly=""/i);
    expect(html).toContain('tabindex="-1"');
    expect(html).toContain("sr-only");
  });

  it("is on the two forms that set a password for a typed number, and on no form that has only a masked one", () => {
    const dir = new URL("../auth/", import.meta.url);
    const used = (file: string) => readFileSync(new URL(file, dir), "utf8").includes("<AccountNameField");
    expect(used("ForgotFlow.tsx")).toBe(true);
    expect(used("RegisterConfirm.tsx")).toBe(true);
    // /me and the invite give only phone_masked: a masked name would be saved as the account.
    expect(used("ChangePasswordForm.tsx")).toBe(false);
    expect(used("InviteFlow.tsx")).toBe(false);
  });
});

// wp8-r17-2 and r17-3/4: classes, not cases. A flow that sends a text words `sms_unavailable` itself, and a waiting
// card is the one LoadingBlock (busy status and offline line), never a bare skeleton.
describe("auth screens, source rules", () => {
  const authDir = new URL("../auth/", import.meta.url);
  const sources = readdirSync(authDir)
    .filter((name) => name.endsWith(".tsx") && !name.endsWith(".test.tsx"))
    .map((name) => ({name, code: readFileSync(new URL(name, authDir), "utf8")}));

  it("the steps that send a text name their own sms_unavailable text, the sign-in page and the steps that send none do not", () => {
    // Forgot: the number step and the code step (Resend). Register: the number step. RegisterConfirm: Resend (Register and
    // Invite). Invite: its Send code step. A new step that sends a text must pass smsDown and raise its count here.
    // ReauthPanel (WP9): its "Send code" step for an account with neither a password nor an authenticator.
    // LoginSteps: the SMS code step (Resend, resend.smsDown); no step of the sign-in page sends a first text with a flow-specific line.
    const expected: Record<string, number> = {"ForgotFlow.tsx": 2, "RegisterFlow.tsx": 1, "RegisterConfirm.tsx": 1, "InviteFlow.tsx": 1, "LoginSteps.tsx": 1, "ReauthPanel.tsx": 1};
    for (const {name, code} of sources) expect((code.match(/<FormError[^>]*smsDown=/g) ?? []).length, name).toBe(expected[name] ?? 0);
  });

  it("a code step, where the visitor already holds a valid code, words sms_unavailable as resend.smsDown, never as the flow's first-send advice (wp8-r18-2)", () => {
    // Every FormError that sits beside a form (`form={form}`) is on a code step: it can only meet sms_unavailable
    // from a Resend. The first-send advice belongs to the FormError of the step that sends the first message.
    // Counts every `<FormError ... form={form}`, with or without smsDown, so a code step that forgets the prop fails
    // here too (wp8-r19-1). A tag ends at `/>`; `=>` inside onRetry does not end it.
    let seen = 0;
    for (const {name, code} of sources) {
      for (const tag of code.match(/<FormError\b[\s\S]*?\/>/g) ?? []) {
        if (!/\bform=\{form\}/.test(tag)) continue;
        seen++;
        expect(tag, name).toContain('smsDown={t("resend.smsDown")}');
      }
    }
    // The Login SMS code step, ForgotFlow's code step and RegisterConfirm (Register and Invite).
    expect(seen).toBe(3);
  });

  it("a Skeleton in the auth screens sits only inside the form of the sign-in tabs", () => {
    for (const {name, code} of sources) {
      const bare = (code.match(/<Skeleton/g) ?? []).length;
      expect(bare, name).toBe(name === "LoginFlow.tsx" ? 1 : 0);
    }
  });
});
