import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// A class test for wp10-r5-2. Section 18 gives each work package its own message namespace. The sentences for the field codes
// that only the admin API answers are admin wording, so they live in `admin.fieldErrors` and not in WP4's `errors.fields`,
// which the panel reads too. The one way an admin form reaches them is `useAdminForm`; a form that calls `useApiForm`
// itself would read them as "It is not valid." and nothing would say why.

const root = join(__dirname);
const messages = join(__dirname, "../../../i18n/messages");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}

describe("the admin app's field-code texts", () => {
  it("every admin form is made with useAdminForm, never with useApiForm", () => {
    const direct = sources(root).filter((file) => !file.endsWith("useAdminForm.ts") && /\buseApiForm\(/.test(readFileSync(file, "utf8")));
    expect(direct).toEqual([]);
  });

  for (const locale of ["fa", "en"]) {
    it(`admin.fieldErrors and errors.fields share no code in ${locale}, so neither app's sentence can stand for the other's`, () => {
      const read = (file: string) => JSON.parse(readFileSync(join(messages, locale, file), "utf8")) as Record<string, unknown>;
      const admin = Object.keys(read("admin.json").fieldErrors as Record<string, string>);
      const shared = Object.keys((read("errors.json") as {fields: Record<string, string>}).fields);
      expect(admin.length).toBeGreaterThan(0);
      expect(admin.filter((code) => shared.includes(code))).toEqual([]);
    });
  }
});

// A class test for wp10-r18-1. A field code can mean different things on different fields: `too_long` is the SMS template body on
// one admin route and a refused password on two others. A line for it in admin.fieldErrors by code alone would read on every
// admin form, password fields included. So a code the shared password text already answers (auth fields.password.*) or the
// password routes send must be keyed by field (`body.too_long`), never flat.
describe("an ambiguous field code is keyed by field", () => {
  const AMBIGUOUS = ["too_long", "too_short", "weak"];
  for (const locale of ["fa", "en"]) {
    it(`admin.fieldErrors has no flat line for a code the password routes also send, in ${locale}`, () => {
      const read = (file: string) => JSON.parse(readFileSync(join(messages, locale, file), "utf8")) as Record<string, unknown>;
      const flat = Object.entries(read("admin.json").fieldErrors as Record<string, unknown>)
        .filter(([, value]) => typeof value === "string")
        .map(([code]) => code);
      expect(flat.filter((code) => AMBIGUOUS.includes(code))).toEqual([]);
    });
  }
});

// A class test for wp10-r5-3. A form that keeps a draft of a server value (useServerForm, useServerDraft) has to answer a server
// that moved under an edit, and the one answer is ConflictNote with Save waiting. A form that used the hook and never read
// `conflict` or `conflicts` would overwrite another admin's value in silence again.
describe("a form with a draft of a server value", () => {
  it("reads the conflict the hook reports", () => {
    const silent: string[] = [];
    for (const file of sources(root)) {
      if (file.endsWith("useServerDraft.ts")) continue;
      const source = readFileSync(file, "utf8");
      if (!/\buse(ServerForm|ServerDraft)\b[(<]/.test(source)) continue;
      if (!/\bconflicts?\b/.test(source) || !source.includes("ConflictNote")) silent.push(file);
    }
    expect(silent).toEqual([]);
  });
});

// A class test for wp10-r6-1 and wp10-r6-5. A form with a draft of a server value is safe only while four things stay true, and a
// refactor can drop any of them with the source still mentioning "conflict": the submit returns while a conflict is unanswered
// (so Enter and Retry are blocked), the button is disabled by it, the submit reads the server first (the page does not refetch
// while it stays open), and a browser case drives the form's conflict note. So each of the four is checked by the shape of the
// source, and the browser cases are checked by their test ids, so a form cannot be added or changed with no case for it.
describe("every form that can meet another admin's change", () => {
  // Each form and the conflict test ids that apps/admin/e2e/admin-pages.spec.ts must drive for it.
  const forms: Record<string, string[]> = {
    "sms/LimitsTab.tsx": ["conflict-otp_cap_ip"],
    "sms/RoutingTab.tsx": ["conflict-primary", "conflict-fallback"],
    // wp10-r8-3: the gateway price is a draft of a server value too, read before the write when it was changed.
    "sms/GatewaysTab.tsx": ["conflict-cost_per_message"],
    "sms/TemplatesTab.tsx": ["conflict-body-", "conflict-id-", "conflict-names-"],
    "settings/WebauthnCard.tsx": ["conflict-rp_id"],
    "settings/RegistrationCard.tsx": ["conflict-mode", "conflict-open_grace_days"],
  };
  const e2e = readFileSync(join(__dirname, "../../../../apps/admin/e2e/admin-pages.spec.ts"), "utf8");

  it("is listed here, so that none is added without a browser case", () => {
    const using = sources(root)
      .filter((file) => !file.endsWith("ConflictNote.tsx") && readFileSync(file, "utf8").includes("<ConflictNote"))
      .map((file) => file.slice(root.length + 1).replaceAll("\\", "/"))
      .sort();
    expect(using).toEqual(Object.keys(forms).sort());
  });

  for (const [file, ids] of Object.entries(forms)) {
    const source = readFileSync(join(root, file), "utf8");
    it(`${file}: the submit stops on a conflict, the button is disabled by it, and the server is read before the write`, () => {
      expect(source, "the early return of submit()").toMatch(/if \([^)\n]*\bconflict(ed)?\b[^)\n]*\) return/);
      expect(source, "the disabled expression of the button").toMatch(/isDisabled=\{[^}\n]*\bconflict(ed)?\b/);
      expect(source, "useCheckedWrite").toMatch(/\buseCheckedWrite\(\)/);
      expect(source, "the read and the write are one call").toMatch(/await write\(/);
    });
    // wp10-r7-2, wp10-r7-5: the read is inside the call the fresh-code dialog repeats, and the form's pending state is the whole write.
    // A form that read the server on its own, ran the fresh-code retry itself, or disabled its fields by the mutation's pending state
    // would bring back a read made once before the dialog (a value changed while the dialog was open is overwritten) and fields that
    // take an edit during the read.
    it(`${file}: reads and writes only through useCheckedWrite, and its fields follow its pending state`, () => {
      expect(source, "no read of its own").not.toMatch(/\buseServerCheck\b/);
      expect(source, "no fresh-code retry of its own").not.toMatch(/\buseFreshRecoverable\b/);
      expect(source, "the mutation's pending state").not.toMatch(/\bsave\.isPending\b/);
    });
    it(`${file}: a browser case drives ${ids.join(", ")}`, () => {
      for (const id of ids) expect(e2e, id).toContain(`"${id}`);
    });
  }
});

// A class test for wp10-r7-1. React Aria gives the focus back to the element that was focused when a dialog opened, and loses it
// (to <body>) when that element is gone: a result panel opens as the form that made it closes, and a confirm can remove the
// button it came from. The result panel and every confirm that removes its own trigger name where the focus goes instead.
describe("a dialog that cannot rely on React Aria's hand-back of the focus", () => {
  it("every OneTimeResult names the element the focus returns to", () => {
    const missing = sources(root)
      .filter((file) => !file.endsWith("OneTimeResult.tsx") && readFileSync(file, "utf8").includes("<OneTimeResult"))
      .filter((file) => !/<OneTimeResult\b(?:(?!\/>)[\s\S])*\breturnFocus=/.test(readFileSync(file, "utf8")));
    expect(missing).toEqual([]);
  });
  it("OneTimeResult takes the focus target as a required prop and hands it over when it unmounts", () => {
    const source = readFileSync(join(root, "shared/OneTimeResult.tsx"), "utf8");
    expect(source).toMatch(/returnFocus: \(\) => HTMLElement \| null;/);
    expect(source).toMatch(/restoreFocusLater\(/);
  });
  it("the revoke confirm of the invites hands the focus to the grid once it is closed", () => {
    expect(readFileSync(join(root, "invites/InvitesPage.tsx"), "utf8")).toMatch(/restoreFocusLater\(\(\) => gridOf\(/);
  });
});

// A class test for wp10-r8-1 and wp10-r8-3. Every admin write that needs the fresh code, a test send and a credential save included,
// goes through useCheckedWrite: it is the one place that makes the write a single pending state and gives the focus back to the
// element that had it when the fields were disabled for the write. A form that ran useFreshRecoverable itself would lose the focus
// to <body> on Enter and would not read the server before a price or a limit is replaced.
describe("every guarded write of the admin app", () => {
  it("goes through useCheckedWrite, which also keeps the focus (wp10-r8-1)", () => {
    const own = sources(root)
      .filter((file) => !file.endsWith("useCheckedWrite.ts") && /\buseFreshRecoverable\b/.test(readFileSync(file, "utf8")))
      .map((file) => file.slice(root.length + 1).replaceAll("\\", "/"));
    expect(own).toEqual([]);
    const hook = readFileSync(join(root, "shared/useCheckedWrite.ts"), "utf8");
    expect(hook).toMatch(/origin\.current = rememberFocus\(focusedElement\(\)\)/);
    expect(hook).toMatch(/restoreFocusAfter\(/);
  });
});

// A class test for wp10-r9-1. A control that removes itself when it is used takes the keyboard focus with it, and the focus falls to
// <body>: the Retry of an error that clears when the retry starts, a conflict note's answer, the Cancel of a draft block. Each of
// them goes through keepFocus, which remembers where the control sat and gives the focus to the nearest container that is left.
describe("a control that removes itself", () => {
  it("every Retry of an admin FormError, every conflict answer and the registration Cancel goes through keepFocus", () => {
    const files = [...sources(root), join(root, "../auth/FreshTotpDialog.tsx")];
    const bad: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/<FormError\b[^>]*\bonRetry=\{(.*?)\}\s*\/?>/g)) {
        // A refetch is no exception (wp10-r15-1): when it succeeds the error, with the Retry that has the focus, is replaced by
        // the content. keepRetry is the form of keepFocus that waits for the refetch.
        if (!/keepFocus\(|keepRetry\(/.test(match[1]!)) bad.push(`${file.slice(root.length + 1)}: ${match[0].slice(0, 80)}`);
      }
    }
    expect(bad).toEqual([]);
    const note = readFileSync(join(root, "shared/ConflictNote.tsx"), "utf8");
    expect(note).toMatch(/onPress=\{\(\) => keepFocus\(onKeep, /);
    expect(note).toMatch(/onPress=\{\(\) => keepFocus\(onUseServer, /);
    expect(readFileSync(join(root, "settings/RegistrationCard.tsx"), "utf8")).toMatch(/keepFocus\(\(\) => setDraft\(null\)\)/);
  });

  // wp10-r15-1. The Retry of a section error is replaced by the content when the refetch succeeds, and so is the one of the shell
  // gate and of a grid's first page: each of them names keepRetry, whatever page renders it.
  it("every SectionError retry of the admin app and of the shell gate names keepRetry (wp10-r15-1)", () => {
    const bad: string[] = [];
    let seen = 0;
    // The render-error boundary of the shell is outside the admin tree and is not a refetch: its `reset` has no promise, so it
    // names keepReset, which waits until the error has left (wp10-r16-2).
    const shellError = join(root, "../../../../apps/admin/src/app/[locale]/(shell)/error.tsx");
    for (const file of [...sources(root), join(root, "../shell/SessionGate.tsx"), shellError]) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/<SectionError\b[^>\n]*?\bonRetry=\{([^\n]*?)\}(?:\s|\/|>)/g)) {
        seen += 1;
        // PagedGrid passes on the handler that gridState built, which is checked below.
        if (file.endsWith("PagedGrid.tsx") && match[1] === "onRetry") continue;
        if (!/keepRetry\(|keepReset\(/.test(match[1]!)) bad.push(`${file.slice(root.length + 1)}: ${match[0].slice(0, 90)}`);
      }
    }
    expect(seen).toBeGreaterThanOrEqual(9);
    expect(bad).toEqual([]);
    // A grid's retry is built in one place, and every grid page takes it from there.
    for (const page of ["users/UsersPage.tsx", "audit/AuditPage.tsx", "invites/InvitesPage.tsx"]) {
      expect(readFileSync(join(root, page), "utf8")).toMatch(/gridState\(/);
    }
    expect(readFileSync(join(root, "shared/PagedGrid.tsx"), "utf8")).toMatch(/onRetry: keepRetry\(/);
    expect(readFileSync(join(root, "../../../../apps/admin/src/app/[locale]/(shell)/error.tsx"), "utf8")).toMatch(/onRetry=\{keepReset\(reset\)\}/);
  });

  // wp10-r16-1 and r16-3. A grid has two more controls that leave with their error: the Load more of a failed later page, and the
  // Retry of the refresh-failed line above rows that are already shown. Every Button of PagedGrid that sits in an error block names
  // keepRetry, and a failed refetch with rows is said by RefreshFailed, never silently.
  it("the grid's Load more of a failed page names keepRetry, and a failed refetch with rows is said (wp10-r16-1, r16-3)", () => {
    const grid = readFileSync(join(root, "shared/PagedGrid.tsx"), "utf8");
    const buttons = grid.split(/<Button\b/).slice(1).map((chunk) => chunk.slice(0, chunk.indexOf("</Button>")));
    expect(buttons.length).toBeGreaterThanOrEqual(1);
    for (const button of buttons) expect(button).toMatch(/onPress=\{keepRetry\(/);
    expect(grid).toMatch(/fetchNextPage: \(\) => query\.fetchNextPage\(\)/);
    expect(grid).toMatch(/error && !isNextPageError \? <RefreshFailed /);
  });

  // wp10-r11-1. The same loss hit the Retry of the refresh-failed line and of the failed impact count: each leaves with its line when
  // the retry succeeds. The rule is on the button, not on the component that renders it, so a new Retry button cannot be missed.
  it("every Retry button of the admin app, whatever component renders it, names keepFocus", () => {
    const bad: string[] = [];
    const seen: string[] = [];
    for (const file of sources(root)) {
      const text = readFileSync(file, "utf8");
      for (const chunk of text.split(/<Button\b/).slice(1)) {
        const end = chunk.indexOf("</Button>");
        const button = end < 0 ? chunk : chunk.slice(0, end);
        const label = button.search(/\(\s*"retry"\s*\)/);
        if (label < 0) continue;
        const name = file.slice(root.length + 1).replaceAll("\\", "/");
        seen.push(name);
        if (!/keepFocus\(/.test(button.slice(0, label))) bad.push(name);
      }
    }
    // The two shared Retry lines are among the buttons found, so the scan cannot pass by matching nothing.
    expect(seen).toEqual(expect.arrayContaining(["shared/RefreshFailed.tsx", "settings/ImpactFailed.tsx"]));
    expect(bad).toEqual([]);
  });

  // wp10-r12-1. The Acknowledge button of an alert leaves with its alert (and the section with the last one) when the call succeeds.
  // The rule is on the button: any admin Button whose handler is an ack mutation names keepFocus.
  it("every admin button that acknowledges something names keepFocus", () => {
    const bad: string[] = [];
    const seen: string[] = [];
    for (const file of sources(root)) {
      const text = readFileSync(file, "utf8");
      for (const chunk of text.split(/<Button\b/).slice(1)) {
        const end = chunk.indexOf("</Button>");
        const button = end < 0 ? chunk : chunk.slice(0, end);
        const press = button.match(/onPress=\{(.*)\}/)?.[1] ?? "";
        if (!/\b(?:ack\w*|useAck\w*)\.mutate(?:Async)?\(|\backAlert\(|\backNotices\(/.test(press)) continue;
        const name = file.slice(root.length + 1).replaceAll("\\", "/");
        seen.push(name);
        if (!/keepFocus\(/.test(press)) bad.push(name);
      }
    }
    expect(seen).toContain("sms/SmsAlerts.tsx");
    expect(bad).toEqual([]);
  });
});

// A class test for wp10-r13-1. The close button of a shell banner leaves with its banner. Every dismissal that useAdminBanners
// hands to the stack (an alert's acknowledgement, a hidden notice) names keepBannerFocus, which gives the focus to the next
// banner, or to the main region when there is none. The rule is on the handler, so a third banner kind cannot forget it.
describe("a shell banner's dismissal keeps the focus", () => {
  it("every onDismiss of useAdminBanners goes through keepBannerFocus", () => {
    const text = readFileSync(join(root, "../shell/useAdminBanners.ts"), "utf8");
    // The handler may span lines, so each one is the text between its key and the next 80 characters.
    const handlers = [...text.matchAll(/onDismiss:/g)].map((m) => text.slice(m.index, m.index + 80));
    expect(handlers.length, "the alert banner and the notice banner both have one").toBeGreaterThanOrEqual(2);
    expect(handlers.filter((chunk) => !/keepBannerFocus\(/.test(chunk))).toEqual([]);
  });

  // wp10-r14-2. A failed acknowledgement is said: nothing else in the shell reads that mutation's error, so a swallowed rejection
  // makes Dismiss look dead.
  it("a failed alert acknowledgement is shown, not swallowed", () => {
    const text = readFileSync(join(root, "../shell/useAdminBanners.ts"), "utf8");
    expect(text).not.toMatch(/\.catch\(\(\) => undefined\)/);
    expect(text).toMatch(/\.catch\(\(error: unknown\) => \{\s*toast\.danger\(errorText\(error\)\)/);
  });

  // wp10-r14-1. The "n more" button leaves with the press, so the same stack hands the focus to the first banner it revealed.
  it("the 'more' button of the stack notes that the focus is to follow, and the effect moves it", () => {
    const text = readFileSync(join(root, "../shell/BannerStack.tsx"), "utf8");
    expect(text).toMatch(/revealed\.current = true;\s*setExpanded\(true\)/);
    expect(text).toMatch(/\[MAX_SHOWN\]/);
    expect(text).toMatch(/\.focus\(\)/);
  });
});

// A class test for wp10-r9-4. The read before a write runs under a key of its own, so that a failed read cannot put an error on the
// query the page renders from, which swaps the open form for a section error and throws the admin's edits away.
describe("the read before a write", () => {
  it("never runs on the page's own query key", () => {
    const check = readFileSync(join(root, "shared/useServerCheck.ts"), "utf8");
    expect(check).toMatch(/queryKey: checkKey\(/);
    expect(check).toMatch(/setQueryData\(options\.queryKey/);
    const direct = sources(root).filter((file) => !file.endsWith("useServerCheck.ts") && /\bfetchQuery\(/.test(readFileSync(file, "utf8")));
    expect(direct.map((file) => file.slice(root.length + 1).replaceAll("\\", "/"))).toEqual([]);
  });
});

// A class test for wp10-r7-3. A number the page shows goes through the page formatter, so Persian digits show in fa (spec 4.4);
// only what is sent is ASCII. The note that names what another admin saved is such a place, and String(n) there prints Latin digits
// next to a field that shows Persian ones.
describe("a conflict note's value", () => {
  it("is never a number turned into text by String()", () => {
    const bad = sources(root).filter((file) => /<ConflictNote\b[^>]*\bvalue=\{[^}]*\bString\(/s.test(readFileSync(file, "utf8")));
    expect(bad).toEqual([]);
  });
});

// A class test for wp10-r10-1. A page query that was refetched in the background and failed keeps its old `data` and sets `error`
// (a reconnect refetch, or the invalidation after a write). A parent that renders SectionError whenever `error` is set unmounts an
// open form, its edits and the Edit credentials dialog with the pasted key. So an admin page gates on `!query.data` only, and
// shows RefreshFailed for the error it still holds. The Stats tab has no state to lose and stays as it is.
describe("a page with a form under a query", () => {
  const readOnly = ["StatsTab.tsx"];
  const pages = sources(root).filter((file) => /[\\/](sms|settings)[\\/]/.test(file) && !readOnly.some((name) => file.endsWith(name)));

  it("never decides between the form and the section error on an error that came with data (wp10-r11-3)", () => {
    // Not one text order of the old gate but the rule behind it: outside the props of SectionError and RefreshFailed, a page reads
    // no `.error` and no `.isError` of a query that has data. So `!x.data || x.error`, `x.isError || !x.data` and a ternary on
    // `x.error` all fail. The impact counts are the other way round on purpose (wp10-r4-2: old numbers after a failed refresh must
    // not be confirmed on), and the outbox poll is the result of a test send inside its own dialog, not a page.
    const own = new Set(["impact", "outbox", "form", "save", "ack"]);
    const bad: string[] = [];
    for (const file of pages) {
      const text = readFileSync(file, "utf8").replace(/<(?:RefreshFailed|SectionError)\b[\s\S]*?\/>/g, "");
      const queries = new Set([...text.matchAll(/\b(\w+)\.data\b/g)].map((m) => m[1]!).filter((name) => !own.has(name)));
      for (const m of text.matchAll(/\b(\w+)\.(error|isError)\b/g)) {
        if (queries.has(m[1]!)) bad.push(`${file.slice(root.length + 1).replaceAll("\\", "/")}: ${m[0]}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("says the refresh failed where it keeps the form", () => {
    const withQuery = pages.filter((file) => /\bSectionError\b/.test(readFileSync(file, "utf8")));
    expect(withQuery.length).toBeGreaterThan(0);
    expect(withQuery.filter((file) => !readFileSync(file, "utf8").includes("<RefreshFailed"))).toEqual([]);
  });
});

// A class test for wp10-r20-3. Spec 4.4 sends every shown number through useAppFormat, the one place that holds Intl settings.
// next-intl's own formatter is a second one: it grouped the digits of a conflict note (۱۰٬۰۰۰) next to a field that shows ۱۰۰۰۰.
describe("a number on the page", () => {
  it("never goes through next-intl's useFormatter in the admin app or the shared UI", () => {
    const uiRoot = join(__dirname, "..");
    const bad = sources(uiRoot).filter((file) => /useFormatter/.test(readFileSync(file, "utf8")));
    expect(bad).toEqual([]);
  });
});

// A class test for wp10-r20-1. Giving the focus back is for the keyboard; the remembered focus is empty after a pointer press, so a
// Save that was clicked never sends the focus to the form's first field.
describe("the focus that a write or a removal gives back", () => {
  it("is remembered only after a keyboard interaction", () => {
    const source = readFileSync(join(root, "shared/restoreFocus.ts"), "utf8");
    expect(source).toContain('if (typeof document === "undefined" || !keyboardDriven) return null');
    expect(source).toContain("trackModality(document)");
  });
});

// A class test for wp10-r20-2. A polite live region inserted with its text is often not spoken. The conflict note is role="alert"
// (announced on insertion), and the Settings impact panels are a LiveStatus (the container first, the text after).
describe("a message that appears with its text", () => {
  it("the conflict note is an alert, never a status region", () => {
    const note = readFileSync(join(root, "shared/ConflictNote.tsx"), "utf8");
    expect(note).toMatch(/role="alert"/);
    expect(note).not.toMatch(/role="status"/);
  });
  it("the empty LiveStatus stays in the accessibility tree, so it is never display:none (wp10-r21-1)", () => {
    const source = readFileSync(join(root, "shared/LiveStatus.tsx"), "utf8");
    // Comments may name the old class; only the rendered className counts.
    const code = source
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("//"))
      .join("\n");
    expect(code).not.toMatch(/\bhidden\b|display:\s*none/);
    expect(code).toContain("empty:sr-only");
  });
  it("the registration and passkey impact panels are a LiveStatus, not a div with role=status", () => {
    for (const file of ["settings/RegistrationCard.tsx", "settings/WebauthnCard.tsx"]) {
      const source = readFileSync(join(root, file), "utf8");
      expect(source, file).toContain("<LiveStatus ");
      expect(source, file).not.toMatch(/role="status"/);
    }
  });
});
