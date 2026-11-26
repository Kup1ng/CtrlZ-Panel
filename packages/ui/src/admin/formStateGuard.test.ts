import {readdirSync, readFileSync, statSync} from "node:fs";
import {join} from "node:path";

import {describe, expect, it} from "vitest";

// Class tests for two kinds of mistake the admin forms made again and again.

const root = __dirname;

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}

const rel = (file: string) => file.slice(root.length + 1).replaceAll("\\", "/");

describe("a form that edits a value the server holds (wp10-r2-4, wp10-r3-3)", () => {
  // `useState(server value)` is read once, so the form never follows a refetch and `draft !== server` is dirty for ever when
  // the server writes the value back in another form ("250000" and "250000.0000"). Such a form uses useServerDraft. These
  // are the seeds that are not a draft of the server's value.
  const allowed: Record<string, string> = {
    "settings/WebauthnCard.tsx settled": "the RP ID the impact count is asked for: it follows the typed name after a pause, it is not the form's value",
  };

  it("seeds no state from the current server row except through useServerDraft", () => {
    const loose: string[] = [];
    for (const file of sources(root)) {
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, i) => {
          const match = /const \[(\w+), \w+\] = useState(?:<[^>]*>)?\((.*)\)/.exec(line);
          if (!match || !/\b(current|row|gateway)\b/.test(match[2]!)) return;
          if (!allowed[`${rel(file)} ${match[1]}`]) loose.push(`${rel(file)}:${i + 1} ${line.trim()}`);
        });
    }
    expect(loose).toEqual([]);
  });
});

describe("a form of several fields keeps only the edited ones (wp10-r4-3)", () => {
  // A draft that is one object written back whole (`setDraft({...draft, x})`) freezes every field it holds at the first edit:
  // the untouched ones stop following the server, and the write, which replaces the whole object, undoes another admin's
  // change in a field this admin never touched. Several fields go through useServerForm's `edit`, which records only the
  // fields that changed.
  it("never writes a draft back as a spread of the whole draft", () => {
    const whole: string[] = [];
    for (const file of sources(root)) {
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (line.includes("setDraft({...draft") && !line.trimStart().startsWith("//")) whole.push(`${rel(file)}:${i + 1} ${line.trim()}`);
        });
    }
    expect(whole).toEqual([]);
  });

  it("builds the write of a multi-field form from the merged draft, not from a seed", () => {
    // The forms that replace a whole object on the server. Each reads its fields from the useServerForm draft.
    for (const file of ["sms/LimitsTab.tsx", "sms/RoutingTab.tsx", "settings/WebauthnCard.tsx", "sms/TemplatesTab.tsx"]) {
      expect(readFileSync(join(root, file), "utf8"), file).toMatch(/useServerForm[<(]/);
    }
  });
});

describe("a second factor code typed in Persian digits (wp10-r3-4)", () => {
  // The slots show what was typed, Persian digits included. A form submitted by its button, or by Enter, reads the state and
  // not the ASCII value `onComplete` hands over, so every form that has the field converts where it reads the code.
  const files = [...sources(root), join(root, "../auth/FreshTotpDialog.tsx")];

  it("converts the code to ASCII in every admin form that has an OtpField", () => {
    const plain: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      if (/<OtpField\b/.test(text) && !/toAsciiDigits\(/.test(text)) plain.push(file);
    }
    expect(plain).toEqual([]);
  });
});
