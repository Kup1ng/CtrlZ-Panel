import {Linter} from "eslint";
import tseslint from "typescript-eslint";
import {describe, expect, it} from "vitest";

import {exemptFiles, restrictedImports, restrictedSyntax, syntaxExcept} from "../src/banned.ts";

// One passing and one failing sample per ban (spec 16.1): a rule that silently never fires is
// worse than none. This runs the lists exactly as eslint.config.mjs does.

function lint(code: string, filename = "packages/ui/src/sample.tsx", syntax = restrictedSyntax.map(({selector, message}) => ({selector, message}))) {
  const linter = new Linter({configType: "flat"});
  const messages = linter.verify(
    code,
    [
      {
        files: ["**/*.{ts,tsx}"],
        languageOptions: {parser: tseslint.parser, parserOptions: {ecmaFeatures: {jsx: true}}},
        rules: {"no-restricted-syntax": ["error", ...syntax], "no-restricted-imports": ["error", restrictedImports]},
      },
    ],
    {filename},
  );
  return messages.map((m) => m.message);
}

const fails = (code: string, ...parts: string[]) => {
  const found = lint(code);
  expect(found.length, `no report for: ${code}`).toBeGreaterThan(0);
  for (const p of parts) expect(found.join("\n")).toContain(p);
};
const passes = (code: string) => expect(lint(code), `a report for: ${code}`).toEqual([]);

describe("physical edges in class strings", () => {
  it("fails on the physical classes", () => {
    for (const cls of ["ml-2", "pr-4", "-ml-4", "left-0", "text-left", "float-right", "border-l", "rounded-r-lg", "md:pl-3", "@max-lg:mr-1", "border-tl-lg"]) {
      fails(`const a = "flex ${cls}";`, "physical class");
    }
    fails("const a = `flex ${1} ml-2`;", "physical class");
  });
  it("passes the logical ones and look-alikes", () => {
    for (const cls of ["ms-2", "pe-4", "start-0", "text-start", "border-s", "rounded-e-lg", "rounded-lg", "border-light", "flex-col", "gap-x-3", "pl", "ml"]) {
      passes(`const a = "flex ${cls}";`);
    }
  });
});

describe("placement", () => {
  it("fails on a bare left or right", () => {
    fails(`const a = <Popover placement="left" />;`, "placement");
    fails(`const a = <Popover placement="bottom right" />;`, "placement");
    fails(`const a = <Popover placement={open ? "right top" : "bottom"} />;`, "placement");
    fails(`const a = {placement: "left"};`, "placement");
  });
  it("passes start, end and a computed edge", () => {
    passes(`const a = <Popover placement="bottom end" />;`);
    passes(`const a = <Popover placement={edge} />;`);
  });
});

describe("dark variant", () => {
  it("fails on dark: and on a resolved branch", () => {
    fails(`const a = "bg-white dark:bg-black";`, "dark");
    fails("const a = `x dark:bg-black`;", "dark");
    fails(`if (resolved === "dark") {}`, "theme");
  });
  it("passes a word that merely contains dark", () => {
    passes(`const a = "darkroom";`);
    passes(`const a = "text-foreground";`);
  });
});

describe("external URLs", () => {
  it("fails on http and https in a string or a template", () => {
    fails(`const a = "https://cdn.example.com/x.js";`, "http");
    fails(`const a = "see http://example.com";`, "http");
    fails("const a = `https://${host}/x`;", "http");
  });
  it("passes the SVG namespace and a plain path", () => {
    passes(`const a = <svg xmlns="http://www.w3.org/2000/svg" />;`);
    passes(`const a = "/fonts/DanaVF.woff2";`);
    passes(`const a = "nothttps";`);
  });
});

describe("raw Intl and toLocale", () => {
  it("fails outside the exempt files", () => {
    fails(`const a = new Intl.NumberFormat("fa");`, "Intl");
    fails(`const a = Intl.DateTimeFormat("fa");`, "Intl");
    fails(`const a = n.toLocaleString();`, "toLocale");
    fails(`const a = d.toLocaleDateString("fa");`, "toLocale");
  });
  it("passes in the file that wraps it, and for toLocaleLowerCase", () => {
    expect(lint(`const a = new Intl.NumberFormat("fa");`, "packages/i18n/src/format.ts", syntaxExcept("intl"))).toEqual([]);
    expect(exemptFiles.rawIntl).toContain("packages/i18n/src/format.ts");
    passes(`const a = s.toLocaleLowerCase();`);
  });
});

describe("next/script with a src", () => {
  it("fails with a src and passes inline", () => {
    fails(`const a = <Script src="/x.js" />;`, "next/script");
    passes(`const a = <Script id="x">{code}</Script>;`);
  });
});

describe("imports", () => {
  it("fails on the banned packages", () => {
    for (const src of ["lucide-react", "@iconify/react", "@gravity-ui/icons", "next-themes", "next/font/google"]) {
      expect(lint(`import x from "${src}";`).length, src).toBeGreaterThan(0);
    }
    expect(lint(`import {useTheme} from "@heroui/react";`).length).toBeGreaterThan(0);
  });
  it("passes the allowed ones", () => {
    passes(`import {Button} from "@heroui/react";`);
    passes(`import localFont from "next/font/local";`);
  });
});
