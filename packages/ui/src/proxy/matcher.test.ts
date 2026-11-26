import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";

import {afterEach, beforeEach, describe, expect, it} from "vitest";

import {checkCompiledMatcher, checkMatcher, excludedNames, matcherLiteral, staticPaths} from "./matcher.ts";

const GOOD = "/((?!logo\\.png$|icon\\.png$).*)";

describe("checkMatcher", () => {
  let dir: string;
  const put = (path: string) => {
    mkdirSync(dirname(join(dir, path)), {recursive: true});
    writeFileSync(join(dir, path), "x");
  };
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ctrlz-matcher-"));
    put("public/logo.png");
    put("src/app/icon.png");
    put("src/app/[locale]/page.tsx");
  });
  afterEach(() => rmSync(dir, {recursive: true, force: true}));

  it("lists public files and root metadata files, and no page", () => {
    expect(staticPaths(dir).sort()).toEqual(["/icon.png", "/logo.png"]);
  });
  it("lists the root metadata routes that are written as code, under the path they answer", () => {
    put("src/app/robots.ts");
    put("src/app/sitemap.ts");
    put("src/app/manifest.ts");
    put("src/app/icon2.tsx");
    put("src/app/apple-icon.tsx");
    put("src/app/opengraph-image.tsx");
    put("src/app/twitter-image.jsx");
    put("src/app/[locale]/robots.ts"); // not at the root: not a root route
    expect(staticPaths(dir).sort()).toEqual([
      "/apple-icon",
      "/icon.png",
      "/icon2",
      "/logo.png",
      "/manifest.webmanifest",
      "/opengraph-image",
      "/robots.txt",
      "/sitemap.xml",
      "/twitter-image",
    ]);
  });
  it("walks a dot folder of public, which Next serves, and skips only the placeholders (wp5-r3-3)", () => {
    put("public/.well-known/security.txt");
    put("public/.gitkeep");
    put("public/.DS_Store");
    put("public/.gitignore");
    put("public/.hidden-file");
    expect(staticPaths(dir).sort()).toEqual(["/.hidden-file", "/.well-known/security.txt", "/icon.png", "/logo.png"]);
  });
  it("fails on a file in a dot folder that the matcher does not name, since the proxy would redirect it to /fa/.well-known/... (wp5-r3-3)", () => {
    put("public/.well-known/a.txt");
    expect(checkMatcher(GOOD, dir).join("\n")).toContain("/.well-known/a.txt is a static file but the proxy runs on it");
  });
  it("accepts a matcher that names the dot folder's file", () => {
    put("public/.well-known/a.txt");
    expect(checkMatcher("/((?!logo\\.png$|icon\\.png$|\\.well-known/a\\.txt$).*)", dir)).toEqual([]);
  });
  it("accepts the matcher of the apps", () => {
    expect(checkMatcher(GOOD, dir).sort()).toEqual([]);
  });
  it("fails on a new file in public that the matcher does not name", () => {
    put("public/robots.txt");
    put("public/manifest.webmanifest");
    expect(checkMatcher(GOOD, dir).sort()).toEqual([
      expect.stringContaining("/manifest.webmanifest is a static file"),
      expect.stringContaining("/robots.txt is a static file"),
    ]);
  });
  it("fails on a dynamic metadata route whose path the matcher does not name", () => {
    put("src/app/robots.ts");
    put("src/app/icon.tsx");
    const problems = checkMatcher(GOOD, dir).join("\n");
    expect(problems).toContain("/robots.txt is a static file");
    expect(problems).toContain("/icon is a static file");
  });
  it("fails when a dot is not escaped, because the lookalike /logoXpng would skip the proxy", () => {
    const problems = checkMatcher("/((?!logo.png$|icon\\.png$).*)", dir);
    expect(problems.join("\n")).toContain("/logoXpng must reach the proxy");
    expect(problems.join("\n")).toContain('"logo.png$" has an unescaped dot');
  });
  it("checks the unescaped dot of the first name too, which follows (?! and not a bar", () => {
    const problems = checkMatcher("/((?!logo.png$|icon\\.png$).*)", dir);
    expect(problems.join("\n")).toContain('"logo.png$" has an unescaped dot');
    // A name that no lookalike in MUST_RUN reaches is still reported on its dot alone.
    expect(checkMatcher("/((?!robots.txt$|logo\\.png$|icon\\.png$).*)", dir).join("\n")).toContain('"robots.txt$" has an unescaped dot');
  });
  // wp5-r4-3: one escaped dot in a name must not vouch for the others.
  it("tests every dot of a name, not only whether the name has an escaped one", () => {
    put("public/logo.min.png");
    put("public/site.v2.webmanifest");
    const bad = checkMatcher("/((?!logo\\.min.png$|icon\\.png$|logo\\.png$).*)", dir).join("\n");
    expect(bad).toContain('"logo\\.min.png$" has an unescaped dot');
    // The second name of three, written with the dot after the version unescaped.
    expect(checkMatcher("/((?!logo\\.png$|icon\\.png$|logo\\.min\\.png$|site\\.v2.webmanifest$).*)", dir).join("\n")).toContain('"site\\.v2.webmanifest$" has an unescaped dot');
    expect(checkMatcher("/((?!logo\\.min\\.png$|site\\.v2\\.webmanifest$|logo\\.png$|icon\\.png$).*)", dir)).toEqual([]);
  });
  it("fails on a matcher that skips pages, or excludes Next's build output, which createProxy handles", () => {
    expect(checkMatcher("/((?!logo\\.png$|icon\\.png$|fa).*)", dir).join("\n")).toContain("/fa must reach the proxy");
    expect(checkMatcher("/((?!_next/static/|logo\\.png$|icon\\.png$).*)", dir).join("\n")).toContain("/_next/static/chunks/a.js must reach the proxy");
  });

  // wp5-r1-9: an excluded folder serves HTML that the proxy never touched, with no CSP and the client's nonce.
  it.each(["api/", "_next/", "_next/static/", "logos/", "logos/[^/]+\\.svg$", "favicon\\.ico$", "_next/image"])(
    "fails on the excluded name %s: a name that no file of the app matches hides a 404 from the proxy",
    (name) => {
      const problems = checkMatcher(`/((?!${name}|logo\\.png$|icon\\.png$).*)`, dir).join("\n");
      expect(problems).toContain(`"${name}" is excluded but no file of the app matches it`);
    },
  );
  it("accepts an excluded name once a file matches it, as a logos folder will be", () => {
    put("public/logos/github.svg");
    expect(checkMatcher("/((?!logos/github\\.svg$|logo\\.png$|icon\\.png$).*)", dir)).toEqual([]);
    // A pattern for the whole folder lets /logos/nothing.svg through unseen, so the files are named one by one.
    const wide = checkMatcher("/((?!logos/[^/]+\\.svg$|logo\\.png$|icon\\.png$).*)", dir).join("\n");
    expect(wide).toContain("/logos/nothing.svg must reach the proxy");
    expect(wide).not.toContain("is excluded but no file");
    // Listing the folder lets /logos/nothing through unseen.
    expect(checkMatcher("/((?!logos/|logo\\.png$|icon\\.png$).*)", dir).join("\n")).toContain("/logos/nothing must reach the proxy");
  });
  // wp5-r5-4: "the matcher excludes files, never a folder" is enforced by shape and by probes made from the real files.
  describe("a name is one literal file (wp5-r5-4)", () => {
    beforeEach(() => {
      put("public/robots.txt");
      put("public/site.webmanifest");
      put("public/.well-known/security.txt");
    });
    const names = "logo\\.png$|icon\\.png$|robots\\.txt$|site\\.webmanifest$";
    it("accepts every file named one by one, the well-known file included", () => {
      expect(checkMatcher(`/((?!${names}|\\.well-known/security\\.txt$).*)`, dir)).toEqual([]);
    });
    it("fails on the folder of a real file", () => {
      const problems = checkMatcher(`/((?!${names}|\\.well-known/).*)`, dir).join("\n");
      expect(problems).toContain('"\\.well-known/" is not a literal file name that ends in $');
      expect(problems).toContain("/.well-known/nothing is no file but the matcher skips it");
    });
    it("fails on a name with no closing $, which is a prefix", () => {
      const problems = checkMatcher(`/((?!logo\\.png$|icon\\.png$|robots\\.txt|site\\.webmanifest$|\\.well-known/security\\.txt$).*)`, dir).join("\n");
      expect(problems).toContain('"robots\\.txt" is not a literal file name that ends in $');
      expect(problems).toContain("/robots.txt/x is no file but the matcher skips it");
    });
    it.each(["site\\.web\\w*$", "site\\.web.*$", "site\\.[a-z]+$"])("fails on the wildcard name %s", (name) => {
      const problems = checkMatcher(`/((?!logo\\.png$|icon\\.png$|robots\\.txt$|${name}|\\.well-known/security\\.txt$).*)`, dir).join("\n");
      expect(problems).toContain(`"${name}" is not a literal file name that ends in $`);
      expect(problems).toContain("is no file but the matcher skips it");
    });
    it("fails on a name that matches the file only as a prefix, whatever the shape", () => {
      // Every shape of the finding, with the guard on its probes alone: the literal-name rule is off here.
      const wide = "/((?!logo\\.png$|icon\\.png$|robots\\.txt$|site\\.webmanifest$|\\.well-known/).*)";
      expect(checkMatcher(wide, dir).filter((p) => p.includes("is no file but the matcher skips it"))).not.toEqual([]);
    });
  });
  it("reads the excluded names of a matcher", () => {
    expect(excludedNames(GOOD)).toEqual(["logo\\.png$", "icon\\.png$"]);
    expect(excludedNames("/(.*)")).toEqual([]);
  });
});

// gate-r6-2: the checks on the expression that Next compiled, read from the build.
describe("checkCompiledMatcher", () => {
  // Next 16.4.5 compiles GOOD into this, for the proxy of an app (read from a real build).
  const REAL = String.raw`^(?:\/(_next\/data\/[^/]{1,}))?(?:\/((?!logo\.png$|icon\.png$).*))(\.json|\.rsc|\.segments\/.+\.segment\.rsc)?[\/#\?]?$`;
  let dir: string;
  const put = (path: string, text = "x") => {
    mkdirSync(dirname(join(dir, path)), {recursive: true});
    writeFileSync(join(dir, path), text);
  };
  const build = (matchers: unknown) =>
    put(".next/server/functions-config-manifest.json", JSON.stringify({version: 1, functions: {"/_middleware": {runtime: "nodejs", matchers}}}));
  const literal = (source: string) => put("src/proxy.ts", `export const config = {\n  matcher: [${JSON.stringify(source)}],\n};\n`);
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ctrlz-compiled-"));
    put("public/logo.png");
    put("src/app/icon.png");
    literal(GOOD);
  });
  afterEach(() => rmSync(dir, {recursive: true, force: true}));

  it("passes for what Next really compiled", () => {
    build([{regexp: REAL, originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir)).toEqual([]);
  });
  it("reads the literal out of proxy.ts the way it is written, escapes included", () => {
    expect(matcherLiteral(join(dir, "src/proxy.ts"))).toBe(GOOD);
    put("src/proxy.ts", "export const config = {matcher: ['/x']};");
    expect(() => matcherLiteral(join(dir, "src/proxy.ts"))).toThrow(/no single matcher literal/);
  });
  it("throws when there is no build, so that a test cannot pass by finding nothing", () => {
    expect(() => checkCompiledMatcher(dir)).toThrow(/next build/);
  });
  it("fails when the build was made from another literal than proxy.ts holds", () => {
    build([{regexp: REAL, originalSource: String.raw`/((?!logo\.png$).*)`}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("build again");
  });
  it("fails when there is not exactly one matcher", () => {
    build([]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("holds 0 proxy matchers");
    build([{regexp: REAL, originalSource: GOOD}, {regexp: REAL, originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("holds 2 proxy matchers");
  });
  it("fails when a Next compiles the lookahead so that it skips more than the file (the `$` no longer ends the path)", () => {
    // Both `$` of the lookahead are gone: it then excludes every name that merely starts with logo.png or icon.png.
    build([{regexp: REAL.replace("logo\\.png$|icon\\.png$", "logo\\.png|icon\\.png"), originalSource: GOOD}]);
    const problems = checkCompiledMatcher(dir).join("\n");
    expect(problems).toContain("/logo.pngx is no file but the matcher skips it");
  });
  it("fails when the suffix group swallows a spelling of a file, which the model cannot see", () => {
    // A compile that runs the lookahead on the path without its suffix: `/logo.png.json` would then skip the proxy.
    build([{regexp: String.raw`^(?:\/((?!logo\.png(?:\.json)?$|icon\.png(?:\.json)?$).*))[\/#\?]?$`, originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("/logo.png.json is no file but the compiled matcher skips it");
  });
  it("fails when a file is not skipped, and when a page is", () => {
    build([{regexp: String.raw`^(?:\/(.*))$`, originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("/logo.png is a static file but the proxy runs on it");
    build([{regexp: String.raw`^(?:\/(?!fa\/).*)$`, originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("must reach the proxy but the matcher skips it");
  });
  it("fails on an expression that is not one", () => {
    build([{regexp: "^(", originalSource: GOOD}]);
    expect(checkCompiledMatcher(dir).join("\n")).toContain("is not a regular expression");
  });
});
