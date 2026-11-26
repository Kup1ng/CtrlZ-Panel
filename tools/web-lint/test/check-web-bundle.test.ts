import {mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import vm from "node:vm";

import {afterEach, beforeEach, describe, expect, it} from "vitest";

import {decode, explain, explainEntry, extractUrlEntries, extractUrls, hostOf, isLoadable, parseAllow, printable, scanApp, staleLines} from "../../../scripts/check-web-bundle.mjs";

// Spec 3.5: the bundle check. These tests build a tiny app folder and prove that the check fires, since
// a check that never fails is worse than none.

const allow = (text: string) => {
  const parsed = parseAllow(text);
  expect(parsed.problems).toEqual([]);
  return parsed.rules;
};

describe("extractUrls", () => {
  it("finds http, https, ws and wss, and drops the query, the fragment and trailing punctuation", () => {
    expect(extractUrls(`a("https://x.test/a?q=one#frag"); b = 'http://y.test.'; new WebSocket("wss://z.test:")`)).toEqual([
      "https://x.test/a",
      "http://y.test",
      "wss://z.test",
    ]);
  });
  it("never keeps a query string, so a token in one cannot be printed", () => {
    expect(extractUrls("https://h.test/p?q=in-the-query").join()).not.toContain("in-the-query");
  });
  it("keeps a template placeholder, which is how a URL built at run time shows", () => {
    expect(extractUrls("`https://${host}/x`")).toEqual(["https://${host"]);
  });
  it("stops at an escaped newline and at brackets", () => {
    expect(extractUrls(String.raw`"see https://a.test/docs\n" (https://b.test/x)`)).toEqual(["https://a.test/docs", "https://b.test/x"]);
  });
  it("finds a scheme-relative URL, which a browser fetches with the page's scheme", () => {
    expect(extractUrls(`a = "//cdn.evil.example/x.js"; @import url(//fonts.example/css?family=x); b = '//host.test:8080/p'`)).toEqual([
      "//cdn.evil.example/x.js",
      "//fonts.example/css",
      "//host.test:8080/p",
    ]);
  });
  it("finds a scheme-relative URL whose host is an address or a Unicode name, not only a dotted ASCII name (wp5-r3-2)", () => {
    expect(
      extractUrls(
        [
          'a = "//1.2.3.4/x.js"',
          "b = '//203.0.113.7/lib.js'",
          "@import url(//192.0.2.1/a.css);",
          'c = "//[::1]/x.js"',
          'd = "//[2001:db8::7]:8080/x"',
          'e = "//пример.рф/x.js"',
          'f = "//münchen.de/a"',
          'g = "//xn--e1afmkfd.xn--p1ai/x.js"',
          'h = "//cdn.example.com/ok.js"',
        ].join("\n"),
      ),
    ).toEqual([
      "//1.2.3.4/x.js",
      "//203.0.113.7/lib.js",
      "//192.0.2.1/a.css",
      "//[::1]/x.js",
      "//[2001:db8::7]:8080/x",
      "//пример.рф/x.js",
      "//münchen.de/a",
      "//xn--e1afmkfd.xn--p1ai/x.js",
      "//cdn.example.com/ok.js",
    ]);
  });
  it("does not take a spaced comment, a word-glued path or a number for a scheme-relative address", () => {
    const text = ["// 1.2.3.4 is the address", "x = a//1.2.3.4", "y = 1//2.5.6.7", "z = '//1.2.3.4.5/x'", "w = '//1.2.3/x'", "v = '//[abc]/x'", "u = '//12.34.56.78901'"].join(String.fromCharCode(10));
    expect(extractUrls(text)).toEqual([]);
  });
  it("finds a URL whose slashes are escaped, as in JSON, an RSC payload and a JS string", () => {
    const BS = String.fromCharCode(92); // a backslash, spelled so that no escaping rule can change it
    const slash = (n: number) => "/".padStart(n + 1, BS).slice(0, n + 1); // n backslashes, then a slash
    const escaped = [
      `"https:${slash(1)}${slash(1)}esc.example${slash(1)}x.js"`,
      `"https:${slash(2)}${slash(2)}double.example${slash(2)}y"`,
      `"https:${BS}u002f${BS}u002fu.example${BS}u002fz"`,
      `"${slash(1)}${slash(1)}rel.example${slash(1)}w"`,
    ].join(",");
    expect(extractUrls(escaped).sort()).toEqual(["//rel.example/w", "https://double.example/y", "https://esc.example/x.js", "https://u.example/z"]);
  });
  it("does not take a comment, a path, a regular expression or a number for a scheme-relative URL", () => {
    const text = ["// a comment with a.dot", "x = a//b.c", "/* //# sourceMappingURL=a.js.map */", "y = 1//2.5", "z = '-//W3C//DTD HTML 4.01//EN'", "p = `${base}//x.y`", "q = ./a/b//c.d"].join(String.fromCharCode(10));
    expect(extractUrls(text)).toEqual([]);
  });
  it("counts a schemed URL once, not again as a scheme-relative one", () => {
    expect(extractUrls("https://x.test/a http://y.test/b")).toEqual(["https://x.test/a", "http://y.test/b"]);
  });
  it("keeps what the query holds for the decision, though never in the string", () => {
    const entries = extractUrlEntries('a("https://h.test/o/r/blob/main/a.js?raw=true#top"); b("https://h.test/p#raw=1"); c("https://h.test/q")');
    expect(entries.map((e) => [e.url, e.query])).toEqual([
      ["https://h.test/o/r/blob/main/a.js", "raw=true"],
      ["https://h.test/p", ""],
      ["https://h.test/q", ""],
    ]);
  });
  it("marks a string that was cut inside its authority while an @ follows", () => {
    const partial = (text: string) => extractUrlEntries(text).map((e) => e.partial);
    expect(partial('x="https://deploy:Xy7?Qp9#zz@registry.example.ir/v2"')).toEqual([true]);
    expect(partial('x="https://ci-bot:ghp_AAAA)x@github.com"')).toEqual([true]);
    expect(partial('x="https://admin:S3cr;et@h.example/x"')).toEqual([true]);
    expect(partial('x="https://h.test/p?mail=a@b.c"')).toEqual([false]);
    expect(partial('x="https://h.test/p" y="a@b.c"')).toEqual([false]);
  });
  it("marks a string whose secret holds a slash or an escaped quote, or whose path holds the @ after a colon (wp5-r3-6)", () => {
    const partial = (text: string) => extractUrlEntries(text).map((e) => e.partial);
    // the cut is at the ?, and the @ comes after a slash that the first version of the scan stopped at
    expect(partial('x="https://ci.bot:12345?pw/x@reg.example.ir/v2"')).toEqual([true]);
    // the cut is at a backslash, and the @ follows an escaped quote
    expect(partial(String.raw`x="https://first.last:2024\"x@h.example"`)).toEqual([true]);
    // whole URL, and the "password" starts after a slash: a browser reads host, port and path, a person wrote a secret
    expect(partial("x='https://deploy.bot:4321/aB9x@registry.example.ir'")).toEqual([true]);
    // no colon in the authority and an @ only in the path (a package version): a plain host, shown as such
    expect(partial("x='https://cdn.example/pkg@1.0/a.js'")).toEqual([false]);
    // a proper userinfo is the usual case printable() already hides
    expect(partial("x='https://svc:pw@api.example/v1'")).toEqual([false]);
  });
  it("prints neither the account name nor the first digits of a secret cut at a slash or an escaped quote (wp5-r3-6)", () => {
    const secrets = /ci\.bot|first\.last|deploy\.bot|12345|2024|4321|aB9x/;
    for (const text of [
      'x="https://ci.bot:12345?pw/x@reg.example.ir/v2"',
      String.raw`x="https://first.last:2024\"x@h.example"`,
      "x='https://deploy.bot:4321/aB9x@registry.example.ir'",
    ]) {
      for (const {url, partial} of extractUrlEntries(text)) expect(printable(url, partial), text).not.toMatch(secrets);
    }
  });
  // wp5-r4-7: a browser reads a backslash as a slash, ignores how many slashes follow a special scheme, and
  // takes `http:evil.example` for a URL, so each of these goes to the host that follows.
  it("finds the spellings that a browser resolves to another host: backslashes, missing slashes, odd runs (wp5-r4-7)", () => {
    const BS = String.fromCharCode(92);
    const cases: Array<[string, string]> = [
      [`"/${BS}${BS}evil.example/a.js"`, "//evil.example/a.js"], // minified source of "/\\evil.example/a.js"
      [`"/${BS}evil.example/a.js"`, "//evil.example/a.js"], // the same after JSON has decoded it
      [`"${BS}${BS}${BS}${BS}evil.example/a.js"`, "//evil.example/a.js"],
      [`"${BS}${BS}evil.example/a.js"`, "//evil.example/a.js"],
      [`"https:${BS}${BS}${BS}${BS}evil.example/a.js"`, "https://evil.example/a.js"],
      [`"https:${BS}${BS}evil.example"`, "https://evil.example"],
      ['"http:evil.example/a.js"', "http://evil.example/a.js"],
      ['"http:/evil.example/a.js"', "http://evil.example/a.js"],
      ['"ws:evil.example/x"', "ws://evil.example/x"],
      ['"wss:/evil.example/x"', "wss://evil.example/x"],
      ['"https:////evil.example/x"', "https://evil.example/x"],
    ];
    for (const [text, url] of cases) {
      expect(extractUrls(text), text).toEqual([url]);
      expect(hostOf(url), text).toBe("evil.example");
    }
  });
  it("does not take a property, a ternary, a regular expression or a word for one of those spellings (wp5-r4-7)", () => {
    const BS = String.fromCharCode(92);
    for (const text of [
      "a//b.c",
      "agent = tls ? u.https:u.http",
      "x = o.http:y.example",
      "see the http: header, or https: and then ws: later",
      `"${BS}${BS}d+${BS}${BS}.${BS}${BS}w+"`,
      `"C:${BS}${BS}Users${BS}${BS}x"`,
    ]) {
      expect(extractUrls(text).filter((u) => /evil|y\.example|\*|verify|Users/.test(u)), text).toEqual([]);
    }
    // The escaped-slash regular expression yields the bare scheme as it is written, and the string its escapes make
    // when it is read as a JS string (a backslash before an ordinary character is that character, wp5-r6-1), and no host.
    expect(extractUrls(`/^https:${BS}/${BS}/${BS}*${BS}.verify${BS}.dns/`).sort()).toEqual(["https://", "https://*.verify.dns/"]);
  });
  it("finds nothing in plain text", () => {
    expect(extractUrls("a // comment, 1/2, https only")).toEqual([]);
  });
});

describe("printable", () => {
  it("shows scheme and host only, and says that a path and userinfo were hidden", () => {
    expect(printable("https://hooks.slack.com/services/T0/B0/SECRETSECRET")).toBe("https://hooks.slack.com  [path of 28 characters hidden]");
    expect(printable("https://user:pw@h.test/x")).toBe("https://h.test  [userinfo hidden, path of 2 characters hidden]");
    expect(printable("//cdn.test/a")).toBe("//cdn.test  [path of 2 characters hidden]");
  });
  it("keeps a bare host whole and shows a placeholder host as it is", () => {
    expect(printable("https://h.test")).toBe("https://h.test");
    expect(printable("https://${origin")).toBe("https://${origin");
  });
  it("never prints a secret from userinfo, the path or an odd shape", () => {
    for (const url of ["https://svc:Sup3rS3cret@api.example.ir/v1", "https://api.telegram.org/bot123456:ABC-DEF/getMe", "wss://h.test:9/a/TOKENTOKEN", "https://a.test@evil.test:Sup3r@h.test/x"]) {
      expect(printable(url), url).not.toMatch(/Sup3r|ABC-DEF|TOKENTOKEN|bot123456|svc:/);
    }
  });
  it("prints an authority only when all of it is a host name, an address or a placeholder, and never a port", () => {
    expect(printable("https://api.example.ir/v1")).toBe("https://api.example.ir  [path of 3 characters hidden]");
    expect(printable("https://api.example.ir:8443/v1")).toBe("https://[authority of 19 characters hidden]  [path of 3 characters hidden]");
    expect(printable("http://localhost:3410")).toBe("http://[authority of 14 characters hidden]");
    expect(printable("http://localhost")).toBe("http://localhost");
    expect(printable("http://127.0.0.1/x")).toBe("http://127.0.0.1  [path of 2 characters hidden]");
    expect(printable("https://${origin")).toBe("https://${origin");
    for (const url of ["https://svc:Ab3", "https://deploy", "https://a b", "https://x.test:80:90", "https://[::1]:80/x", "https://ho st.test/x"]) {
      expect(printable(url), url).toMatch(/^https:\/\/\[authority of \d+ characters hidden\]/);
    }
  });
  it("hides the authority of a string that was cut before its @, whatever the cut character was", () => {
    // The extractor ends a URL at ? # ; , ) ] } | ^ and a quote, so a userinfo that holds one is cut and its
    // @ never reaches printable: it must not take the user name or the start of a password for a host.
    const secrets = /deploy|Xy7|Ab3|S3cr|ci-bot|ci\.bot|ghp_|AAAA|kL9|Zq/;
    for (const text of [
      'x = "https://deploy:Xy7?Qp9#zz@registry.example.ir/v2"',
      'x = "https://svc:Ab3/kL9+Zq==@api.example.ir/v1"',
      'x = "https://admin:S3cr;et@h.example/x"',
      'x = "https://ci-bot:ghp_AAAABBBBCCCCDDDD)x@github.com"',
      'x = "https://deploy?x=1@h.example/x"',
      'x = "https://ci.bot,Xy7@h.example/x"',
    ]) {
      for (const {url, partial} of extractUrlEntries(text)) expect(printable(url, partial), text).not.toMatch(secrets);
    }
  });
});

describe("printable, a class and not one more cut character (wp5-r4-1)", () => {
  // The extractor cuts a URL at whitespace, a quote, a backtick, < and >, so a userinfo that holds one is cut
  // inside it and what is left (`ci.bot:1234`) looks like a host and a port. Rounds 2 and 3 closed the cut
  // characters one by one. The rule now is that a colon in the authority hides all of it, with or without an @ later.
  it("never prints the account name or the first digits of a password, whichever character cut the string", () => {
    for (const cut of ["'", "`", "<", ">", " ", '"', "\t", "?", "#", ";", ",", ")", "]", "}", "|", "^", "/"]) {
      const text = `x = "https://ci.bot:1234${cut}5@reg.example.ir/v2"`;
      for (const {url, partial} of extractUrlEntries(text)) {
        expect(printable(url, partial), JSON.stringify(cut)).not.toMatch(/ci\.bot|1234/);
      }
    }
  });
  it("hides every authority that holds a colon, a port included, and prints a bare host", () => {
    for (const url of ["https://ci.bot:1234", "https://reg.example.ir:8443/x", "http://localhost:3000", "https://${a}:${b"]) {
      expect(printable(url), url).toMatch(/^https?:\/\/\[authority of \d+ characters hidden\]/);
    }
    expect(printable("https://reg.example.ir/v2")).toBe("https://reg.example.ir  [path of 3 characters hidden]");
  });
});

describe("hostOf", () => {
  it("reads the host of a scheme-relative URL", () => {
    expect(hostOf("//Cdn.Test/x")).toBe("cdn.test");
  });
  it("lower-cases the host and drops port and path", () => {
    expect(hostOf("https://Next.JS.org:8080/docs")).toBe("next.js.org");
    expect(hostOf("https://${origin")).toBe("${origin");
  });
});

describe("parseAllow", () => {
  it("reads url and host lines, with a scope for url", () => {
    const rules = allow("url https://a.test https://b.test in node_modules/next/ # reason\nhost X.test y.test # other\n# comment\n\n");
    expect(rules).toHaveLength(2);
    expect(rules[0]).toMatchObject({kind: "url", values: ["https://a.test", "https://b.test"], scope: "node_modules/next/"});
    expect(rules[1]).toMatchObject({kind: "host", values: ["x.test", "y.test"]});
  });
  it("refuses a line with no reason, an unknown kind, a host with a scheme or a scope, and an empty line of values", () => {
    const {problems} = parseAllow(
      ["url https://a.test", "domain a.test # why", "host https://a.test # why", "host a.test in x/ # why", "url in x/ # why", "url https://a.test in # why"].join("\n"),
    );
    expect(problems).toHaveLength(6);
  });
});

describe("explain", () => {
  const rules = allow(
    [
      "url https://exact.test # in the browser bundle",
      "url https://scoped.test in node_modules/next/ # only in next",
      "host docs.test # docs",
    ].join("\n"),
  );
  it("matches an exact string anywhere", () => {
    expect(explain("https://exact.test", ".next/static/a.js", rules)).toBe(rules[0]);
    expect(explain("https://exact.test/more", ".next/static/a.js", rules)).toBeUndefined();
  });
  it("matches a scoped string only in its path", () => {
    expect(explain("https://scoped.test", ".next/standalone/apps/panel/node_modules/next/dist/a.js", rules)).toBe(rules[1]);
    expect(explain("https://scoped.test", ".next/static/a.js", rules)).toBeUndefined();
  });
  it("accepts a host in node_modules inside .next/standalone and never in the browser bundle or public", () => {
    expect(explain("https://docs.test/any/path", ".next/standalone/apps/panel/node_modules/pkg/a.js", rules)).toBe(rules[2]);
    expect(explain("https://docs.test/any/path", ".next/static/chunks/a.js", rules)).toBeUndefined();
    expect(explain("https://docs.test/any/path", "public/logos/a.svg", rules)).toBeUndefined();
  });
  it("counts a host line only for files under node_modules, not for the compiled code of this repository", () => {
    expect(explain("https://docs.test/x", ".next/standalone/apps/panel/node_modules/next/dist/a.js", rules)).toBe(rules[2]);
    expect(explain("https://docs.test/x", ".next/standalone/node_modules/.pnpm/next@1/node_modules/next/a.js", rules)).toBe(rules[2]);
    for (const path of [".next/standalone/apps/panel/.next/server/chunks/ssr/a.js", ".next/standalone/apps/panel/server.js", ".next/standalone/apps/panel/.next/server/app/fa.html"]) {
      expect(explain("https://docs.test/x", path, rules), path).toBeUndefined();
    }
  });
  it("never lets a host line vouch for a file that a program loads, but does for a page", () => {
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    for (const url of ["https://docs.test/lib.js", "https://docs.test/a.css", "https://docs.test/s/a.json", "https://docs.test/i.png", "https://docs.test/o/r/releases/download/v1/x", "https://docs.test/o/r/archive/main", "https://docs.test/o/r/raw", "https://docs.test/x.JS"]) {
      expect(explain(url, path, rules), url).toBeUndefined();
    }
    for (const url of ["https://docs.test/docs/page", "https://docs.test/o/r/blob/abc/src/x.js", "https://docs.test/o/r/issues/12", "https://docs.test/a.jsx.html"]) {
      expect(explain(url, path, rules), url).toBe(rules[2]);
    }
    expect(isLoadable("https://h.test/x.js")).toBe(true);
    expect(isLoadable("https://x.js/page")).toBe(false);
  });
  it("does not let a look-alike host through, on a path where a host line does count", () => {
    // Under node_modules, so the host match is really made: the first version of this case used a path where
    // no host line applies, and passed whether or not the host was read right (wp5-r2-1).
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    for (const url of [
      "https://docs.test.evil.example/x",
      "https://notdocs.test/x",
      "https://docs.test@evil.example/x",
      "https://docs.test:pw@evil.example/x",
      "https://docs.test:80@evil.example/x",
      "https://user:docs.test@evil.example/x",
      "//docs.test:pw@evil.example/x",
      "https://docs.test%40evil.example/x",
    ]) {
      expect(explain(url, path, rules), url).toBeUndefined();
    }
    // The browser ends the authority at the first / ? or #, so what follows a ? is not userinfo.
    expect(explain("https://evil.example?a@docs.test", path, rules)).toBeUndefined();
    expect(explain("https://u:p@docs.test/page", path, rules)).toBe(rules[2]);
  });
  it("reads the host the way a browser does", () => {
    const cases: [string, string][] = [
      ["https://github.com:pw@evil.example/a", "evil.example"],
      ["https://a:b:c@evil.example:8080/a", "evil.example"],
      ["https://evil.example?a@docs.test", "evil.example"],
      ["https://evil.example#a@docs.test", "evil.example"],
      ["https://evil.example/a@docs.test", "evil.example"],
      ["//u:p@Cdn.Test/x", "cdn.test"],
    ];
    for (const [url, host] of cases) expect(hostOf(url), url).toBe(host);
  });
  it("never lets a host line vouch for a release asset, an archive, a clone URL or a raw view, in any spelling", () => {
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    for (const url of [
      "https://docs.test/o/r/releases/latest/download/tool",
      "https://docs.test/o/r/releases/download/v1/tool",
      "https://docs.test/o/r/zipball/main",
      "https://docs.test/o/r/tarball/main",
      "https://docs.test/o/r.git",
      "https://docs.test/o/r.git/info/refs",
      "https://docs.test/o/r/archive/refs/tags/v1",
      // a viewer page that climbs out of its folder is not a viewer page
      "https://docs.test/o/r/blob/main/a.js/../../../raw/x.js",
      "https://docs.test/o/r/blob/main/a.js/%2e%2e/%2e%2e/%2e%2e/raw/x",
      "https://docs.test/o/r/blob/main/a%2f..%2fraw",
      // the viewer exemption starts at the start of the path
      "https://docs.test/x/blob/y/z.js",
      "https://docs.test/o/blob/main/a.js",
    ]) {
      expect(explain(url, path, rules), url).toBeUndefined();
    }
  });
  it("lets a host line vouch only for a page shape, so no archive, package or Git endpoint can pass by its extension (wp5-r3-5)", () => {
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    for (const url of [
      // the four the reviewer measured
      "https://docs.test/dist/v26.13.0/node-v26.13.0-linux-x64.tar.xz",
      "https://docs.test/o/r/media/main/x",
      "https://docs.test/o/r/info/refs",
      "https://docs.test/o/r/releases/expanded_assets/v1",
      // an extension of any kind is a file, not only the ones a list knew
      "https://docs.test/a.xz",
      "https://docs.test/a.bz2",
      "https://docs.test/a.7z",
      "https://docs.test/a.msi",
      "https://docs.test/a.deb",
      "https://docs.test/a.rpm",
      "https://docs.test/a.jar",
      "https://docs.test/a.whl",
      "https://docs.test/a.dmg",
      "https://docs.test/a.pkg",
      "https://docs.test/a.pdf",
      "https://docs.test/a.php",
      "https://docs.test/x/show_bug.cgi",
      // folders that serve files or Git
      "https://docs.test/o/r/releases",
      "https://docs.test/o/r/releases/v1",
      "https://docs.test/media",
      "https://docs.test/a/info/x",
      "https://docs.test/o/r.git/info/refs?service=git-upload-pack",
    ]) {
      const [clean, query = ""] = url.split("?");
      expect(explain(clean!, path, rules, query), url).toBeUndefined();
    }
    for (const url of [
      "https://docs.test/docs/page",
      "https://docs.test/docs/page/",
      "https://docs.test/ref/page.html",
      "https://docs.test/ref/page.HTM",
      "https://docs.test/schemas/sitemap/0.9",
      "https://docs.test/o/r/releases/tag/v1.2.3",
      "https://docs.test/o/r/pull/12",
      "https://docs.test/o/r/blob/abc/src/x.js",
      "https://docs.test/o/r/tree/main/dist",
    ]) {
      expect(explain(url, path, rules), url).toBe(rules[2]);
    }
    expect(isLoadable("https://docs.test/media/x")).toBe(true);
    expect(isLoadable("https://docs.test/o/r/blob/main/media/a.png")).toBe(false);
  });
  it("lets a host line vouch for http, https and scheme-relative strings only, and for no endpoint (wp5-r4-2)", () => {
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    // A WebSocket string has no page shape, and an extensionless path under api, login, oauth, graphql or socket is a call.
    for (const url of [
      "wss://docs.test/socket",
      "ws://docs.test/x",
      "wss://docs.test/docs/page",
      "WSS://docs.test/docs/page",
      "https://docs.test/api/data",
      "https://docs.test/login/oauth/access_token",
      "https://docs.test/oauth/token",
      "https://docs.test/graphql",
      "https://docs.test/socket",
      "https://docs.test/api",
    ]) {
      expect(explain(url, path, rules), url).toBeUndefined();
    }
    // What it still vouches for: a documentation page, a `.html` page under /api/, a viewer page of an organisation
    // that happens to be called "graphql", and a scheme-relative link.
    for (const url of [
      "https://docs.test/docs/api/reference",
      "http://docs.test/api/fs.html",
      "https://docs.test/graphql/dataloader/blob/abc/src/index.js",
      "//docs.test/docs/page",
    ]) {
      expect(explain(url, path, rules), url).toBe(rules[2]);
    }
    // An exact url line may still name a socket: the reviewer chose that string.
    const exact = allow("url wss://docs.test/socket # a reviewed socket");
    expect(explain("wss://docs.test/socket", path, exact)).toBe(exact[0]);
  });
  it("refuses a host line for a link whose query asks for the file itself, and keeps a plain viewer page", () => {
    const path = ".next/standalone/apps/panel/node_modules/pkg/a.js";
    const viewer = "https://docs.test/o/r/blob/main/dist/loader.js";
    expect(explain(viewer, path, rules)).toBe(rules[2]);
    for (const query of ["raw=true", "raw=1", "a=1&raw=true", "download", "download=1", "a=1&download=1", "RAW=true"]) {
      expect(explain(viewer, path, rules, query), query).toBeUndefined();
      expect(explain("https://docs.test/o/r/blob/main/README", path, rules, query), query).toBeUndefined();
    }
    for (const query of ["plain=1", "draw=1", "rawish=1", "x=raw"]) expect(explain(viewer, path, rules, query), query).toBe(rules[2]);
    expect(isLoadable("https://docs.test/o/r/blob/main/a.js", "raw=true")).toBe(true);
  });
});

describe("scanApp", () => {
  let dir: string;
  const put = (path: string, content: string | Buffer) => {
    mkdirSync(dirname(join(dir, path)), {recursive: true});
    writeFileSync(join(dir, path), content);
  };
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ctrlz-bundle-"));
    put(".next/static/chunks/app.js", 'var ns="http://www.w3.org/2000/svg";');
    put(".next/standalone/node_modules/next/dist/server.js", "// https://nextjs.org/docs/x\n");
  });
  afterEach(() => rmSync(dir, {recursive: true, force: true}));

  const rules = () =>
    allow("url http://www.w3.org/2000/svg # svg namespace\nhost nextjs.org # docs\n");

  it("passes when every string is explained", () => {
    const r = rules();
    const result = scanApp(dir, r);
    expect(result.unexplained.size).toBe(0);
    expect(result.files).toBe(2);
    expect(staleLines(r)).toEqual({fail: [], warn: []});
  });

  it("fails on a new string in the browser bundle, in the server tree and in public", () => {
    put(".next/static/chunks/new.js", 'fetch("https://cdn.example/lib.js")');
    put(".next/standalone/apps/panel/.next/server/page.js", 'x="https://analytics.example/collect?id=1"');
    put("public/logos/a.svg", '<image href="https://img.example/a.png"/>');
    const {unexplained} = scanApp(dir, rules());
    expect([...unexplained.keys()].sort()).toEqual(["https://analytics.example/collect", "https://cdn.example/lib.js", "https://img.example/a.png"]);
    expect(unexplained.get("https://cdn.example/lib.js")?.path).toBe(".next/static/chunks/new.js");
  });

  it("reports a host line that matched nothing, and fails an unscoped url line that matched nothing", () => {
    const r = allow("url http://www.w3.org/2000/svg # ns\nurl https://gone.test # was in the bundle\nurl https://also.test in node_modules/ # scoped\nhost nextjs.org docs.test # docs\n");
    scanApp(dir, r);
    const stale = staleLines(r);
    expect(stale.fail).toEqual(["line 2: url https://gone.test"]);
    expect(stale.warn).toEqual(["line 3: url https://also.test", "line 4: host docs.test"]);
  });

  it("does not scan binary files, nor the metadata of a package in node_modules", () => {
    put(".next/static/media/font.woff2", "https://binary.example/x");
    put(".next/standalone/node_modules/pkg/package.json", '{"homepage":"https://pkg.example"}');
    put(".next/standalone/node_modules/pkg/README.md", "https://pkg.example/readme");
    put(".next/standalone/node_modules/pkg/index.d.ts", "// https://pkg.example/types");
    expect(scanApp(dir, rules()).unexplained.size).toBe(0);
  });

  // wp5-r4-6, wp5-r5-5: a NUL is legal in code, and Node loads a file with no extension as JavaScript.
  it("scans every file that is not binary by name, whatever bytes it holds, and counts the ones it skips by name", () => {
    const nul = String.fromCharCode(0);
    const names = ["a.js", "a.mjs", "a.cjs", "a.json", "a.html", "a.css", "a.rsc", "a.map", "a.txt", "a.body", "run", "a.so", "other.dat", "a.mts", "a.cts"];
    for (const name of names) put(`.next/static/chunks/${name}`, `/*${nul}*/
fetch("https://cdn.evil.example/${name}");`);
    put(".next/standalone/node_modules/pkg/data.bin", Buffer.from([0, 1, 2, ...Buffer.from("https://nul.example/bin")]));
    // skipped by name, and counted
    put(".next/standalone/node_modules/pkg/a.png", Buffer.from([0, 1, 2, ...Buffer.from('"https://png.example/p"')]));
    // a native addon and a WebAssembly module run, so they are scanned like any other file that holds a NUL (wp5-r7-5)
    put(".next/standalone/node_modules/pkg/a.wasm", Buffer.from([0, 1, 2, ...Buffer.from('"https://wasm.example/w"')]));
    put(".next/standalone/node_modules/pkg/a.node", Buffer.from([0, 1, 2, ...Buffer.from('"https://node.example/n"')]));
    const result = scanApp(dir, rules());
    expect([...result.unexplained.keys()].sort()).toEqual(
      [...names.map((n) => `https://cdn.evil.example/${n}`), "https://nul.example/bin", "https://wasm.example/w", "https://node.example/n"].sort(),
    );
    expect(result.skipped).toBe(1);
  });

  it("skips the files that a licence or a credits text has, by name, and scans code that only starts like one", () => {
    for (const name of ["LICENSE", "LICENSE-MIT", "LICENSE.txt", "license.md", "NOTICE", "NOTICE.txt", "COPYING", "AUTHORS", "CONTRIBUTORS.md", "LICENCE_APACHE"]) {
      put(`.next/standalone/node_modules/pkg/${name}`, "https://legal.example/x");
    }
    expect(scanApp(dir, rules()).unexplained.size).toBe(0);
    for (const name of ["notice.js", "notice-client.js", "licenseCheck.js", "license.mjs", "authors.js", "copying.cjs", "contributors.json", "LICENSE.html"]) {
      put(`.next/standalone/node_modules/pkg/${name}`, `fetch("https://${name.replace(/[^a-z]/gi, "")}.example/x")`);
    }
    expect(scanApp(dir, rules()).unexplained.size).toBe(8);
  });

  it("does scan code in node_modules, and a package.json outside node_modules", () => {
    put(".next/standalone/node_modules/pkg/index.js", 'fetch("https://vendor.example/x")');
    put(".next/standalone/apps/panel/package.json", '{"homepage":"https://app.example"}');
    expect([...scanApp(dir, rules()).unexplained.keys()].sort()).toEqual(["https://app.example", "https://vendor.example/x"]);
  });

  it("says so when the app was not built", () => {
    rmSync(join(dir, ".next"), {recursive: true});
    expect(() => scanApp(dir, rules())).toThrow(/next build/);
  });

  // wp5-r13-2: a folder the scan cannot read is a folder it never scanned. Making one unreadable is not the same on
  // every system (chmod does nothing for a Windows account), so the real fs is wrapped and one folder fails.
  const failing = (match: string, code: string, where: "readdirSync" | "statSync") => ({
    readdirSync: (d: string, o: {withFileTypes: true}) => {
      if (where === "readdirSync" && d.split("\\").join("/").endsWith(match)) throw Object.assign(new Error(`${code}: denied, scandir '${d}'`), {code});
      return readdirSync(d, o);
    },
    statSync: (p: string) => {
      if (where === "statSync" && p.split("\\").join("/").endsWith(match)) throw Object.assign(new Error(`${code}: denied, stat '${p}'`), {code});
      return statSync(p);
    },
    realpathSync,
  });

  it("stops and names the folder when a folder below the scan root cannot be listed, instead of skipping it", () => {
    put(".next/standalone/node_modules/.pnpm/pkg/dist/a.js", 'x="https://cdn.evil.test/a.js";');
    for (const code of ["EACCES", "EPERM", "EIO"]) {
      expect(() => scanApp(dir, rules(), failing("node_modules/.pnpm/pkg/dist", code, "readdirSync")), code).toThrow(
        new RegExp(`cannot list .*pkg.dist.*${code}`),
      );
    }
    // The same tree, readable, reports the string: the failure above is not a missing file.
    expect([...scanApp(dir, rules()).unexplained.keys()]).toEqual(["https://cdn.evil.test/a.js"]);
  });
  it("stops and names the entry when it cannot be inspected for a reason other than not being there", () => {
    put(".next/standalone/node_modules/pkg/a.js", "x=1");
    for (const code of ["EACCES", "EPERM", "ELOOP"]) {
      expect(() => scanApp(dir, rules(), failing("node_modules/pkg/a.js", code, "statSync")), code).toThrow(/cannot inspect .*a.js/);
    }
  });
  it("leaves out a link whose target is gone, and counts it", () => {
    put(".next/standalone/node_modules/pkg/a.js", "x=1");
    const result = scanApp(dir, rules(), failing("node_modules/pkg/a.js", "ENOENT", "statSync"));
    expect(result.dangling).toBe(1);
    expect(scanApp(dir, rules()).dangling).toBe(0);
  });
});

describe("the allow file of this repository", () => {
  const file = join(dirname(fileURLToPath(import.meta.url)), "..", "bundle-url-allow.txt");
  const text = readFileSync(file, "utf8");

  it("parses, and every line has a reason", () => {
    expect(parseAllow(text).problems).toEqual([]);
  });
  it("names no host in the browser bundle's part: only exact strings", () => {
    const [browserPart = ""] = text.split("# --- The server tree");
    expect(browserPart).not.toMatch(/^host /m);
  });
  it("allows no host that could be a real destination", () => {
    const hosts = parseAllow(text).rules.filter((r) => r.kind === "host").flatMap((r) => r.values);
    const refused = [
      // CDNs, fonts, telemetry and package registries
      "cdn.jsdelivr.net", "fonts.googleapis.com", "fonts.gstatic.com", "unpkg.com", "cdnjs.cloudflare.com", "telemetry.nextjs.org",
      "registry.npmjs.org", "raw.githubusercontent.com", "www.googletagmanager.com",
      // hosts that serve something a page can embed or a program can fetch: favicons, video, social cards, issue boards, sample content
      "www.google.com", "www.youtube.com", "developers.google.com", "developers.facebook.com", "developer.twitter.com", "developer.x.com",
      "linear.app", "vercel.com", "example.com", "www.example.com",
    ];
    for (const bad of refused) expect(hosts, bad).not.toContain(bad);
  });
  it("holds no host line that counts a code host for what a program downloads", () => {
    // github.com stays a documentation host in node_modules (about 120 comment links to source), and the rule
    // that a host line never vouches for a file that is loaded is what keeps it from covering a download.
    const rules = parseAllow(text).rules;
    for (const url of ["https://github.com/o/r/releases/download/v1/x", "https://github.com/o/r/archive/main", "https://github.com/o/r/raw", "https://gist.github.com/u/abc.js", "https://github.com/u.png"]) {
      expect(explain(url, ".next/standalone/node_modules/pkg/a.js", rules), url).toBeUndefined();
    }
    for (const url of [
      "https://github.com/o/r/releases/latest/download/tool",
      "https://github.com/o/r/zipball/main",
      "https://github.com/o/r/tarball/main",
      "https://github.com/o/r.git",
      "https://github.com/o/r/blob/main/a.js/../../../raw/x.js",
      "https://github.com:pw@evil.example/a",
    ]) {
      expect(explain(url, ".next/standalone/node_modules/pkg/a.js", rules), url).toBeUndefined();
    }
    expect(explain("https://github.com/o/r/blob/main/dist/loader.js", ".next/standalone/node_modules/pkg/a.js", rules, "raw=true")).toBeUndefined();
    expect(explain("https://github.com/o/r/blob/abc/src/x.js", ".next/standalone/node_modules/pkg/a.js", rules)).toBeDefined();
  });
  it("explains no string whose authority a browser reads to another host, whatever cut character the extractor knows (wp5-r4-5)", () => {
    // A browser ends the authority only at / ? # or a backslash, so in each of these the real host is evil.example,
    // or a label of attacker.io. The extractor used to end the string at the cut character and the host line or the
    // exact url line before it explained the rest.
    const rules = parseAllow(text).rules;
    const strings = [
      "https://github.com,x@evil.example/p.js",
      "https://github.com;x@evil.example/payload",
      "https://github.com)x@evil.example/p",
      "https://github.com]@evil.example/p",
      "https://nextjs.org|x@evil.example/payload",
      "https://react.dev^@evil.example/p",
      "https://x;@evil.example/a.js",
      "http://localhost,@evil.example/a",
      "http://n|@evil.example/a",
      "https://github.com}x@evil.example/p",
      "http://${origin}@evil.example/p",
    ];
    const paths = [
      ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js", // a host line counts here
      ".next/static/chunks/a.js", // only exact lines count here
      ".next/standalone/apps/panel/.next/server/chunks/ssr/a.js",
    ];
    for (const url of strings) {
      for (const path of paths) {
        for (const entry of extractUrlEntries(`s = "${url}"`)) {
          expect(explain(entry.url, path, rules, entry.query), `${url} in ${path} read as ${entry.url}`).toBeUndefined();
          expect(entry.partial, url).toBe(true);
          expect(hostOf(entry.url), url).toBe("evil.example");
        }
      }
    }
    // Without a userinfo the cut character may still make the host another one: label by label it is attacker.io's.
    for (const entry of extractUrlEntries('s = "https://github.com;x.attacker.io/p"')) {
      expect(explain(entry.url, paths[0]!, rules, entry.query), entry.url).toBeUndefined();
      expect(hostOf(entry.url)).toBe("github.com;x.attacker.io");
    }
    // What stays as it was: punctuation after the authority, a placeholder, and a regular expression.
    for (const [text, url] of [
      ["see (https://nextjs.org) and", "https://nextjs.org"],
      ["see https://nextjs.org, then", "https://nextjs.org"],
      ["`https://${host}/x`", "https://${host"],
      ["`http://n${base}/x`", "http://n${base"],
      ["`http://localhost:${port}/x`", "http://localhost:${port"],
      ["`https://${host}${path}`", "https://${host"], // a second placeholder holds no literal host text
      ["`https://${a}:${port}/x`", "https://${a"],
      [String.raw`/^(\/|https:\/\/|http:\/\/)/`, "https://"],
    ] as const) {
      const entries = extractUrlEntries(text);
      expect(entries.map((e) => e.url), text).toContain(url);
      expect(entries.some((e) => e.partial), text).toBe(false);
    }
  });
  // wp5-r5-1 and wp5-r5-2 (one class), wp5-r5-3: the strings are checked as the runtime reads them, not as the source spells them.
  const nodeModules = ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js"; // a host line counts here
  const staticChunk = ".next/static/chunks/a.js"; // only exact lines count here
  const BS = String.fromCharCode(92);
  /** Every entry the extractor finds in `source`, which must explain nothing on either path and have this host. */
  const expectUnexplained = (source: string, host: string, rules: ReturnType<typeof parseAllow>["rules"]) => {
    const entries = extractUrlEntries(source);
    expect(entries.length, source).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(hostOf(entry.url), source).toBe(host);
      for (const path of [nodeModules, staticChunk]) expect(explain(entry.url, path, rules, entry.query), `${source} in ${path}`).toBeUndefined();
    }
  };
  it("reads a JS escape in a URL as the character it makes, so no host line explains another host (wp5-r5-1, wp5-r5-2)", () => {
    const rules = parseAllow(text).rules;
    const cases: [string, string][] = [
      ['fetch("https://github.com@evil.example/x")', "evil.example"],
      [`fetch("https://github.com${BS}x40evil.example/x")`, "evil.example"],
      [`fetch("https://github.com${BS}u0040evil.example/x")`, "evil.example"],
      [`fetch("https://github.com${BS}u{40}evil.example/x")`, "evil.example"],
      [`fetch("https://github.com${BS}x2eevil.example/p")`, "github.com.evil.example"],
      [`fetch("https://nextjs.org${BS}x2eevil.example/a.js")`, "nextjs.org.evil.example"],
      [`fetch("https://x${BS}x40evil.example/a.js")`, "evil.example"],
      // the engine, or the URL parser, drops a tab, a line feed and a carriage return, as an escape or as itself
      [`fetch("https://github.com${BS}t.evil.example/p")`, "github.com.evil.example"],
      [`fetch("https://github.com${BS}n.evil.example/p")`, "github.com.evil.example"],
      [`fetch("https://github.com${BS}r.evil.example/p")`, "github.com.evil.example"],
      ['fetch("https://github.com\t.evil.example/p")', "github.com.evil.example"],
      ['fetch("https://github.com\n.evil.example/p")', "github.com.evil.example"],
      // the scheme and the slashes in escapes, and a break inside the scheme
      [`fetch("https:${BS}x2f${BS}x2fevil.example/p")`, "evil.example"],
      [`fetch("https${BS}x3a//evil.example/p")`, "evil.example"],
      [`fetch("${BS}u0068ttps://evil.example/p")`, "evil.example"],
      [`fetch("ht${BS}ttps://evil.example/p")`, "evil.example"],
      // after a break the URL starts, and "a\nhttps" is not the word "nhttps"
      [`fetch("a${BS}nhttps://evil.example/p")`, "evil.example"],
      [`fetch("a${BS}n//evil.example/p")`, "evil.example"],
      [`fetch("a${BS}thttp:evil.example/p")`, "evil.example"],
    ];
    for (const [source, host] of cases) expectUnexplained(source, host, rules);
  });
  it("keeps a plain line break after a complete URL, and an escaped backslash, as they were (wp5-r5-1)", () => {
    const rules = parseAllow(text).rules;
    for (const source of [`"see https://nextjs.org/docs${BS}n"`, `"https://nextjs.org/docs${BS}n"`, `"https://nextjs.org/docs${BS}t"`, '"https://nextjs.org/docs\n"', '"https://nextjs.org/docs\n// next line"']) {
      const entries = extractUrlEntries(source);
      expect(entries.map((e) => hostOf(e.url)), source).toEqual(["nextjs.org"]);
      expect(explain(entries[0]!.url, nodeModules, rules, entries[0]!.query), source).toBeDefined();
    }
    // `\\r` is an escaped backslash and a letter: a Windows path in a comment, no break and no URL
    expect(extractUrls(String.raw`'\\path\\route.js'`)).toEqual([]);
  });
  it("explains no string whose host is spelled with a cut character, a port or a punycode label (wp5-r5-3)", () => {
    const rules = parseAllow(text).rules;
    for (const [source, host] of [
      ['fetch("https://github.com;x.attacker.io:443/p")', "github.com;x.attacker.io"],
      ['fetch("https://github.com)x.attacker.io:8443/p")', "github.com)x.attacker.io"],
      ['fetch("https://github.com;x.attacker.xn--p1ai/p")', "github.com;x.attacker.xn--p1ai"],
      ['fetch("https://nextjs.org|x.attacker.io:8080/p")', "nextjs.org|x.attacker.io"],
    ] as const) {
      expectUnexplained(source, host, rules);
      expect(extractUrlEntries(source).every((e) => e.partial), source).toBe(true);
    }
  });
  // wp5-r6-1, wp5-r6-2: the rest of JS string unescaping. Each source below is a JS string literal; `vm` says what its
  // runtime string is and `new URL` which host that string reaches, so the test does not rely on a reading of the
  // escapes that is the extractor's own.
  const LF = String.fromCharCode(10);
  const CR = String.fromCharCode(13);
  const TAB = String.fromCharCode(9);
  const LINE_SEPARATOR = String.fromCharCode(0x2028);
  const FEFF = String.fromCharCode(0xfeff);
  const serverChunk = ".next/standalone/apps/panel/.next/server/chunks/ssr/a.js";
  const runtimeHost = (literalBody: string) => new URL(vm.runInNewContext(`"${literalBody}"`) as string).hostname;
  const escapedHosts: string[] = [
    `htt${BS}ps://cdn.evil.example/x.js`, // an escape in the scheme: no match at all before
    `https://github.com${BS}.evil.example/x`,
    `https://github.com${BS}@evil.example/x`,
    `https://github.com${BS}${LF}.evil.example/x`, // a line continuation
    `https://github.com${BS}${CR}${LF}@evil.example/x`,
    `https://github.com${BS}${LINE_SEPARATOR}.evil.example/x`,
    `https://nextjs.org${BS}-x.evil.example/x`,
    `https://x${BS}@evil.example/a.js`,
    `https://a${BS}.evil.example/a.js`,
    `https://x${BS}100evil.example/a.js`, // legacy octal
    `https://x${BS}u{0000040}evil.example/a.js`, // leading zeros in a long escape
    `https://x${FEFF}.evil.example/a.js`, // dropped by the host mapping of a browser, matched by \s in JS
    `https://a${BS}:443${BS}@evil.example/a.js`,
    `https://github.com${BS}100evil.example/x`,
    `https://github.com${FEFF}.evil.example/x`,
    `https://github.com${BS}uFEFF.evil.example/x`,
    `https://nextjs.org${BS}u{0000040}evil.example/a`,
  ];
  it("explains no string that a JS escape, a line continuation or an ignored character sends to another host (wp5-r6-1, wp5-r6-2)", () => {
    const rules = parseAllow(text).rules;
    for (const body of escapedHosts) {
      const host = runtimeHost(body);
      const entries = extractUrlEntries(`fetch("${body}")`);
      expect(entries.some((e) => hostOf(e.url) === host), `${JSON.stringify(body)} should be read as ${host}`).toBe(true);
      for (const path of [nodeModules, staticChunk, serverChunk]) {
        for (const e of entries) {
          // The CSS and HTML readings (wp5-r9-2) add strings of their own (an octal escape of JS is a CSS hex escape): they name no allowed
          // host, so nothing explains them, which the next line checks for every entry.
          expect(explain(e.url, path, rules, e.query, e.partial, e.alt), `${JSON.stringify(body)} as ${e.url} in ${path}`).toBeUndefined();
        }
      }
    }
  });
  it("refuses a host line for a string that was cut at a backslash, and never explains a partial string (wp5-r6-2)", () => {
    const rules = parseAllow(text).rules;
    // Without the flag a line explains the same prefix: the refusal is the flag, not the host.
    expect(explain("https://github.com/o/r", nodeModules, rules)).toBeDefined();
    expect(explain("https://x", staticChunk, rules)).toBeDefined();
    for (const source of [
      `"https://github.com${BS}bevil.example/x"`,
      `"https://github.com${BS}fevil.example/x"`,
      `"https://github.com${BS}x4gvil.example/x"`, // a malformed \x
      `"https://github.com${String.fromCharCode(0xa0)}evil.example/x"`, // a non-ASCII space
    ]) {
      const entry = extractUrlEntries(source).find((e) => e.url === "https://github.com");
      expect(entry, source).toBeDefined();
      expect(entry!.partial, source).toBe(true);
      expect(explain(entry!.url, nodeModules, rules, entry!.query, entry!.partial, entry!.alt), source).toBeUndefined();
    }
    expect(explain("https://x", staticChunk, rules, "", true)).toBeUndefined();
    expect(explain("https://github.com", nodeModules, rules, "", true)).toBeUndefined();
  });
  it("reads a break in the path as a browser's URL parser does, so a host line does not vouch for a download split by one (wp5-r6-2)", () => {
    const rules = parseAllow(text).rules;
    for (const body of [
      `https://github.com/o/r/re${BS}nleases/download/v1/tool`,
      `https://github.com/o/r/re${TAB}leases/download/v1/tool`,
      `https://github.com/o/r/releases/dow${BS}tnload/v1/tool`,
      `https://github.com/o/r/re${BS}rleases/download/v1/tool`,
    ]) {
      const entries = extractUrlEntries(`fetch("${body}")`);
      expect(entries.map((e) => hostOf(e.url)), body).toEqual(["github.com"]);
      expect(runtimeHost(body), body).toBe("github.com");
      for (const e of entries) expect(explain(e.url, nodeModules, rules, e.query, e.partial, e.alt), `${body} as ${e.url}`).toBeUndefined();
    }
  });
  it("keeps explaining a complete URL that a line break or a placeholder follows, and a comment line after one (wp5-r6-1, wp5-r6-2)", () => {
    const rules = parseAllow(text).rules;
    for (const source of [
      `"https://github.com/o/r${BS}n"`, // the negative of wp5-r6-1: a break after a complete URL
      `"https://github.com/o/r${BS}n${BS}n"`,
      `"https://nextjs.org/docs/messages/x${BS}n$${"{"}list.join(",")}"`,
      "// https://nextjs.org/docs/messages/x\n// config.js and the rest\n",
    ]) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      for (const e of entries) {
        expect(explain(e.url, nodeModules, rules, e.query, e.partial, e.alt), `${source} as ${e.url}`).toBeDefined();
      }
    }
  });
  // wp5-r7-1 .. wp5-r7-4: where the extractor cuts a string, and what the runtime or a browser makes of the rest. Every
  // source below is spelled with BS (a backslash that no escaping rule can change), `reach` evaluates a JS literal with
  // `vm` and asks `new URL` for the URL it makes, and `expectNoLine` checks that no rule explains any entry of the source.
  const VT = String.fromCharCode(11);
  const FF = String.fromCharCode(12);
  const reach = (literal: string) => new URL(vm.runInNewContext(literal) as string, "https://base.test/");
  const expectNoLine = (source: string, paths: string[], rules: ReturnType<typeof parseAllow>["rules"]) => {
    const entries = extractUrlEntries(source);
    expect(entries.length, source).toBeGreaterThan(0);
    for (const e of entries) {
      for (const path of paths) expect(explain(e.url, path, rules, e.query, e.partial, e.alt, e.cut), `${source} as ${e.url} in ${path}`).toBeUndefined();
    }
  };
  const allPaths = [nodeModules, staticChunk, serverChunk];
  it("explains no string whose host continues after an escaped quote, a quote that the extractor cannot tell from a closing one (wp5-r7-1)", () => {
    const rules = parseAllow(text).rules;
    const literals = [
      `'https://github.com${BS}'.evil.example/x'`,
      `"https://github.com${BS}".evil.example/x"`,
      `\`https://github.com${BS}\`.evil.example/x\``,
      `'https://x${BS}'.evil.example/a.js'`,
      `'//github.com${BS}'.evil.example/p'`,
      `'https://github.com${BS}'@evil.example/x'`,
      `'https://github.com${BS}'.evil.example:443/x'`,
    ];
    for (const literal of literals) {
      const host = reach(literal).hostname;
      expect(host, literal).toMatch(/evil\.example/);
      expectNoLine(`x = ${literal}`, allPaths, rules);
      expect(extractUrlEntries(`x = ${literal}`).some((e) => e.partial), literal).toBe(true);
    }
  });
  it("keeps explaining a URL that an unescaped quote ends, and one that ends an embedded JSON string (wp5-r7-1)", () => {
    const rules = parseAllow(text).rules;
    for (const source of [
      `x = 'https://github.com/o/r'`,
      `x = "https://github.com/o/r"`,
      "x = `https://github.com/o/r`",
      `x = 'https://github.com/o/r' + '.evil.example'`,
      `{${BS}"u${BS}":${BS}"https://nextjs.org/docs${BS}",${BS}"s${BS}":${BS}"/a.zip${BS}"}`,
      `"https://nextjs.org/docs${BS}")`,
    ]) {
      const entries = extractUrlEntries(source).filter((x) => hostOf(x.url) === "github.com" || hostOf(x.url) === "nextjs.org");
      expect(entries.length, source).toBeGreaterThan(0);
      for (const e of entries) {
        expect(e.partial, source).toBe(false);
        expect(explain(e.url, nodeModules, rules, e.query, e.partial, e.alt, e.cut), `${source} as ${e.url}`).toBeDefined();
      }
    }
  });
  it("does not let a host line vouch for the part of a path before an escaped quote or a backslash (wp5-r7-2, wp5-r7-4)", () => {
    const rules = parseAllow(text).rules;
    // JS literals: the runtime path is what a download needs. A pair of backslashes is one at run time, a slash for the URL parser.
    const climb = `..${BS}${BS}`;
    const literals: [string, RegExp][] = [
      [`'https://github.com/o/r${BS}'/releases/download/v1/tool'`, /releases\/download/],
      [`"https://nextjs.org/docs${BS}"/a.zip"`, /a\.zip$/],
      [`"https://github.com/o/r/blob/main/x/${climb.repeat(5)}o/r/releases/download/v1/tool"`, /^\/o\/r\/releases\/download\/v1\/tool$/],
      [`"https://github.com/o/r/tree/x${BS}${BS}${climb.repeat(4)}o/r/raw/main/a.js"`, /^\/o\/r\/raw\/main\/a\.js$/],
      [`"https://nextjs.org/docs${BS}${BS}${climb}dl${BS}${BS}tool.tar.xz"`, /^\/dl\/tool\.tar\.xz$/],
      [`"https://nextjs.org/docs${BS}${BS}x.js"`, /^\/docs\/x\.js$/],
    ];
    for (const [literal, runtimePath] of literals) {
      expect(reach(literal).pathname, literal).toMatch(runtimePath);
      expectNoLine(`x = ${literal}`, [nodeModules], rules);
    }
    // Text that is no JS source (HTML, decoded JSON, an RSC payload): a literal backslash is a slash for a browser.
    const texts: [string, RegExp][] = [
      [`href="https://github.com/o/r${BS}media${BS}main${BS}x"`, /^\/o\/r\/media\/main\/x$/],
      [`href="https://nextjs.org/docs${BS}x.zip"`, /^\/docs\/x\.zip$/],
    ];
    for (const [source, runtimePath] of texts) {
      expect(new URL(/"([^"]*)"/.exec(source)![1]!).pathname, source).toMatch(runtimePath);
      expectNoLine(source, [nodeModules], rules);
    }
  });
  it("keeps explaining a page that a break or an escaped line end follows, so the backslash rule is no noise (wp5-r7-2)", () => {
    const rules = parseAllow(text).rules;
    for (const source of [`"see https://nextjs.org/docs/x${BS}nfoo"`, `"https://github.com/o/r/blob/main/a.js${BS}n"`, "// https://nextjs.org/docs/messages/x\n"]) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      for (const e of entries) expect(explain(e.url, nodeModules, rules, e.query, e.partial, e.alt, e.cut), `${source} as ${e.url}`).toBeDefined();
    }
  });
  it("reads a space, VT or FF before an @ in the authority as userinfo, so the host is what follows the @ (wp5-r7-3)", () => {
    const rules = parseAllow(text).rules;
    const gaps = [" ", VT, FF, `${BS}x20`, `${BS}x0b`, `${BS}x0c`, `${BS}u000b`, `${BS}u000c`, `${BS}t `, ":443 "];
    for (const gap of gaps) {
      for (const [prefix, path] of [["https://github.com", nodeModules], ["https://x", staticChunk], ["https://a", staticChunk]] as const) {
        const literal = `"${prefix}${gap}@evil.example/x"`;
        expect(reach(literal).hostname, literal).toBe("evil.example");
        expectNoLine(`fetch(${literal})`, [path], rules);
        expect(extractUrlEntries(`fetch(${literal})`).some((e) => e.partial), literal).toBe(true);
      }
    }
    // The escapes \v and \f are no exemption either.
    for (const esc of ["v", "f"]) expectNoLine(`"https://github.com${BS}${esc}@evil.example/x"`, [nodeModules], rules);
    // With no @ after the gap the string is as it was, and a space after a complete URL stays harmless.
    for (const source of [`"https://x "`, `"https://x foo"`, `'https://x bar baz'`]) {
      const entries = extractUrlEntries(source);
      expect(entries.map((e) => e.url), source).toEqual(["https://x"]);
      expect(entries[0]!.partial, source).toBe(false);
      expect(explain("https://x", staticChunk, rules), source).toBeDefined();
    }
  });
  // wp5-r8-2 .. wp5-r8-4: where a string ends is a question about the string it sits in. A cut character, a quote of
  // the other kind, `<` or `>` do not end a URL for the URL parser, so the path or the host goes on after them.
  it("does not let a host line vouch for a path that goes on after a cut character, a quote of the other kind, `<` or `>` (wp5-r8-2)", () => {
    const rules = parseAllow(text).rules;
    const BT = "`";
    // each: the character that cuts the string, written in a literal that does not end at it
    const cuts: [string, string][] = [
      [")", '"'], ["]", '"'], ["}", '"'], ["|", '"'], [",", '"'], [";", '"'], ["^", '"'], ["'", '"'], ["<", '"'], [">", '"'], [BT, '"'], ['"', "'"],
      // white space ends nothing either: the URL parser percent-encodes it and the path goes on
      [" ", '"'], [String.fromCharCode(0xa0), '"'], [String.fromCharCode(0xfeff), '"'], [String.fromCharCode(0x2028), '"'],
    ];
    const tails: [string, RegExp][] = [
      ["https://github.com/o/r", /^\/o\/r\/releases\/download\/v1\/tool$/],
      ["https://github.com/o/r/blob/x", /^\/o\/r\/releases\/download\/v1\/tool$/],
      ["https://github.com/o/r/tree/x", /^\/o\/r\/raw\/main\/a\.js$/],
      ["https://nextjs.org/docs", /^\/dl\/tool\.tar\.xz$/],
    ];
    const climbs = ["/../../o/r/releases/download/v1/tool", "/../../../../../o/r/releases/download/v1/tool", "/../../../../o/r/raw/main/a.js", "/../dl/tool.tar.xz"];
    cuts.forEach(([cut, quote]) => {
      tails.forEach(([prefix, runtime], j) => {
        const literal = `${quote}${prefix}${cut}${climbs[j]}${quote}`;
        expect(reach(literal).pathname, literal).toMatch(runtime);
        expectNoLine(`fetch(${literal})`, [nodeModules], rules);
      });
    });
    // a string that starts after a line break right after its quote is the start of its string
    const lead = `"${BS}nhttps://github.com/o/r'/../../o/r/releases/download/v1/tool"`;
    expect(reach(lead).pathname).toBe("/o/r/releases/download/v1/tool");
    expectNoLine(`fetch(${lead})`, [nodeModules], rules);
  });
  it("keeps explaining a link that a sentence, a bracket or the end of its own string ends (wp5-r8-2)", () => {
    const rules = parseAllow(text).rules;
    for (const source of [
      "// see (https://nextjs.org/docs/messages/x).",
      "// [a](https://nextjs.org/docs/a), [b](https://nextjs.org/docs/b)",
      '"https://github.com/o/r/blob/x/a.js"',
      "`https://github.com/o/r`",
      "'Read more: https://nextjs.org/docs/messages/foo`);this.x=\"e\"}resolve(e){return t}'",
      '"https://nextjs.org/docs/a.html"',
      '"https://nextjs.org/docs/messages/foo is deprecated, read https://nextjs.org/docs/a"',
    ]) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      for (const e of entries) {
        expect(e.partial, source).toBe(false);
        expect(explain(e.url, nodeModules, rules, e.query, e.partial, e.alt, e.cut), `${source} as ${e.url}`).toBeDefined();
      }
    }
  });
  it("explains no string whose host continues after a quote of the other kind or a backtick (wp5-r8-3)", () => {
    const rules = parseAllow(text).rules;
    const literals = [
      `"https://github.com'.evil.example/x"`,
      `'https://github.com".evil.example/x'`,
      `"https://github.com${"`"}.evil.example/x"`,
      `${"`"}https://github.com'.evil.example/x${"`"}`,
      `${"`"}https://github.com".evil.example/x${"`"}`,
      `"https://nextjs.org'.evil.example/a.js"`,
      `"//github.com'.evil.example/x"`,
      `"https://github.com'@evil.example/x"`,
      `"https://github.com'.evil.example:443/x"`,
    ];
    for (const literal of literals) {
      expect(reach(literal).hostname, literal).toMatch(/evil\.example/);
      expectNoLine(`fetch(${literal})`, [nodeModules], rules);
    }
    // the browser bundle: the unscoped `url https://x` line must not explain it either
    for (const literal of [`"https://x'.evil.example/a.js"`, `'https://x".evil.example/a.js'`, `"https://a${"`"}.evil.example/a.js"`]) {
      expect(reach(literal).hostname, literal).toMatch(/evil\.example/);
      expectNoLine(`fetch(${literal})`, [staticChunk], rules);
    }
    // what stays as it was: the quote that closes the string ends the URL
    for (const source of [`"https://x")+y`, `'https://x'+".evil.example"`, `("https://x",1)`, `"https://x";return t}`]) {
      const entries = extractUrlEntries(source);
      expect(entries.map((e) => e.url), source).toEqual(["https://x"]);
      expect(entries[0]!.partial, source).toBe(false);
      expect(explain("https://x", staticChunk, rules, "", false), source).toBeDefined();
    }
  });
  it("holds for every ASCII mark and four kinds of white space after a host or a path, in three kinds of quote: no explained string reaches another host or a file (wp5-r8, the class)", () => {
    // The oracle is the runtime URL (`vm` and `new URL`), not the extractor's reading. A rule explains a string only when
    // the runtime host is the one it names and, for a host line, the runtime path is a page. A host with no dot is
    // no name that an outside resolver answers and is left out.
    const rules = parseAllow(text).rules;
    const pathsAndRules: [string, number][] = [[nodeModules, 0], [staticChunk, 1], [serverChunk, 2]];
    const marks: string[] = [" ", String.fromCharCode(0xa0), String.fromCharCode(0xfeff), String.fromCharCode(0x2028)];
    for (let code = 0x21; code < 0x7f; code++) {
      const mark = String.fromCharCode(code);
      if (!"\\/?#".includes(mark)) marks.push(mark);
    }
    const hosts: [string, number][] = [["github.com", 0], ["nextjs.org", 0], ["x", 1], ["localhost", 2]];
    const prefixes = ["https://github.com/o/r", "https://github.com/o/r/blob/x", "https://nextjs.org/docs"];
    const problems: string[] = [];
    let cases = 0;
    for (const quote of ['"', "'", "`"]) {
      for (const mark of marks) {
        if (mark === quote) continue;
        const bodies: [string, number][] = [];
        for (const [host, at] of hosts) {
          bodies.push([`https://${host}${mark}.evil.example/x`, at], [`https://${host}${mark}@evil.example/x`, at]);
        }
        for (const prefix of prefixes) {
          bodies.push([`${prefix}${mark}/../../o/r/releases/download/v1/tool`, 0], [`${prefix}${mark}/../x.zip`, 0], [`${prefix}${mark}x.zip`, 0]);
        }
        for (const [body, at] of bodies) {
          const literal = `${quote}${body}${quote}`;
          let url: URL;
          try {
            url = new URL(vm.runInNewContext(literal) as string);
          } catch {
            continue;
          }
          if (!url.hostname.includes(".") && url.hostname !== "localhost") continue;
          cases++;
          const [path] = pathsAndRules[at]!;
          for (const e of extractUrlEntries(`fetch(${literal})`)) {
            const rule = explain(e.url, path, rules, e.query, e.partial, e.alt, e.cut);
            if (!rule) continue;
            const named = hostOf(e.url) === url.hostname;
            const page = rule.kind === "url" || !isLoadable(url.origin + url.pathname, url.search.slice(1));
            if (!named || !page) problems.push(`${JSON.stringify(literal)} runs as ${url.href} and ${e.url} is explained`);
          }
        }
      }
    }
    expect(cases).toBeGreaterThan(3000);
    expect(problems.slice(0, 10)).toEqual([]);
  });
  it("explains no string whose host holds literal text after a placeholder, and keeps a port or another placeholder as it was (wp5-r8-4)", () => {
    const rules = parseAllow(text).rules;
    const BT = "`";
    const sources = [
      `${BT}https://\${b}.cdn.evil.example/lib.js${BT}`,
      `${BT}https://\${c}cdn.evil.example/lib.js${BT}`,
      `${BT}https://\${b}-evil.example/x${BT}`,
      `${BT}https://\${origin}.evil.example/x${BT}`,
      `${BT}https://\${req.headers.host}.evil.example/x${BT}`,
      `${BT}http://\${addressString}.evil.example/x${BT}`,
      `${BT}http://n\${t}.evil.example/x${BT}`,
      `${BT}http://localhost:\${a}.evil.example/x${BT}`,
    ];
    for (const source of sources) {
      const entries = extractUrlEntries(`fetch(${source})`);
      expect(entries.length, source).toBeGreaterThan(0);
      expect(entries.every((e) => e.partial), source).toBe(true);
      expectNoLine(`fetch(${source})`, [nodeModules, serverChunk, ".next/standalone/apps/panel/node_modules/next/dist/lib/x.js"], rules);
    }
    for (const source of [`${BT}https://\${b}/x${BT}`, `${BT}https://\${b}:\${p}/x${BT}`, `${BT}https://\${b}:8080/x${BT}`, `${BT}https://\${host}\${path}${BT}`]) {
      expect(extractUrlEntries(source).some((e) => e.partial), source).toBe(false);
    }
  });
  it("scopes the placeholder lines to the files that hold them, so no other code can use them (wp5-r8-4)", () => {
    const rules = parseAllow(text).rules;
    // our own server code (not under node_modules, not a chunk that Turbopack wrote) and the browser bundle
    for (const url of ["https://${b", "https://${c", "https://${origin", "https://${req.headers.host", "http://n${t", "http://localhost:${a"]) {
      expect(explain(url, ".next/standalone/apps/panel/.next/server/app/x.js", rules), url).toBeUndefined();
      expect(explain(url, ".next/static/chunks/a.js", rules), url).toBeUndefined();
    }
    expect(explain("https://${origin", ".next/standalone/node_modules/next/dist/lib/metadata/resolvers/resolve-url.js", rules)).toBeDefined();
  });
  it("explains nothing in the compiled code of the apps by host: those strings are exact lines", () => {
    const rules = parseAllow(text).rules;
    expect(explain("https://nextjs.org/docs/new-page", ".next/standalone/apps/panel/.next/server/chunks/ssr/a.js", rules)).toBeUndefined();
    expect(explain("https://nextjs.org/docs/new-page", ".next/standalone/apps/panel/node_modules/next/dist/a.js", rules)).toBeDefined();
  });
});

describe("round 9 (wp5-r9)", () => {
  const rules = parseAllow(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "bundle-url-allow.txt"), "utf8")).rules;
  const BS = String.fromCharCode(92);
  const BT = "`";
  const nodeModules = ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js"; // a host line counts here
  const nextDist = ".next/standalone/apps/panel/node_modules/next/dist/lib/helpers/install.js";
  const staticChunk = ".next/static/chunks/a.js";
  const serverChunk = ".next/standalone/apps/panel/.next/server/chunks/ssr/a.js";
  const allPaths = [nodeModules, nextDist, staticChunk, serverChunk];
  /** Every entry of the source, explained by no rule on any of the paths (the arguments are what scanApp passes). */
  const explainedBy = (source: string, paths: string[]) => {
    const found: string[] = [];
    for (const e of extractUrlEntries(source)) {
      for (const path of paths) if (explainEntry(e, path, rules)) found.push(`${e.url} in ${path}`);
    }
    return found;
  };

  it("never lets a host line vouch for a URL with a placeholder in its path, a percent escape in a folder name or a placeholder that holds the whole path (wp5-r9-1, wp5-r9-3)", () => {
    const sources = [
      `${BT}https://github.com/\${repo}/releases/download/v1/tool${BT}`,
      `${BT}https://github.com/\${o}/\${r}/archive/\${ref}.zip${BT}`,
      `${BT}https://github.com/\${o}/\${r}.git${BT}`,
      `${BT}https://github.com/o/r/blob/\${ref}/../../../releases/download/v1/tool${BT}`,
      `${BT}https://nextjs.org/docs/\${p}.tar.gz${BT}`,
      `${BT}https://nextjs.org/\${p}/x.zip${BT}`,
      `${BT}https://github.com/o/r/blob/\${b}/../../../../o/r/releases/download/v1/tool${BT}`,
      `${BT}https://nextjs.org/docs/\${b}/../../dl/tool.tar.xz${BT}`,
      `${BT}https://github.com/\${b}${BT}`,
      '"https://github.com/o/r/%72eleases/download/v1/x"',
      '"https://nextjs.org/docs/a%20b"',
    ];
    for (const source of sources) {
      expect(extractUrlEntries(`fetch(${source})`).length, source).toBeGreaterThan(0);
      expect(explainedBy(`fetch(${source})`, [nodeModules, nextDist]), source).toEqual([]);
    }
    // a viewer page keeps being a page, whatever the URL parser made of a space in it, and a plain docs page is one too
    expect(isLoadable("https://github.com/o/r/blob/x%20x.zip")).toBe(false);
    expect(isLoadable("https://nextjs.org/docs/messages/some-page")).toBe(false);
    expect(isLoadable("https://nextjs.org/docs/messages/${x")).toBe(true);
    expect(isLoadable("https://${origin")).toBe(false); // the placeholder is the host, which no host line names
  });
  it("explains the three placeholder strings of Next by an exact line, scoped to Next's own code (wp5-r9-3)", () => {
    for (const url of ["https://nextjs.org/docs/messages/${r", "https://nextjs.org/docs/${hasAppDir", "https://nextjs.org/docs/messages/${docsPathname"]) {
      expect(explain(url, ".next/standalone/apps/panel/node_modules/next/dist/server/render.js", rules), url).toBeDefined();
      expect(explain(url, nodeModules, rules), url).toBeUndefined();
      expect(explain(url, staticChunk, rules), url).toBeUndefined();
    }
  });

  it("explains no exact-line string that a cut character, a backslash pair or an encoded separator sends to a download on the same host (wp5-r9-4)", () => {
    const sources = [
      '"https://github.com/zloirock/core-js)/../../o/r/raw/main/x.js"',
      '"https://react.dev/errors/,/../../dl/x.tar.xz"',
      '"https://registry.npmjs.org/,/../evil-pkg/-/evil-pkg-1.0.0.tgz"',
      '"https://github.com/vercel/next.js)/../../o/r/releases/download/v1/tool"',
      '"https://github.com/vercel/next.js]/../../o/r/releases/download/v1/tool"',
      `"https://github.com/vercel/next.js${BS}${BS}..${BS}${BS}o/r/releases/download/v1/tool"`,
      `"https://github.com/vercel/next.js${BS}${BS}%2e%2e${BS}${BS}o/r/raw/main/a.js"`,
    ];
    for (const source of sources) {
      expect(extractUrlEntries(`fetch(${source})`).length, source).toBeGreaterThan(0);
      expect(explainedBy(`fetch(${source})`, allPaths), source).toEqual([]);
    }
    // the same lines keep explaining the strings they name, and a backslash that only closes an embedded string is no climb
    expect(explainedBy('fetch("https://github.com/vercel/next.js")', [nextDist]).length).toBeGreaterThan(0);
    expect(explainedBy('fetch("https://react.dev/errors/")', allPaths).length).toBe(4);
    expect(explainedBy(`x = "new URL(${BS}"https://example.com${BS}");return t"`, [".next/standalone/apps/panel/node_modules/next/dist/compiled/x.js"]).length).toBeGreaterThan(0);
    // a bare scheme with no host (the source of a regular expression) has nothing to climb to
    expect(explainedBy(`x = /^https:${BS}/${BS}/${BS}*${BS}.verify${BS}.dns/`, [".next/standalone/apps/panel/.next/server/chunks/a.js"]).length).toBeGreaterThan(0);
  });

  it("finds a scheme-relative URL whose host starts with a placeholder, and keeps a path join and a regular-expression builder out (wp5-r9-5)", () => {
    for (const source of [`s.src=${BT}//\${b}.cdn.evil.example/lib.js${BT}`, `s.src=${BT}//\${b}evil.example/lib.js${BT}`, `x = "//\${b}.cdn.evil.example/lib.js"`, `x=(//\${a}.evil.example/x`]) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      expect(entries.every((e) => e.url.startsWith("//${") && e.partial), source).toBe(true);
      expect(explainedBy(source, allPaths), source).toEqual([]);
    }
    expect(extractUrls(`${BT}\${base}//\${path}${BT}`)).toEqual([]);
    expect(extractUrls("a = `${base}//${path}/x.js`; b = c + '//' + d")).toEqual([]);
    // how a regular-expression builder escapes a character: two backslashes in the source are one at run time
    expect(extractUrls(`return ${BT}${BS}${BS}\${e.value}${BT}`)).toEqual([]);
  });

  it("reads a CSS hex escape and an HTML character reference in a URL, so a stylesheet or an SVG cannot pull from a CDN unseen (wp5-r9-2)", () => {
    const sources = [
      `a{background:url(https:${BS}2f${BS}2fcdn.evil.example/x.png)}`,
      `@import url("${BS}68ttps://cdn.evil.example/a.css");`,
      `@import url("${BS}68 ttps://cdn.evil.example/a.css");`,
      `@import url(${BS}000068ttps://cdn.evil.example/a.css);`,
      'x href="&#104;ttps://cdn.evil.example/a.css"',
      'x href="&#x68;ttps://cdn.evil.example/a.css"',
      'x href="https:&#47;&#47;cdn.evil.example/a.css"',
      'x href="https:&sol;&sol;cdn.evil.example/a.css"',
      'x href="https&colon;//cdn.evil.example/a.css"',
      'x href="https://cdn&period;evil.example/a.css"',
      'x href="https://x&commat;cdn.evil.example/a.css"',
    ];
    for (const source of sources) {
      const urls = extractUrls(source);
      expect(urls.some((u) => hostOf(u) === "cdn.evil.example"), `${source} -> ${urls.join(" ")}`).toBe(true);
      expect(explainedBy(source, allPaths), source).toEqual([]);
    }
    // what the other readings must not invent: a JS message's escaped newline is no letter n, and a doubled backslash
    // is no hex escape
    expect(extractUrls(`"see https://nextjs.org/docs/messages/a-page${BS}n  " + 'a &amp; b'`)).toEqual(["https://nextjs.org/docs/messages/a-page"]);
    expect(extractUrls(`"https:${BS}${BS}evil.example/a.js"`)).toEqual(["https://evil.example/a.js"]);
  });
});

describe("decode (wp5-r6-3)", () => {
  const url = "https://cdn.evil.example/x.js";
  const NUL = String.fromCharCode(0);
  const le = (s: string) => Buffer.from(s, "utf16le");
  const be = (s: string) => Buffer.from(le(s)).swap16();

  it("reads a UTF-16 file, with or without a byte order mark, as UTF-16", () => {
    const body = `fetch("${url}")`;
    for (const buffer of [
      Buffer.concat([Buffer.from([0xff, 0xfe]), le(body)]),
      Buffer.concat([Buffer.from([0xfe, 0xff]), be(body)]),
      le(body),
      be(body),
    ]) {
      expect(extractUrls(decode(buffer)), buffer.subarray(0, 4).toString("hex")).toContain(url);
    }
  });
  it("scans a file with a NUL as UTF-8 and as latin1 without the NULs, so a Unicode host and a split word both show", () => {
    const withNul = Buffer.from(`/*${NUL}*/import("//пример.рф/x.js")`, "utf8");
    expect(extractUrls(decode(withNul)).map((u) => hostOf(u))).toContain("пример.рф");
    const split = Buffer.from(`fetch("https://cdn.${NUL}evil.example/x.js")`, "latin1");
    expect(extractUrls(decode(split)).map((u) => hostOf(u))).toContain("cdn.evil.example");
  });
  it("reads a file without a NUL as UTF-8, and a minified file with one NUL is not taken for UTF-16", () => {
    expect(extractUrls(decode(Buffer.from(`fetch("${url}")`)))).toEqual([url]);
    const oneNul = Buffer.from(`/*${NUL}*/${"x".repeat(200)};fetch("${url}")`, "latin1");
    expect(extractUrls(decode(oneNul))).toContain(url);
  });
});

describe("round 10 (wp5-r10)", () => {
  const rules = parseAllow(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "bundle-url-allow.txt"), "utf8")).rules;
  const BS = String.fromCharCode(92);
  const BT = "`";
  const nodeModules = ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js"; // a host line counts here
  const nextDist = ".next/standalone/apps/panel/node_modules/next/dist/lib/helpers/install.js";
  const staticChunk = ".next/static/chunks/a.js";
  const serverChunk = ".next/standalone/apps/panel/.next/server/chunks/ssr/a.js";
  const allPaths = [nodeModules, nextDist, staticChunk, serverChunk];
  /** Every entry of the source that some rule explains on one of the paths: what scanApp would let through. */
  const explainedBy = (source: string, paths: string[]) => {
    const found: string[] = [];
    for (const e of extractUrlEntries(source)) {
      for (const path of paths) if (explainEntry(e, path, rules)) found.push(`${e.url} in ${path}`);
    }
    return found;
  };

  it("finds a scheme-relative URL whose first label has an underscore or whose dots are not ASCII, and reads the host as a browser does (wp5-r10-1)", () => {
    const sources: Array<[string, string]> = [
      ['x="//my_bucket.s3.amazonaws.com/x.js"', "https://my_bucket.s3.amazonaws.com/x.js"],
      ["x='//my_bucket.s3.amazonaws.com/x.js'", "https://my_bucket.s3.amazonaws.com/x.js"],
      ["a{background:url(//my_bucket.s3.amazonaws.com/a.woff2)}", "https://my_bucket.s3.amazonaws.com/a.woff2"],
      ['x="http:my_bucket.s3.amazonaws.com/x.js"', "http://my_bucket.s3.amazonaws.com/x.js"],
      ['x="//cdn。evil。com/x.js"', "https://cdn。evil。com/x.js"],
      ['x="//cdn．evil．com/x.js"', "https://cdn．evil．com/x.js"],
      ['x="//cdn｡evil｡com/x.js"', "https://cdn｡evil｡com/x.js"],
      ['x="http:cdn。evil。com/x.js"', "http://cdn。evil。com/x.js"],
      ['x="//cdn.my_site.example.com/x.js"', "https://cdn.my_site.example.com/x.js"],
      ['x="https://my_bucket.s3.amazonaws.com/x.js"', "https://my_bucket.s3.amazonaws.com/x.js"],
      ['x="https://cdn。evil。com/x.js"', "https://cdn。evil。com/x.js"],
    ];
    for (const [source, browserUrl] of sources) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      // the oracle is the URL parser, so the test does not lean on the extractor's own reading
      expect(entries.map((e) => hostOf(e.url)), source).toContain(new URL(browserUrl).hostname);
      expect(explainedBy(source, allPaths), source).toEqual([]);
    }
    // the report names the host the browser reads, and a bucket name is a host label
    expect(printable("//my_bucket.s3.amazonaws.com/x.js")).toBe("//my_bucket.s3.amazonaws.com  [path of 5 characters hidden]");
    expect(printable("https://cdn。evil。com/x.js")).toBe("https://cdn.evil.com  [path of 5 characters hidden]");
    // none of these is a URL
    for (const source of ["// a_b.example.com", "a//b_c.example.com", "x = 1; // my_note.txt is here", "const r = /^\\/\\/a_b\\.c/"]) {
      expect(extractUrls(source), source).toEqual([]);
    }
  });

  it("never lets a host line vouch for a URL that a program builds with + or .concat(), or with a placeholder in its query (wp5-r10-2)", () => {
    const sources = [
      '"https://github.com/"+repo+"/releases/download/v1/tool"',
      '"https://github.com/".concat(o,"/").concat(r,"/releases/download/").concat(t)',
      '"https://github.com/o/r/blob/"+ref+"/../../../releases/download/v1/tool"',
      '"https://nextjs.org/docs/"+p+".tar.gz"',
      "'https://github.com/' + owner + '/' + repo",
      '"https://github.com/" . concat (repo)',
      `${BT}https://github.com/o/r/blob/main/a.js?\${q}${BT}`,
      `${BT}https://github.com/o/r?\${q}${BT}`,
    ];
    for (const source of sources) {
      expect(extractUrlEntries(`x=${source}`).length, source).toBeGreaterThan(0);
      expect(explainedBy(`x=${source}`, [nodeModules, nextDist]), source).toEqual([]);
    }
    // the exact line of the one built string that the real builds hold still names it, anywhere
    for (const path of allPaths) expect(explainedBy('throw new Error("https://react.dev/errors/"+e)', [path]), path).toHaveLength(1);
    // a link whose string closes, and a sentence, are still pages (a message that ends in a line break before a + is not:
    // see round 11, wp5-r11-5)
    for (const source of [
      '"https://github.com/o/r/blob/main/README"',
      '"read https://nextjs.org/docs/messages/some-page."',
      `x(${BT}https://nextjs.org/docs/messages/some-page${BT}) + y`,
    ]) {
      expect(explainedBy(`x=${source}`, [nodeModules]), source).not.toEqual([]);
    }
  });

  it("does not let an exact line that ends in an open placeholder explain what follows the brace (wp5-r10-3)", () => {
    // line 26 is for any template whose host is the variable b or c, closing right after it, in our own server code
    expect(explainedBy(`x=new URL(${BT}https://\${b}${BT})`, [serverChunk])).not.toEqual([]);
    expect(explainedBy(`x=${BT}https://\${b}/releases/download/v1/tool${BT}`, [serverChunk])).toEqual([]);
    expect(explainedBy(`x=${BT}https://\${c}/x${BT}`, [serverChunk])).toEqual([]);
    expect(explainedBy(`x=${BT}http://localhost:\${a}/dl/tool.tar.xz${BT}`, [serverChunk])).toEqual([]);
    // the docs links of Next close, or go on with a page, and never with a climb or a file
    expect(explainedBy(`x=${BT}https://nextjs.org/docs/messages/\${r}${BT}`, [nextDist])).not.toEqual([]);
    expect(explainedBy(`x=${BT}https://nextjs.org/docs/messages/\${r}#section${BT}`, [nextDist])).not.toEqual([]);
    for (const source of [
      `${BT}https://nextjs.org/docs/messages/\${r}/../../../dl/x.tar.xz${BT}`,
      `${BT}https://nextjs.org/docs/messages/\${r}/../../../releases/download/v1/tool${BT}`,
      `${BT}https://nextjs.org/docs/messages/\${r}.zip${BT}`,
      `${BT}https://nextjs.org/docs/messages/\${r}?download${BT}`,
      `${BT}https://nextjs.org/docs/messages/\${r}\${tail}${BT}`,
    ]) {
      expect(explainedBy(`x=${source}`, [nextDist]), source).toEqual([]);
    }
    // an expression with its own quotes and braces does not hide the remainder
    expect(explainedBy(`x=${BT}https://\${b || 'x'}/releases/download/v1/tool${BT}`, [serverChunk])).toEqual([]);
    expect(explainedBy(`x=${BT}https://\${b || {a: 1}.a}/releases/download/v1/tool${BT}`, [serverChunk])).toEqual([]);
    // a template whose closing brace cannot be found is never explained
    expect(explainedBy(`x=${BT}https://\${b`, [serverChunk])).toEqual([]);
    // a line that names the whole template still does (the mkcert download), and only that template, in its own file
    const mkcert = ".next/standalone/apps/panel/node_modules/next/dist/lib/mkcert.js";
    const template = `${BT}https://github.com/FiloSottile/mkcert/releases/download/\${MKCERT_VERSION}/\${binaryName}${BT}`;
    expect(explainedBy(`x=${template}`, [mkcert])).not.toEqual([]);
    expect(explainedBy(`x=${template}`, [nextDist])).toEqual([]);
    expect(explainedBy(`x=${BT}https://github.com/FiloSottile/mkcert/releases/download/\${MKCERT_VERSION}/other${BT}`, [mkcert])).toEqual([]);
    // the two request templates of Next, which go on with a path of the request, are named whole
    expect(explainedBy(`x=fetch(${BT}https://\${req.headers.host}\${urlPath}${BT})`, [nextDist])).not.toEqual([]);
    expect(explainedBy(`x=fetch(${BT}https://\${req.headers.host}\${other}${BT})`, [nextDist])).toEqual([]);
    expect(explainedBy(`x=${BT}http://\${i.host||"localhost"}:\${i.port||80}${BT}`, [nextDist])).not.toEqual([]);
  });

  it("reads a CSS hex escape together with an identity escape, so a stylesheet that mixes the two is found (wp5-r10-4)", () => {
    const sources = [
      `a{background:url(htt${BS}p:${BS}2f/cdn.evil.example/x.png)}`,
      `a{background:url(${BS}68 ttp${BS}s:${BS}2f/cdn.evil.example/x.png)}`,
      `a{background:url("ht${BS}74p${BS}:${BS}/${BS}/cdn.evil.example/x.png")}`,
      `a{background:url(h${BS}74${BS}74ps${BS}3a${BS}2f${BS}2fcdn${BS}2eevil.example/x.png)}`,
    ];
    for (const source of sources) {
      const urls = extractUrls(source);
      expect(urls.some((u) => hostOf(u) === "cdn.evil.example"), `${source} -> ${urls.join(" ")}`).toBe(true);
      expect(explainedBy(source, allPaths), source).toEqual([]);
    }
    // what stays out: an escaped letter that the JS reading owns is not decoded by the CSS one
    expect(extractUrls(`"see https://nextjs.org/docs/messages/a-page${BS}n  " + 'a${BS}pb'`)).toEqual(["https://nextjs.org/docs/messages/a-page"]);
  });

  it("decodes an HTML numeric character reference that has leading zeros (wp5-r10-5)", () => {
    const sources = [
      '<a href="&#00000000104;ttps://cdn.evil.example/a.css">',
      '<a href="&#x0000068;ttps://cdn.evil.example/a.css">',
      '<link href="https:&#x000002f;&#x000002f;cdn.evil.example/a.css">',
      '<a href="&#0104;ttps://cdn.evil.example/a.css">',
      '<a href="h&#x74;tps://cdn.evil.example/a.css">',
    ];
    for (const source of sources) {
      const urls = extractUrls(source);
      expect(urls.some((u) => hostOf(u) === "cdn.evil.example"), `${source} -> ${urls.join(" ")}`).toBe(true);
      expect(explainedBy(source, allPaths), source).toEqual([]);
    }
    // a reference to the null character is still no character
    expect(extractUrls('<a href="&#0000;ttps://cdn.evil.example/a.css">')).not.toContain("https://cdn.evil.example/a.css");
  });
});

describe("round 11 (wp5-r11)", () => {
  const rules = parseAllow(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "bundle-url-allow.txt"), "utf8")).rules;
  const BS = String.fromCharCode(92);
  const nodeModules = ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js"; // a host line counts here
  const nextDist = ".next/standalone/apps/panel/node_modules/next/dist/server/a.js"; // the exact lines of Next count here
  const explainedBy = (source: string, paths: string[]) => {
    const found: string[] = [];
    for (const e of extractUrlEntries(source)) {
      for (const path of paths) if (explainEntry(e, path, rules)) found.push(`${e.url} in ${path}`);
    }
    return found;
  };

  // wp5-r11-1. The cost of a file must be in proportion to its size. A regular expression that starts with an unanchored run
  // is retried at every position of the run, so a run of n characters costs n squared: 20,000 newlines took 2.7 s, 80,000
  // took 45 s, and a padded file stalled CI with no message. One test holds the class: a long run of every kind of character
  // that a regular expression of the scanner can start a run on, alone, after a scheme, inside a quoted URL, after a
  // quote, and before a URL that must still be found.
  it("takes time in proportion to the size of a run, whatever the run is made of (wp5-r11-1)", () => {
    const units: Record<string, string> = {
      newline: "\n",
      tab: "\t",
      cr: "\r",
      backslash: BS,
      "backslash pair": BS + BS,
      "tab escape": `${BS}t`,
      "newline escape": `${BS}n`,
      "carriage return escape": `${BS}r`,
      "hex escape": `${BS}x4`,
      "unicode escape": `${BS}u00`,
      "slash escape": `${BS}/`,
      dot: ".",
      "dot label": "a.",
      colon: ":",
      comma: ",",
      bracket: ")",
      scheme: "http:",
      "scheme with a host": "http:a.",
      "scheme with slashes": "https://",
      "scheme-relative": "//a.b ",
      "at sign": "x@",
      "quote in a path": 'https://a.b/"',
      "placeholder": "${",
      "html reference": "&#",
      "css escape": `${BS}2`,
      "invisible mark": "\uFEFF",
      "slash-less scheme and comma": "http:a.bc,",
      "slash-less scheme and semicolon": "http:a.bc;",
      "URL and comma": "https://a.b/,",
      "bracketed scheme-relative URL": "(//a.bc/x)",
    };
    const contexts: Array<[string, string, string]> = [
      ["alone", "", ""],
      ["after a scheme", "https://", ""],
      ["inside a quoted URL", 'x="https://a.b', ""],
      ["before a URL", "", ' "https://cdn.evil.example/x.js"'],
    ];
    // The property is linear cost, so it is asserted as a ratio and not as a wall-clock bound that sits close to the real cost and goes red on a loaded
    // machine (gate-r29-1: 5027 ms against 5000 for a run the scanner handles in about 1 s on an idle one; the same class as gate-r25-2 below). The
    // same run at 50,000 characters is timed first: a scan that is quadratic takes 16 times as long for 4 times the input, a linear one 4 times, and the
    // bound of 10 keeps the first failing and leaves room for noise. The small run is the best of two, and below 250 ms it is timer, JIT and GC noise
    // and is not allowed to make the ratio large (a 53 ms base against 709 ms was the first red of this version, and the same case measured 57 to 226 ms
    // at 50,000 and 600 to 690 ms at 200,000: linear). The quadratic scans this test was written for took 2.7 s at 20,000 characters, so they are
    // far above that floor at 50,000, and a loose absolute ceiling catches a scan that is slow at any size.
    const timeOf = (source: string) => {
      const started = performance.now();
      const entries = extractUrlEntries(source);
      return {took: performance.now() - started, entries};
    };
    const slow: string[] = [];
    for (const [unitName, unit] of Object.entries(units)) {
      const small = unit.repeat(Math.ceil(50_000 / unit.length));
      const run = unit.repeat(Math.ceil(200_000 / unit.length));
      for (const [where, before, after] of contexts) {
        const base = Math.min(timeOf(before + small + after).took, timeOf(before + small + after).took);
        const {took, entries} = timeOf(before + run + after);
        if (took / Math.max(base, 250) > 10 || took > 30_000) slow.push(`${unitName} ${where}: ${Math.round(base)} ms for 50k, ${Math.round(took)} ms for 200k`);
        if (after !== "") expect(entries.some((e) => hostOf(e.url) === "cdn.evil.example"), `${unitName} ${where}`).toBe(true);
      }
    }
    expect(slow).toEqual([]);
  }, 600_000);

  // wp5-r11-4. The text after the `}` of a placeholder is read the way the URL parser reads it, and never as a prefix.
  it("does not let an exact line that ends in a placeholder explain a remainder with a backslash or a long run (wp5-r11-4)", () => {
    const NEXT = "x=`https://nextjs.org/docs/messages/${r}";
    const sources = [
      `${NEXT}${BS}${BS}x.zip\``, // a JS pair is one backslash, which is a slash: /messages/a/x.zip
      `${NEXT}${BS}x.zip\``, // a lone one, as written
      "x=`https://nextjs.org/docs/${hasAppDir}" + [BS + BS, "..", BS + BS, "..", BS + BS, "dl", BS + BS, "tool`"].join(""),
      `${NEXT}${BS}${BS}a${BS}${BS}b.tar.xz\``,
      `${NEXT}${"/a".repeat(130)}${"/..".repeat(133)}/dl/x.tar.xz\``, // longer than the bound, so its end is unknown
      `${NEXT}${BS}t/../../dl/x.tar.xz\``, // a break is deleted and the climb is still there
    ];
    for (const source of sources) expect(explainedBy(source, [nextDist]), source).toEqual([]);
    // the shapes of the real strings stay explained: a message name, a sentence, a closing quote, a line break and a word
    for (const source of [
      `${NEXT}\``,
      `${NEXT}-page\``,
      `x="see https://nextjs.org/docs/messages/\${r}."`,
      `x="see https://nextjs.org/docs/messages/\${r}${BS}nMore text"`,
      `x='https://nextjs.org/docs/messages/\${r}'`,
    ]) {
      expect(explainedBy(source, [nextDist]), source).toHaveLength(1);
    }
  });

  // wp5-r11-5. A break escape before the closing quote does not end a URL that a program completes.
  it("treats a URL that ends in a break escape before its closing quote as built, so a host line does not vouch for it (wp5-r11-5)", () => {
    const sources = [
      `x="https://github.com/${BS}t"+repo+"/releases/download/v1/tool"`,
      `x="https://github.com/${BS}n"+repo+"/releases/download/v1/tool"`,
      `x="https://github.com/${BS}r${BS}n".concat(o,"/").concat(r,"/releases/download/v1/tool")`,
      `x="https://nextjs.org/docs/${BS}n"+p+".tar.gz"`,
      `x="https://github.com/${BS}x0a"+repo+"/releases/download/v1/tool"`,
      'x="https://github.com/\t"+repo+"/releases/download/v1/tool"',
      'x="https://github.com/o/r\n"+tail',
    ];
    for (const source of sources) expect(explainedBy(source, [nodeModules]), source).toEqual([]);
    // the message links of Next end like that, and an exact line names each, in Next's own code only
    const message = `x='See https://github.com/nodejs/node/issues/65100.${BS}n' + 'Falling back'`;
    expect(explainedBy(message, [nextDist])).toHaveLength(1);
    expect(explainedBy(message, [nodeModules])).toEqual([]);
    // a link whose string closes and is not completed stays a page
    expect(explainedBy(`x="see https://github.com/o/r${BS}n"`, [nodeModules])).toHaveLength(1);
  });

  // wp5-r11-6 and wp5-r11-2. A host line vouches for a page that a comment cites, never for a base that a program extends.
  it("never lets a host line vouch for a bare origin, or for a string that a comment hides the + after (wp5-r11-6, wp5-r11-2)", () => {
    const sources = [
      'x="https://github.com/" /* owner */ + repo + "/releases/download/v1/tool"',
      'x="https://github.com/o/r" // base\n + "/releases/download/v1/tool"',
      'x="https://nextjs.org/docs/" /* a */ /* b */ .concat(p, ".tar.gz")',
      'const B="https://github.com";fetch(B+repo+"/releases/download/v1/tool")',
      'let u="https://github.com";u+=repo+"/releases/download/v1/tool"',
      'fetch(new URL(repo+"/releases/download/v1/tool","https://github.com"))',
      '["https://github.com",o,r,"releases/download",t].join("/")',
      "const B=`https://github.com`;",
      // the spellings of the finding, with the slash that `new URL` writes after every bare origin (wp5-r12-1)
      'const B="https://github.com/";fetch(B+repo+"/releases/download/v1/tool")',
      'let u="https://github.com/";u+=repo+"/releases/download/v1/tool"',
      'fetch(new URL(repo+"/releases/download/v1/tool","https://github.com/"))',
      '["https://github.com/",o,r,"releases/download",t].join("")',
      'x="//github.com/"',
      'x="https://github.com//"',
      'x="https://github.com/?"',
      'x="https://nextjs.org/"',
    ];
    for (const source of sources) expect(explainedBy(source, [nodeModules]), source).toEqual([]);
    // a bare origin is named by an exact line, scoped to the file that holds it
    expect(explain("https://sindresorhus.com", nodeModules, rules)).toBeUndefined();
    expect(explain("https://sindresorhus.com", ".next/standalone/apps/panel/node_modules/next/dist/build/webpack/loaders/css-loader/src/camelcase.js", rules)).toBeDefined();
    // a page with a path is still a page
    expect(explain("https://github.com/o/r", nodeModules, rules)).toBeDefined();
  });
});

describe("round 12 (wp5-r12)", () => {
  const rules = parseAllow(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "bundle-url-allow.txt"), "utf8")).rules;
  const BS = String.fromCharCode(92);
  const nodeModules = ".next/standalone/node_modules/.pnpm/x@1/node_modules/x/index.js";
  const nextDist = ".next/standalone/node_modules/.pnpm/next@16.4.5/node_modules/next/dist/server/a.js";
  const explainedBy = (source: string, paths: string[]) => {
    const found: string[] = [];
    for (const e of extractUrlEntries(source)) {
      for (const path of paths) if (explainEntry(e, path, rules)) found.push(`${e.url} in ${path}`);
    }
    return found;
  };

  // wp5-r12-1. A bare origin is a bare origin with the slash that the URL parser writes after it.
  it("treats a path made only of slashes as a bare origin, and names the real roots of Next by one exact line (wp5-r12-1)", () => {
    for (const url of ["https://github.com", "https://github.com/", "https://github.com//", "//github.com/", "https://nextjs.org/"]) {
      expect(explain(url, nodeModules, rules), url).toBeUndefined();
    }
    // a page, even a short one, is still a page
    expect(explain("https://github.com/o", nodeModules, rules)).toBeDefined();
    // the specification roots that Next cites in its comments
    for (const root of [
      "http://browserhacks.com/",
      "https://url.spec.whatwg.org/",
      "https://infra.spec.whatwg.org/",
      "https://mimesniff.spec.whatwg.org/",
      "https://fetch.spec.whatwg.org/",
      "https://webidl.spec.whatwg.org/",
      "https://websockets.spec.whatwg.org/",
    ]) {
      expect(explain(root, nextDist, rules), root).toBeDefined();
      expect(explain(root, nodeModules, rules), root).toBeUndefined();
    }
    // a page on a specification host is still covered by the host line
    expect(explain("https://fetch.spec.whatwg.org/#concept-request", nodeModules, rules)).toBeUndefined(); // the fragment is cut, so it is the root
    expect(explain("https://html.spec.whatwg.org/multipage/", nodeModules, rules)).toBeDefined();
  });

  // wp5-r12-2. In a template literal an escaped quote is an ordinary character, and the remainder goes on past it.
  it("reads an escaped quote after a placeholder as a character of the path, never as the end of the remainder (wp5-r12-2)", () => {
    const sources = [
      "x=`https://nextjs.org/docs/messages/${r}" + BS + '"/../../../dl/x.tar.xz`',
      "x=`https://nextjs.org/docs/messages/${r}" + BS + "'/../../../dl/x.tar.xz`",
      "x=`https://nextjs.org/docs/messages/${r}" + BS + '"' + BS + '"/../../../dl/x.tar.xz`',
    ];
    for (const source of sources) {
      expect(explainedBy(source, [nextDist]), source).toEqual([]);
      const entry = extractUrlEntries(source).find((e) => e.url.includes("messages"));
      expect(entry?.afters.some((after) => after.includes("dl/x.tar.xz")), source).toBe(true);
    }
    // an escaped quote that only closes an embedded string, with nothing of a path after it, still ends the remainder
    expect(explainedBy("x='see https://nextjs.org/docs/messages/${r}" + BS + "'.'", [nextDist])).toHaveLength(1);
    // an unknown closer and path text after the quote: nothing is known about the end
    expect(explainedBy("see https://nextjs.org/docs/messages/${r}" + BS + '"/../../dl/x.tar.xz more', [nextDist])).toEqual([]);
  });

  // wp5-r12-3. Many URLs in one run with no white space, quote or backslash must not make a scan quadratic: each scan that
  // starts at a match is bounded, and a scan that reaches its bound leaves the entry partial.
  it("takes time in proportion to the size of a run of many URLs, and explains nothing past a bound (wp5-r12-3)", () => {
    const units = ["http:a.bc,", "http:a.bc;", "https:a.bc)", "ws:a.bc|", "https://a.b/,", "(//a.bc/x)", 'x="https://a.b/,'];
    // The property is linear cost, so it is asserted as a ratio and not as a wall-clock bound that sits close to the real cost and goes red on a
    // loaded or slower machine (gate-r25-2: 5029 ms against 5000). A scan that ran to the end of the run from every start would take 16 times as long
    // for 4 times the input; the ratio bound of 10 keeps that failing and leaves room for noise. Each size is the best of two runs, and a loose
    // absolute ceiling still catches a scan that is slow at any size.
    const timeOf = (unit: string, size: number) => {
      const run = unit.repeat(Math.ceil(size / unit.length));
      let best = Infinity;
      for (let i = 0; i < 2; i += 1) {
        const started = performance.now();
        extractUrlEntries(run);
        best = Math.min(best, performance.now() - started);
      }
      return best;
    };
    const slow: string[] = [];
    for (const unit of units) {
      const small = timeOf(unit, 12_500);
      const large = timeOf(unit, 50_000);
      // Below 100 ms the small run is mostly timer and JIT noise, so it is not allowed to make the ratio large.
      const ratio = large / Math.max(small, 100);
      if (ratio > 10 || large > 30_000) slow.push(`${unit}: ${Math.round(small)} ms for 12.5k, ${Math.round(large)} ms for 50k`);
    }
    expect(slow).toEqual([]);
    // a URL after the run is still found
    expect(extractUrls("https://a.b/,".repeat(20_000) + ' "https://cdn.evil.example/x.js"').some((u) => hostOf(u) === "cdn.evil.example")).toBe(true);
    // a string whose token or authority is longer than the bound is partial, so no line explains it
    const longPath = "a/".repeat(2000);
    const longHost = "a".repeat(600);
    for (const source of [`x="https://github.com/o/r/blob/${longPath}"`, `x="https://${longHost}.github.com/x"`, `https://github.com/${longPath}`]) {
      const entries = extractUrlEntries(source);
      expect(entries.length, source).toBeGreaterThan(0);
      expect(entries.every((e) => e.partial), source).toBe(true);
      expect(explainedBy(source, [nodeModules]), source).toEqual([]);
    }
    // under the bound nothing changes
    expect(explainedBy("x=\"https://github.com/o/r/blob/main/" + "a/".repeat(200) + "\"", [nodeModules])).toHaveLength(1);
  }, 120_000);
});

// Round 13 (wp5-r13-1): the source lint (url-allow.txt) lets a file hold an external-looking string, and the bundle
// gate (bundle-url-allow.txt) must explain the same string once it is compiled. WP4 added `https://ctrlz.invalid`
// to the first and not to the second, and only the real build showed it. This reads the first list, so a new file
// or a new string in one of those files cannot be forgotten in the second.
describe("the source allow list and the bundle allow list agree (wp5-r13-1)", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const sourceFiles = readFileSync(join(root, "tools", "web-lint", "url-allow.txt"), "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "" && !line.trim().startsWith("#"))
    .map((line) => line.split(/\s+#/)[0]!.trim());
  const rules = parseAllow(readFileSync(join(root, "tools", "web-lint", "bundle-url-allow.txt"), "utf8")).rules;

  it("lists at least one source file, so the loop below cannot pass by being empty", () => {
    expect(sourceFiles.length).toBeGreaterThan(0);
  });

  // Both places a compiled file of ours lands: the panel's browser bundle and the server chunks that the admin
  // (and the panel) keep under standalone.
  const where = [".next/static/chunks/a.js", ".next/standalone/apps/panel/.next/server/chunks/a.js"];

  it.each(sourceFiles)("explains every URL string of %s in at least one of the two places it is compiled to", (file) => {
    const source = readFileSync(join(root, file), "utf8");
    for (const entry of extractUrlEntries(source)) {
      const explained = where.some((path) => explainEntry(entry, path, rules) !== undefined);
      expect(explained, `${entry.url} in ${file}`).toBe(true);
    }
  });
});
