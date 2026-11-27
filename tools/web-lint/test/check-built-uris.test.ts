import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";

import {afterEach, describe, expect, it} from "vitest";

import {builtFiles, findInlineUris} from "../check-built-uris.mjs";

// gate-r13-2: the policy has no data: and no blob: in img-src and font-src, and a build that needs one must fail before a browser does.
const scan = (text: string, path = "apps/panel/.next/static/chunks/a.css", allow = "") => findInlineUris([{path, text}], allow);

describe("check-built-uris", () => {
  it("fails on a CSS image that is a data: or blob: URI, whatever the quoting", () => {
    for (const css of [
      '.a{mask-image:url("data:image/svg+xml,%3Csvg%3E")}',
      ".a{background:url('data:image/png;base64,AAAA')}",
      ".a{background:url(data:image/png;base64,AAAA)}",
      ".a{background:url( data:image/png;base64,AAAA )}",
      ".a{background:URL(DATA:image/png;base64,AAAA)}",
      ".a{background:url(blob:https://x/1)}",
      ".a{-webkit-mask:url(\n  'data:image/svg+xml;utf8,<svg/>')}",
    ]) {
      expect(scan(css).found, css).toHaveLength(1);
    }
  });

  it("fails on the same CSS written inside a JS string, and on a script that builds an image or a font", () => {
    for (const js of [
      'e.style.cssText="mask-image:url(\\"data:image/svg+xml,%3Csvg%3E\\")"',
      'const i=new Image;i.src="data:image/gif;base64,R0lGOD"',
      "const f=`data:font/woff2;base64,AAAA`",
      "x='data:application/font-woff;base64,AAAA'",
      'const u="blob:"+id',
    ]) {
      expect(scan(js, "apps/admin/.next/static/chunks/b.js").found, js).toHaveLength(1);
    }
  });

  it("reports the file and the line, and a short piece of the match and not the whole URI", () => {
    const {found} = scan(`a{}\nb{}\n.c{background:url("data:image/png;base64,${"A".repeat(500)}")}`);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/^apps\/panel\/\.next\/static\/chunks\/a\.css:3: /);
    expect(found[0]!.length).toBeLessThan(200);
  });

  it("passes what is not a data or blob image: plain urls of ours, other data: uses, look-alikes", () => {
    for (const text of [
      ".a{background:url(/_next/static/media/x.svg)}",
      ".a{background:url(\"/_next/static/media/x.svg\")}",
      "/* data:image/png in a comment */ .a{}",
      "const metadata:image/x",
      'if(t.startsWith("text/")){}',
      "const s={data:image,blobs:1,blob:2}",
      "//# sourceMappingURL=a.js.map",
    ]) {
      expect(scan(text).found, text).toEqual([]);
    }
  });

  it("lets a reviewed file through, with a reason, and says when a line explains nothing", () => {
    const css = '.a{mask-image:url("data:image/svg+xml,%3Csvg%3E")}';
    const allow = "# header\napps/panel/.next/static/chunks/a.css  # reviewed: a decorative mask that the CSP change of the same commit allows\nchunks/gone.css  # old\n";
    const r = scan(css, "apps/panel/.next/static/chunks/a.css", allow);
    expect(r.found).toEqual([]);
    expect(r.allowed).toHaveLength(1);
    expect(r.stale).toEqual(['inline-uri-allow.txt:3: "chunks/gone.css" explains nothing']);
    expect(scan(css, "apps/admin/.next/static/chunks/a.css", allow).found, "the part must be in the path").toHaveLength(1);
  });

  it("refuses an allow line with no reason", () => {
    const r = scan("a{}", "x.css", "chunks/a.css\nchunks/b.css  #\n");
    expect(r.problems).toHaveLength(2);
  });
});

describe("builtFiles", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, {recursive: true, force: true});
  });
  function fake(files: Record<string, string>) {
    const root = mkdtempSync(join(tmpdir(), "ctrlz-built-"));
    dirs.push(root);
    for (const [name, text] of Object.entries(files)) {
      const full = join(root, name);
      mkdirSync(join(full, ".."), {recursive: true});
      writeFileSync(full, text);
    }
    return root;
  }

  // The files that every test below needs: a build with a static half and a server half.
  const BASE = {
    "apps/panel/.next/static/chunks/a.js": "1",
    "apps/panel/.next/static/css/a.css": "2",
    "apps/panel/.next/server/chunks/ssr/c.js": "3",
  };

  it("throws when there is no build, so a missing .next cannot pass as a clean scan", () => {
    expect(() => builtFiles(fake({"apps/panel/package.json": "{}"}), "panel")).toThrow(/next build/);
  });

  it("throws when the build has no CSS or no JS, so a moved folder cannot pass as a clean scan", () => {
    const root = fake({"apps/panel/.next/static/chunks/a.js": "1", "apps/panel/.next/server/chunks/ssr/c.js": "3"});
    expect(() => builtFiles(root, "panel")).toThrow(/would check nothing/);
  });

  it("throws when there is no JS under .next/server/chunks, so a moved server folder cannot pass as a clean scan (gate-r14-2)", () => {
    const root = fake({"apps/panel/.next/static/chunks/a.js": "1", "apps/panel/.next/static/css/a.css": "2", "apps/panel/.next/server/app/p.html": "4"});
    expect(() => builtFiles(root, "panel")).toThrow(/server half/);
  });

  it("reads .next/static, the compiled server chunks, the prerendered pages and the CSS, JS and SVG of public/, and nothing else", () => {
    const root = fake({
      ...BASE,
      "apps/panel/.next/static/media/f.woff2": "3",
      "apps/panel/.next/server/chunks/ssr/c.js.map": "m",
      "apps/panel/.next/server/chunks/ssr/d.mjs": "d",
      "apps/panel/.next/server/app/en/p.html": "4",
      "apps/panel/.next/server/app/en/p.rsc": "4",
      "apps/panel/.next/server/app/en/p.meta": "4",
      "apps/panel/.next/server/app-paths-manifest.json": "4",
      "apps/panel/public/i.svg": "5",
      "apps/panel/public/logo.png": "6",
    });
    expect(builtFiles(root, "panel").map((f) => f.path).sort()).toEqual([
      "apps/panel/.next/server/app/en/p.html",
      "apps/panel/.next/server/app/en/p.rsc",
      "apps/panel/.next/server/chunks/ssr/c.js",
      "apps/panel/.next/server/chunks/ssr/d.mjs",
      "apps/panel/.next/static/chunks/a.js",
      "apps/panel/.next/static/css/a.css",
      "apps/panel/public/i.svg",
    ]);
  });

  it("finds a data: image that only a Server Component holds: in the compiled chunk, the prerendered HTML and the flight payload (gate-r14-2)", () => {
    const img = '<img src="data:image/svg+xml,%3Csvg%3E" alt="">';
    const root = fake({
      ...BASE,
      "apps/panel/.next/server/chunks/ssr/page.js": `return jsx("img",{src:"data:image/svg+xml,%3Csvg%3E"})`,
      "apps/panel/.next/server/app/fa/empty.html": img,
      "apps/panel/.next/server/app/fa/empty.rsc": `1:["$","div",null,{"style":{"backgroundImage":"url(data:image/svg+xml,%3Csvg%3E)"}}]`,
    });
    const {found} = findInlineUris(builtFiles(root, "panel"), "");
    expect(found.map((f) => f.split(":")[0]!).sort()).toEqual([
      "apps/panel/.next/server/app/fa/empty.html",
      "apps/panel/.next/server/app/fa/empty.rsc",
      "apps/panel/.next/server/chunks/ssr/page.js",
    ]);
  });
});
