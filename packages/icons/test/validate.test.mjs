import {describe, expect, it} from "vitest";
import {parseProvenance, pascal, validateIconSvg, validateLooseSvg} from "../scripts/lib.mjs";

const wrap = (body, attrs = "") =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" ${attrs}>${body}</svg>`;

const good = wrap(`<path d="M3 3h18"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/>`);

describe("validateIconSvg (spec 7.3)", () => {
  it("accepts a well-formed icon", () => {
    expect(validateIconSvg(good)).toEqual([]);
  });

  it("accepts the SVG namespace and nothing else that looks like a URL", () => {
    expect(validateIconSvg(wrap(`<path d="M3 3h18"/>`, `xmlns="http://www.w3.org/2000/svg"`))).toEqual([]);
    expect(validateIconSvg(wrap(`<path d="M3 3h18"/>`, `xmlns="http://example.test/x"`)).join("\n")).toMatch(/xmlns|http/);
  });

  const bad = {
    "wrong viewBox": good.replace("0 0 24 24", "0 0 32 32"),
    "wrong stroke width on the root": good.replace('stroke-width="1.5"', 'stroke-width="2"'),
    "wrong stroke width on a child": wrap(`<path d="M3 3h18" stroke-width="2"/>`),
    "a hex colour": wrap(`<path d="M3 3h18" stroke="#04B5FB"/>`),
    "a named colour": wrap(`<path d="M3 3h18" fill="red"/>`),
    "a gradient reference": wrap(`<path d="M3 3h18" fill="url(#g)"/>`),
    "an image": wrap(`<image width="4" height="4"/>`),
    "a script": wrap(`<script>alert(1)</script>`),
    "a style": wrap(`<style>path{stroke:red}</style>`),
    "a use": wrap(`<use x="1"/>`),
    "a foreignObject": wrap(`<foreignObject x="1"></foreignObject>`),
    "an href": wrap(`<path d="M3 3h18" href="x"/>`),
    "an xlink href": wrap(`<path d="M3 3h18" xlink:href="x"/>`),
    "an id": wrap(`<path id="a" d="M3 3h18"/>`),
    "an event handler": wrap(`<path d="M3 3h18" onload="x"/>`),
    "an http string": wrap(`<path d="M3 3h18" data-x="http://x"/>`),
    "a class": wrap(`<path d="M3 3h18" class="x"/>`),
    "a width on the root": wrap(`<path d="M3 3h18"/>`, `width="24"`),
    "a transform": wrap(`<path d="M3 3h18" transform="scale(-1 1)"/>`),
    "text content": wrap(`<g>hello</g>`),
    "a bad path character": wrap(`<path d="M3 3h18 foo"/>`),
    "an unbalanced tag": `<svg viewBox="0 0 24 24"><g></svg>`,
    "an XML declaration": `<?xml version="1.0"?>${good}`,
    "two roots": good + good,
  };
  for (const [name, svg] of Object.entries(bad)) {
    it(`rejects ${name}`, () => {
      expect(validateIconSvg(svg).length).toBeGreaterThan(0);
    });
  }
});

describe("validateLooseSvg (brand and logos)", () => {
  it("keeps brand colours but not references", () => {
    const logo = `<svg viewBox="0 0 1024 1024" fill="none"><path d="M1 1h2" fill="#04B5FB"/></svg>`;
    expect(validateLooseSvg(logo)).toEqual([]);
    expect(validateLooseSvg(logo.replace('fill="#04B5FB"', 'fill="url(#g)"')).length).toBeGreaterThan(0);
    expect(validateLooseSvg(`<svg viewBox="0 0 24 24"><image/></svg>`).length).toBeGreaterThan(0);
    expect(validateLooseSvg(`<svg viewBox="0 0 24 24"><path d="M1 1" id="a"/></svg>`).length).toBeGreaterThan(0);
    expect(validateLooseSvg(`<svg><path d="M1 1"/></svg>`).length).toBeGreaterThan(0);
  });
});

describe("helpers", () => {
  it("builds component names", () => {
    expect(pascal("ads-trackers")).toBe("AdsTrackers");
    expect(pascal("vpn-dns")).toBe("VpnDns");
    expect(pascal("Logo")).toBe("Logo");
  });

  it("reads provenance rows and ignores the rest", () => {
    const md = "| File | Author | Date | Method |\n|---|---|---|---|\n| svg/a/b.svg | X | 2026-11-07 | drawn from scratch |\ntext";
    expect([...parseProvenance(md).keys()]).toEqual(["svg/a/b.svg"]);
  });
});
