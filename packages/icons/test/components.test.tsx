import {describe, expect, it} from "vitest";
import type {ReactElement} from "react";
import {Logo} from "../src/generated/brand/Logo.tsx";
import {registry} from "../src/generated/registry.ts";
import {Icon} from "../src/Icon.tsx";
import {general} from "../src/hugeicons.ts";
import {SubIcon, hasSubIcon} from "../src/SubIcon.tsx";
import {hasLogo, logoSrc, monogramLetter} from "../src/monogram.ts";

// forwardRef components are plain objects with a render function, so they can be
// called without a DOM. That is enough to check the props they hand to <svg>.
type Rendered = ReactElement<Record<string, unknown>>;
const renderRef = (c: unknown, props: Record<string, unknown>): Rendered =>
  (c as {render: (p: unknown, r: unknown) => Rendered}).render(props, null);

describe("generated icons", () => {
  const all = Object.entries(registry).flatMap(([group, set]) => Object.entries(set).map(([name, c]) => ({group, name, c})));

  it("registers one component per file", () => {
    expect(all).toHaveLength(69);
  });

  it("is decorative by default and named on request", () => {
    for (const {c} of all) {
      const hidden = renderRef(c, {});
      expect(hidden.type).toBe("svg");
      expect(hidden.props["aria-hidden"]).toBe(true);
      expect(hidden.props.role).toBeUndefined();
      const named = renderRef(c, {"aria-label": "Malware"});
      expect(named.props["aria-hidden"]).toBeUndefined();
      expect(named.props.role).toBe("img");
    }
  });

  it("draws on the 24 grid with a 1.5 round stroke in currentColor, 1em square", () => {
    for (const {c} of all) {
      const p = renderRef(c, {}).props;
      expect(p).toMatchObject({viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round", strokeLinejoin: "round", width: "1em", height: "1em"});
    }
  });

  it("lets a caller override size and class", () => {
    const p = renderRef(registry.filters.malware, {className: "size-6", width: 40}).props;
    expect(p.className).toBe("size-6");
    expect(p.width).toBe(40);
  });
});

describe("Logo", () => {
  it("keeps the brand colour and viewBox", () => {
    const p = renderRef(Logo, {}).props;
    expect(p.viewBox).toBe("0 0 1024 1024");
    expect(JSON.stringify(p.children)).toContain("#04B5FB");
  });
});

describe("SubIcon", () => {
  it("renders a known slug and nothing for an unknown one", () => {
    expect(SubIcon({group: "filters", name: "malware"})).not.toBeNull();
    // @ts-expect-error an unknown slug is a type error, and still harmless at run time
    expect(SubIcon({group: "filters", name: "not-a-filter"})).toBeNull();
    expect(hasSubIcon("filters", "malware")).toBe(true);
    expect(hasSubIcon("filters", "constructor")).toBe(false);
    expect(hasSubIcon("services", "adult")).toBe(false);
  });

  it("passes the label through as the accessible name", () => {
    const el = SubIcon({group: "rules", name: "folder", label: "Folder"}) as ReactElement<Record<string, unknown>>;
    expect(el.props["aria-label"]).toBe("Folder");
  });
});

describe("Icon (Hugeicons allowlist)", () => {
  it("covers every name the spec lists for P1, the eight that the P2 and P3 screens added and the five of the P4 admin sidebar", () => {
    const names = "bell menu search plus more chevron close check help info warning error profiles endpoints analytics statistics activityLog domainTest preferences account api logout sun moon system copy edit trash download key shield phone language users invite sms settings audit filters services rules profileOptions lock unlock upload calendar globe link qr move overview nodes pair domain runbook".split(" ");
    expect(Object.keys(general).sort()).toEqual([...names].sort());
    for (const n of names) expect(Array.isArray((general as Record<string, unknown>)[n]), n).toBe(true);
  });

  it("is decorative unless labelled, and flips only when asked", () => {
    const plain = Icon({name: "bell"}).props as Record<string, unknown>;
    expect(plain["aria-hidden"]).toBe(true);
    expect(plain.role).toBeUndefined();
    expect(plain.className).toBeUndefined();
    expect(plain).toMatchObject({size: "1em", color: "currentColor", strokeWidth: 1.5});
    const named = Icon({name: "chevron", label: "Next", flip: true, className: "size-4"}).props as Record<string, unknown>;
    expect(named.role).toBe("img");
    expect(named["aria-label"]).toBe("Next");
    expect(named["aria-hidden"]).toBeUndefined();
    expect(named.className).toBe("rtl:rotate-180 size-4");
  });
});

describe("monogram and logo lookup", () => {
  it("takes the first grapheme", () => {
    expect(monogramLetter("apple")).toBe("A");
    expect(monogramLetter("  spotify")).toBe("S");
    expect(monogramLetter("دیجی‌کالا")).toBe("د");
    expect(monogramLetter("😀 fun")).toBe("😀");
    expect(monogramLetter("ßeta")).toBe("ß");
    expect(monogramLetter("")).toBe("?");
    expect(monogramLetter("   ")).toBe("?");
  });

  it("never builds a URL from an unknown or hostile slug", () => {
    expect(hasLogo("apple")).toBe(false); // the manifest is empty in P1
    expect(logoSrc("apple")).toBeNull();
    expect(logoSrc("https://evil.test/x")).toBeNull();
    expect(logoSrc("../x")).toBeNull();
    expect(logoSrc("")).toBeNull();
  });
});
