import {describe, expect, it} from "vitest";

import {
  ACCENT_BG,
  ACCENT_FG,
  ACCENT_RATIO,
  accentProblem,
  AXE_TAGS,
  classify,
  contrastRatio,
  failingNodes,
  keyOf,
  splitLibraryDefects,
  parseKnown,
  REGION_ATTR,
  regionsOfHtml,
  type KnownFailure,
} from "./axeLogic.ts";

const v = (id: string, impact: string | null, ...targets: string[][]) => ({id, impact, nodes: targets.map((target) => ({target}))});

describe("the gate of spec 17.5", () => {
  it("uses the four WCAG tags, whose wcag22aa carries the 24 px target-size rule", () => {
    expect([...AXE_TAGS]).toEqual(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]);
  });

  it("fails on serious and critical only, one entry per node", () => {
    const found = failingNodes([
      v("color-contrast", "serious", [".a"], [".b"]),
      v("button-name", "critical", ["#c"]),
      v("region", "moderate", [".d"]),
      v("tabindex", "minor", [".e"]),
      v("no-impact", null, [".f"]),
    ]);
    expect(found).toEqual(["color-contrast: .a", "color-contrast: .b", "button-name: #c"]);
  });

  it("names a node inside an iframe or a shadow root with its whole path", () => {
    expect(failingNodes([v("color-contrast", "serious", ["iframe", ".inner"], [[".host", ".in-shadow"]] as unknown as string[])])).toEqual([
      "color-contrast: iframe .inner",
      "color-contrast: .host >> .in-shadow",
    ]);
  });
});

describe("the known file", () => {
  const known: KnownFailure[] = [
    {rule: "color-contrast", selector: ".muted", screen: "dialogs", note: "Q1"},
    {rule: "color-contrast", selector: ".other", screen: "rows"},
  ];

  it("excuses a listed failure on its own screen, and fails an unlisted one", () => {
    const r = classify([keyOf("color-contrast", ".muted"), keyOf("button-name", "#x")], known, "dialogs");
    expect(r.known).toEqual(["color-contrast: .muted"]);
    expect(r.unknown).toEqual(["button-name: #x"]);
    expect(r.stale).toEqual([]);
  });

  it("does not excuse a listed selector on another screen", () => {
    const r = classify([keyOf("color-contrast", ".muted")], known, "rows");
    expect(r.unknown).toEqual(["color-contrast: .muted"]);
  });

  it("calls an entry stale when its failure no longer occurs on its screen, and only on its screen", () => {
    expect(classify([], known, "dialogs").stale).toEqual(["color-contrast: .muted"]);
    expect(classify([], known, "states").stale).toEqual([]);
  });

  it("is empty when the file is absent or blank, and refuses a malformed one", () => {
    expect(parseKnown(null)).toEqual([]);
    expect(parseKnown("  \n")).toEqual([]);
    expect(parseKnown("[]")).toEqual([]);
    expect(parseKnown('[{"rule":"r","selector":"s","screen":"x","note":"Q2"}]')).toEqual([{rule: "r", selector: "s", screen: "x", note: "Q2"}]);
    expect(() => parseKnown("{}")).toThrow(/array/);
    expect(() => parseKnown('[{"rule":"r","selector":"s"}]')).toThrow(/screen/);
    expect(() => parseKnown("not json")).toThrow();
  });
});

describe("the accent pair (DESIGN.md)", () => {
  it("is 8.42 for #010D16 on #04B5FB", () => {
    expect(contrastRatio(ACCENT_FG, ACCENT_BG)).toBeCloseTo(ACCENT_RATIO, 1);
    expect(accentProblem(ACCENT_BG, ACCENT_FG)).toBeNull();
  });
  it("allows a channel off by one from the oklch rounding, and no more", () => {
    expect(accentProblem([4, 181, 250], [1, 13, 22])).toBeNull();
    expect(accentProblem([4, 181, 253], ACCENT_FG)).toMatch(/accent is/);
  });
  it("refuses light text on the accent, which is the fixed rule", () => {
    expect(accentProblem(ACCENT_BG, [255, 255, 255])).toMatch(/must be dark/);
  });
});

describe("splitLibraryDefects (wp8-r5-5)", () => {
  const defect = {rule: "role-img-alt", within: '[role="log"]', element: '[role="img"]', note: "announcer"};
  const inLog = {rule: "role-img-alt", selector: 'div[aria-labelledby="react-aria123-_r_5_"]', inside: ['[role="log"]']};

  it("reports a node of the rule inside the region and passes everything else on", () => {
    const outside = {rule: "role-img-alt", selector: "img.logo", inside: []};
    const other = {rule: "color-contrast", selector: "p", inside: ['[role="log"]']};
    const split = splitLibraryDefects([inLog, outside, other], [defect], new Set(['[role="log"]']));
    expect(split.covered).toEqual([keyOf(inLog.rule, inLog.selector)]);
    expect(split.rest).toEqual([keyOf(outside.rule, outside.selector), keyOf(other.rule, other.selector)]);
    expect(split.stale).toEqual([]);
  });

  it("is stale when the region is on the page and holds no such failure, and not when there is no region", () => {
    expect(splitLibraryDefects([], [defect], new Set(['[role="log"]'])).stale).toEqual(['role-img-alt within [role="log"]']);
    expect(splitLibraryDefects([], [defect], new Set()).stale).toEqual([]);
  });
});

describe("regionsOfHtml (gate-r2-12, gate-r2-20)", () => {
  const defects = [
    {rule: "role-img-alt", within: '[role="log"]', element: '[role="img"]', note: "announcer"},
    {rule: "x", within: ".other", element: "i", note: "other"},
  ];

  // The region comes from the markup that axe returned, so a node that React Aria has removed from the page since is still classified.
  it("reads the region from the node's own markup, with no page to ask", () => {
    expect(regionsOfHtml(`<div role="img" ${REGION_ATTR}="0" aria-labelledby="react-aria1-_r_5_"></div>`, defects)).toEqual(['[role="log"]']);
    expect(regionsOfHtml(`<div ${REGION_ATTR}="0 1" role="img">`, defects)).toEqual(['[role="log"]', ".other"]);
    expect(regionsOfHtml(`<div ${REGION_ATTR}="1">`, defects)).toEqual([".other"]);
  });
  it("finds nothing for a node that was not marked, or whose mark names no defect", () => {
    expect(regionsOfHtml('<div role="img" aria-labelledby="x"></div>', defects)).toEqual([]);
    expect(regionsOfHtml(`<div ${REGION_ATTR}="">`, defects)).toEqual([]);
    expect(regionsOfHtml(`<div ${REGION_ATTR}="7">`, defects)).toEqual([]);
    // Only the attribute itself, not a value that merely contains its name.
    expect(regionsOfHtml(`<div data-x-${REGION_ATTR}="0">`, defects)).toEqual([]);
  });
});
