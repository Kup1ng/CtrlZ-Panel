import AxeBuilder from "@axe-core/playwright";
import {appendFileSync, readFileSync} from "node:fs";
import {resolve} from "node:path";
import type {Page} from "@playwright/test";

import {
  accentProblem,
  AXE_TAGS,
  classify,
  ELEMENT_ATTR,
  FAILING_IMPACTS,
  parseKnown,
  REGION_ATTR,
  regionsOfHtml,
  splitIncomplete,
  splitLibraryDefects,
  type DefectNode,
  type KnownFailure,
  type LibraryDefect,
  type Rgb,
} from "./axeLogic.ts";
import {expect, test} from "./guard.ts";

// Spec 17.5 for every spec that runs axe (wp12-r1-9): the tags, the failing impacts, the known file,
// the summary and the accent pair live here once, so a screen's matrix spec asks one question.
//
//   await expectAccessible(page, {screen: "dialogs"});
//
// `e2e/axe-known.json` (next to the specs of the app, `[]` while nothing is known) lists the failures
// that DESIGN.md Q1 to Q4 leave open: `{"rule": "color-contrast", "selector": "...", "screen": "dialogs",
// "note": "Q2"}`. A failing node on that list is reported in the run summary (axeReporter.ts) and does
// not fail. A listed node that no longer occurs on its screen does fail, so the file cannot go stale.
// `incomplete` results (a translucent surface makes contrast undecidable) are logged, never failed.

const KNOWN_FILE = "e2e/axe-known.json";

function readKnown(): KnownFailure[] {
  try {
    return parseKnown(readFileSync(resolve(process.cwd(), KNOWN_FILE), "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  }
}

/**
 * Marks every element inside the region of a defect with REGION_ATTR (and the defective element itself with ELEMENT_ATTR), and keeps marking what is added until `unmarkRegions`. Returns
 * the regions that hold their defective element right now.
 */
async function markRegions(page: Page, defects: readonly LibraryDefect[]): Promise<string[]> {
  return page.evaluate(
    ({regions, elements, attr, elementAttr}) => {
      const mark = (el: Element) => {
        const hit = regions.flatMap((region, i) => (el.closest(region) != null ? [i] : []));
        if (hit.length > 0) el.setAttribute(attr, hit.join(" "));
        // The defective element itself, apart from the rest of its region.
        const own = regions.flatMap((region, i) => (el.matches(`${region} ${elements[i]}`) ? [i] : []));
        if (own.length > 0) el.setAttribute(elementAttr, own.join(" "));
      };
      document.querySelectorAll("*").forEach(mark);
      const observer = new MutationObserver((records) => {
        for (const record of records)
          record.addedNodes.forEach((node) => {
            if (node.nodeType !== 1) return;
            mark(node as Element);
            (node as Element).querySelectorAll("*").forEach(mark);
          });
      });
      observer.observe(document, {childList: true, subtree: true});
      (window as unknown as {__ctrlzRegionObserver?: MutationObserver}).__ctrlzRegionObserver = observer;
      return regions.filter((region, i) => document.querySelector(`${region} ${elements[i]}`) != null);
    },
    {regions: defects.map((d) => d.within), elements: defects.map((d) => d.element), attr: REGION_ATTR, elementAttr: ELEMENT_ATTR},
  );
}

/** Stops the observer, takes the marks off, and returns the regions that hold their defective element now. */
async function unmarkRegions(page: Page, defects: readonly LibraryDefect[]): Promise<string[]> {
  return page.evaluate(
    ({regions, elements, attr, elementAttr}) => {
      (window as unknown as {__ctrlzRegionObserver?: MutationObserver}).__ctrlzRegionObserver?.disconnect();
      document.querySelectorAll(`[${attr}]`).forEach((el) => el.removeAttribute(attr));
      document.querySelectorAll(`[${elementAttr}]`).forEach((el) => el.removeAttribute(elementAttr));
      return regions.filter((region, i) => document.querySelector(`${region} ${elements[i]}`) != null);
    },
    {regions: defects.map((d) => d.within), elements: defects.map((d) => d.element), attr: REGION_ATTR, elementAttr: ELEMENT_ATTR},
  );
}

export async function expectAccessible(
  page: Page,
  options: {
    screen: string;
    include?: string;
    exclude?: string[];
    /** A defect of a library's own element, found by the region it sits in (see `LibraryDefect`). */
    libraryDefects?: LibraryDefect[];
    /**
     * The screen is one where the library defects must still occur: a defect whose element is on the page and
     * no longer fails fails the run as stale. Not every screen with the element fails it (the log's image is
     * labelled by an announcement on some), so this is asked of one screen that always does.
     */
    libraryDefectsMustOccur?: boolean;
    /**
     * Leave the pointer where it is. The default parks it in the corner first (gate-r7-8): a control under the pointer is in its hover state, so
     * without that a screen's result depended on where the last click happened to leave the mouse, and a layout change elsewhere on the screen
     * could turn it red (a hover fill that fails contrast) or green. A case that wants the hover state hovers the control and passes this.
     */
    keepPointer?: boolean;
  },
) {
  if (!options.keepPointer) await page.mouse.move(0, 0);
  let builder = new AxeBuilder({page}).withTags([...AXE_TAGS]);
  if (options.include) builder = builder.include(options.include);
  for (const e of options.exclude ?? []) builder = builder.exclude(e);
  const defects = options.libraryDefects ?? [];
  // The regions are decided now, in the page, and not after axe has answered (gate-r2-12): see REGION_ATTR.
  const before = defects.length > 0 ? await markRegions(page, defects) : [];
  let result;
  let after: string[] = [];
  try {
    result = await builder.analyze();
  } finally {
    // Always, so that an analysis that throws does not leave the observer behind.
    if (defects.length > 0) after = await unmarkRegions(page, defects);
  }
  const nodes: DefectNode[] = [];
  for (const v of result.violations) {
    if (v.impact == null || !FAILING_IMPACTS.has(v.impact)) continue;
    for (const n of v.nodes) {
      // A target that is not one plain selector (a shadow root, a frame) is never a library defect.
      const selector = n.target.length === 1 && typeof n.target[0] === "string" ? n.target[0] : null;
      const inside = selector && defects.some((d) => d.rule === v.id) ? regionsOfHtml(n.html, defects) : [];
      nodes.push({rule: v.id, selector: n.target.map((t) => (Array.isArray(t) ? t.join(" >> ") : String(t))).join(" "), inside});
    }
  }
  // On the page before the analysis and after it: an element that came or went during it was not what axe looked at.
  const present = new Set<string>();
  for (const d of options.libraryDefectsMustOccur ? defects : []) if (before.includes(d.within) && after.includes(d.within)) present.add(d.within);
  const split = splitLibraryDefects(nodes, defects, present);

  const {unknown, known, stale} = classify(split.rest, readKnown(), options.screen);
  const info = test.info();
  for (const c of split.covered) {
    const d = defects.find((x) => c.startsWith(`${x.rule}: `))!;
    info.annotations.push({type: "axe-known", description: `${options.screen}: ${c} (${d.note})`});
  }
  stale.push(...split.stale);
  for (const k of known) info.annotations.push({type: "axe-known", description: `${options.screen}: ${k}`});
  for (const i of result.incomplete) {
    const {covered, own} = splitIncomplete(i.id, i.nodes, defects);
    // A node in the region of a library defect that names this rule is that defect, already reported above: not a node left to a look.
    if (covered > 0) info.annotations.push({type: "axe-known", description: `${options.screen}: ${i.id} incomplete (${covered} nodes, same element as the library defect)`});
    if (own > 0) info.annotations.push({type: "axe-incomplete", description: `${options.screen}: ${i.id} (${own} nodes)`});
  }
  // AXE_INCOMPLETE_FILE=path: one JSON line per screen with the node, the html and axe's own reason of every undecided result, so a person can
  // look at the element instead of a count (P1 gate). Off by default: the run summary stays short.
  const dump = process.env.AXE_INCOMPLETE_FILE;
  if (dump && result.incomplete.length > 0) {
    const reason = (n: {any: {message: string}[]; all: {message: string}[]; none: {message: string}[]}) =>
      [...n.any, ...n.all, ...n.none].map((c) => c.message);
    appendFileSync(
      dump,
      JSON.stringify({
        project: info.project.name,
        screen: options.screen,
        incomplete: result.incomplete.map((i) => ({
          id: i.id,
          nodes: i.nodes.map((n) => ({target: n.target, html: n.html.slice(0, 240), reason: reason(n), data: n.any.map((c) => c.data)})),
        })),
      }) + "\n",
    );
  }

  expect(unknown, "axe: serious or critical violations that no known entry covers (spec 17.5)").toEqual([]);
  expect(stale, "axe-known.json or a libraryDefects entry lists a failure that no longer occurs: delete it (spec 17.5)").toEqual([]);
}

/**
 * The accent pair, from computed colours (17.5): the page resolves `--accent` and `--accent-foreground`
 * to sRGB through a canvas (the tokens are oklch), and the Node side checks the exact colours and the 8.42.
 */
export async function expectAccentPair(page: Page) {
  const [bg, fg] = await page.evaluate(() => {
    const probe = document.createElement("canvas").getContext("2d", {willReadFrequently: true})!;
    const resolveVar = (name: string): [number, number, number] => {
      const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      probe.clearRect(0, 0, 1, 1);
      probe.fillStyle = "#000";
      probe.fillStyle = value;
      probe.fillRect(0, 0, 1, 1);
      const [r, g, b] = probe.getImageData(0, 0, 1, 1).data;
      return [r!, g!, b!];
    };
    return [resolveVar("--accent"), resolveVar("--accent-foreground")] as [Rgb, Rgb];
  });
  expect(accentProblem(bg, fg), "the accent pair of DESIGN.md").toBeNull();
}
