// The decisions of the accessibility check of spec 17.5, apart from Playwright and axe so that a unit
// test can drive them. The page-facing half is axe.ts.

/** The tags of 17.5: WCAG 2.0 to 2.2, A and AA. `wcag22aa` carries axe's `target-size` rule, the 24 px hit target of DESIGN.md. */
export const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] as const;

/** Only these impacts fail a run (17.5). `minor` and `moderate` are reported by axe and are not gated here. */
export const FAILING_IMPACTS = new Set(["serious", "critical"]);

/** The slice of an axe violation this logic reads. */
export type AxeViolation = {id: string; impact?: string | null; nodes: {target: unknown[]}[]};

/**
 * One known failure of DESIGN.md Q1 to Q4: a rule on a selector, on one screen. `screen` is the name a
 * spec passes to `expectAccessible`, so an entry is checked (and can go stale) only in its own screen's run.
 */
export type KnownFailure = {rule: string; selector: string; screen: string; note?: string};

/** `rule: selector`, one line per node, the way the failure message and the known file both name it. */
export const keyOf = (rule: string, selector: string) => `${rule}: ${selector}`;

const selectorOf = (target: unknown[]) => target.map((t) => (Array.isArray(t) ? t.join(" >> ") : String(t))).join(" ");

/** Every failing node of the violations, as `rule: selector`. */
export function failingNodes(violations: readonly AxeViolation[]): string[] {
  return violations
    .filter((v) => v.impact != null && FAILING_IMPACTS.has(v.impact))
    .flatMap((v) => v.nodes.map((n) => keyOf(v.id, selectorOf(n.target))));
}

export type Classified = {
  /** Failing nodes nobody has recorded: these fail the run. */
  unknown: string[];
  /** Failing nodes the known file lists: reported in the summary, not failed. */
  known: string[];
  /** Known entries of this screen that did not occur: these fail the run, to keep the file honest. */
  stale: string[];
};

export function classify(failing: readonly string[], known: readonly KnownFailure[], screen: string): Classified {
  const mine = known.filter((k) => k.screen === screen);
  const listed = new Set(mine.map((k) => keyOf(k.rule, k.selector)));
  const seen = new Set(failing);
  return {
    unknown: failing.filter((f) => !listed.has(f)),
    known: failing.filter((f) => listed.has(f)),
    stale: [...listed].filter((k) => !seen.has(k)),
  };
}

/** The file may be absent or empty before any known failure exists; anything else malformed is an error, not "no entries". */
export function parseKnown(text: string | null): KnownFailure[] {
  if (text === null || text.trim() === "") return [];
  const data: unknown = JSON.parse(text);
  if (!Array.isArray(data)) throw new Error("axe-known.json must be an array");
  return data.map((entry, i) => {
    const e = entry as Partial<KnownFailure>;
    if (typeof e?.rule !== "string" || typeof e.selector !== "string" || typeof e.screen !== "string") {
      throw new Error(`axe-known.json entry ${i} needs a string rule, selector and screen`);
    }
    return {rule: e.rule, selector: e.selector, screen: e.screen, ...(typeof e.note === "string" ? {note: e.note} : {})};
  });
}

// --- the accent pair ---------------------------------------------------------------------------

export type Rgb = [number, number, number];

const linear = (v: number) => {
  const c = v / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};
const luminance = ([r, g, b]: Rgb) => 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);

/** WCAG 2.x contrast ratio of two sRGB colours. */
export function contrastRatio(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

/** DESIGN.md: `#010D16` on `#04B5FB`, 8.42. Dark text on the accent is a fixed rule of the project. */
export const ACCENT_BG: Rgb = [0x04, 0xb5, 0xfb];
export const ACCENT_FG: Rgb = [0x01, 0x0d, 0x16];
export const ACCENT_RATIO = 8.42;

/** What is wrong with the accent pair as computed in a page, or null when it is right. */
export function accentProblem(bg: Rgb, fg: Rgb): string | null {
  // A channel may be off by one: the browser rounds oklch to 8 bits, and the token is the colour, not the hex.
  const near = (a: Rgb, b: Rgb) => a.every((v, i) => Math.abs(v - b[i]!) <= 1);
  if (!near(bg, ACCENT_BG)) return `the accent is rgb(${bg.join(",")}), not rgb(${ACCENT_BG.join(",")})`;
  if (!near(fg, ACCENT_FG)) return `the text on the accent is rgb(${fg.join(",")}), not rgb(${ACCENT_FG.join(",")}): it must be dark`;
  const ratio = contrastRatio(bg, fg);
  if (Math.abs(ratio - ACCENT_RATIO) > 0.05) return `the accent pair has contrast ${ratio.toFixed(2)}, not ${ACCENT_RATIO}`;
  return null;
}

// --- a defect of a library, found by the region it sits in -------------------------------------------

/**
 * A failure that a library's own element causes, listed by the region it sits in and not by a selector: React
 * Aria's live announcer is `role="log"` holding an empty `role="img"` whose `aria-labelledby` points at nothing,
 * and its selector carries a random id, so no line of `axe-known.json` could ever match it twice (wp8-r5-5).
 */
export type LibraryDefect = {
  rule: string;
  within: string;
  /**
   * The element that carries the defect. The region alone is not enough to expect the failure: React Aria's log
   * is on the page from the first announcement and holds the empty image only after a button went pending.
   */
  element: string;
  note: string;
  /**
   * Rules whose `incomplete` result on a node inside the region is this same defect, so it is reported as known and not as a node left to
   * a manual look. React Aria's announcer is both a `role-img-alt` failure and an `aria-valid-attr-value` one that axe cannot decide (the
   * id its `aria-labelledby` names is gone by the time axe looks), and it is one element.
   */
  alsoIncomplete?: readonly string[];
};

/**
 * React Aria's live announcer: `role="log"` holding an empty `role="img"` whose `aria-labelledby` names an element that is no longer there.
 * A Button with `isPending` creates it the first time a form is submitted. It is the library's element, inert (a screen reader reads the
 * announcement from the log, not from the image), and its selector holds a random id, so it is listed by region (wp8-r5-5). The one entry
 * for every matrix spec, so the three of them cannot drift apart.
 */
export const LIVE_ANNOUNCER: LibraryDefect = {
  rule: "role-img-alt",
  within: '[role="log"]',
  element: '[role="img"]',
  note: "React Aria live announcer: an empty role=img with a dangling aria-labelledby",
  alsoIncomplete: ["aria-valid-attr-value"],
};

/**
 * The attribute that marks, right before axe runs, every element that sits inside the region of a library defect. Axe hands back the
 * markup of a node as it was when it analysed it, so the region is read from that markup and never from the live page afterwards:
 * React Aria removes its announcer 7 seconds after an announcement, which on a loaded machine is between the analysis and a second look
 * at the page (gate-r2-12, gate-r2-20). The value is the indices of the defects whose region contains the element, space separated.
 */
export const REGION_ATTR = "data-ctrlz-region";

/**
 * The same kind of mark, for the element itself: the indices of the defects whose `element` this node is, inside their region. A region
 * mark says "somewhere in the log"; a node that axe cannot decide counts as the known defect only when it is the defective element, so an
 * undecided node of an app-owned `role="log"` is still left to a look (P1 gate).
 */
export const ELEMENT_ATTR = "data-ctrlz-defect";

function marked(html: string, attr: string, defects: readonly LibraryDefect[]): LibraryDefect[] {
  const value = new RegExp(`\\s${attr}="([0-9 ]*)"`).exec(html)?.[1];
  if (!value) return [];
  const found = new Set<LibraryDefect>();
  for (const index of value.split(" ")) {
    const defect = defects[Number(index)];
    if (index !== "" && defect) found.add(defect);
  }
  return [...found];
}

/** The `within` selectors of the defects that the marked markup of an axe node says it sits in. */
export function regionsOfHtml(html: string, defects: readonly LibraryDefect[]): string[] {
  return [...new Set(marked(html, REGION_ATTR, defects).map((d) => d.within))];
}

/**
 * The undecided nodes of one rule, split into those that are a library defect already reported (the node is the defective element of a
 * defect that names this rule in `alsoIncomplete`, inside its region, read from the marked markup like regionsOfHtml) and those left to a
 * manual look. Sitting in the region is not enough: that would hide an undecided node of anything else inside the same region.
 */
export function splitIncomplete(
  rule: string,
  nodes: readonly {html: string; target: readonly unknown[]}[],
  defects: readonly LibraryDefect[],
): {covered: number; own: number} {
  let covered = 0;
  for (const n of nodes) {
    // A target that is not one plain selector (a shadow root, a frame) is never a library defect, as with a failure.
    const plain = n.target.length === 1 && typeof n.target[0] === "string";
    if (plain && marked(n.html, ELEMENT_ATTR, defects).some((d) => d.alsoIncomplete?.includes(rule))) covered++;
  }
  return {covered, own: nodes.length - covered};
}

export type DefectNode = {rule: string; selector: string; /** The `within` selectors of the defects that contain this node. */ inside: readonly string[]};

export type DefectSplit = {
  /** Nodes no defect covers: these go through the known file as before. */
  rest: string[];
  /** Nodes a defect covers: reported in the run summary, not failed. */
  covered: string[];
  /** A defect whose element is on the page and holds no such node: the library fixed it, so the entry must go. */
  stale: string[];
};

export function splitLibraryDefects(nodes: readonly DefectNode[], defects: readonly LibraryDefect[], present: ReadonlySet<string>): DefectSplit {
  const rest: string[] = [];
  const covered: string[] = [];
  const hit = new Set<LibraryDefect>();
  for (const n of nodes) {
    const defect = defects.find((d) => d.rule === n.rule && n.inside.includes(d.within));
    if (defect) {
      hit.add(defect);
      covered.push(keyOf(n.rule, n.selector));
    } else rest.push(keyOf(n.rule, n.selector));
  }
  const stale = defects.filter((d) => present.has(d.within) && !hit.has(d)).map((d) => `${d.rule} within ${d.within}`);
  return {rest, covered, stale};
}
