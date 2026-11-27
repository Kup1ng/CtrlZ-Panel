import {readFileSync} from "node:fs";
import {describe, expect, it} from "vitest";

// The status colours as text (wp8-r1-1, wp8-r1-2). `--danger`, `--warning` and `--success` are fills, and on a
// plain surface they fail 4.5:1 (dark danger 3.70, light warning 2.05, light success 2.3). Text uses the
// `-text` tokens, and this test measures them against every surface a message can sit on, in both themes, so
// a changed value or a new surface cannot slip under the line unseen. The class half: no component may spell
// `text-danger`, `text-warning` or `text-success`, which would bring the fill back as text.

const read = (name: string) => readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
const tokens = read("tokens.css");
const flat = read("flat.css");

function block(css: string, selector: string): string {
  const start = css.indexOf(`${selector} {`);
  if (start === -1) throw new Error(`no ${selector} block`);
  return css.slice(start, css.indexOf("\n}", start));
}

const declared = (css: string, name: string): string => {
  const m = new RegExp(`${name}:\s*([^;]+);`).exec(css);
  if (!m) throw new Error(`${name} not declared`);
  return m[1]!.trim();
};

type Rgb = [number, number, number];

function oklch(L: number, C: number, hue: number): Rgb {
  const a = C * Math.cos((hue * Math.PI) / 180);
  const b = C * Math.sin((hue * Math.PI) / 180);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const lin = [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s, -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s, -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s];
  return lin.map((v) => Math.min(1, Math.max(0, v))) as Rgb;
}

function hex(value: string): Rgb {
  return [1, 3, 5].map((i) => {
    const c = parseInt(value.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  }) as Rgb;
}

/** `#rrggbb` or `oklch(L% C h)`; a `var(--x)` is followed inside the same block. */
function colour(value: string, scope: string): Rgb {
  const v = /^var\((--[\w-]+)\)$/.exec(value);
  if (v) return colour(declared(scope, v[1]!), scope);
  if (value.startsWith("#")) return hex(value);
  const o = /^oklch\(\s*([\d.]+)(%?)\s+([\d.]+)\s+([\d.]+)\s*\)$/.exec(value);
  if (!o) throw new Error(`cannot read ${value}`);
  return oklch(o[2] ? Number(o[1]) / 100 : Number(o[1]), Number(o[3]), Number(o[4]));
}

const luminance = ([r, g, b]: Rgb) => 0.2126 * r + 0.7152 * g + 0.0722 * b;
const contrast = (x: Rgb, y: Rgb) => {
  const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
};

const themes = [
  {name: "flat-light", surfaces: ["--surface", "--surface-secondary", "--default", "--background", "--field-background"]},
  {name: "flat-dark", surfaces: ["--surface", "--surface-secondary", "--default", "--background", "--field-background", "--overlay"]},
];

for (const theme of themes) {
  describe(`${theme.name}: status text`, () => {
    const colours = block(tokens, `html.${theme.name}`);
    const surfaces = block(flat, `html.${theme.name}`);
    for (const token of ["--danger-text", "--warning-text", "--success-text"]) {
      for (const surface of theme.surfaces) {
        it(`${token} on ${surface} reaches 4.5:1`, () => {
          const fg = colour(declared(colours, token), colours);
          const bg = colour(declared(surfaces, surface), surfaces);
          expect(contrast(fg, bg)).toBeGreaterThanOrEqual(4.5);
        });
      }
    }
  });
}

describe("accent text on a secondary button under the pointer (light)", () => {
  it("--accent-soft-foreground reaches 4.5:1 on #e1e1e2, the fill the secondary button darkens to", () => {
    const colours = block(tokens, "html.flat-light");
    expect(contrast(colour(declared(colours, "--accent-soft-foreground"), colours), hex("#e1e1e2"))).toBeGreaterThanOrEqual(4.5);
  });
});

describe("the HeroUI error text follows the token", () => {
  it("overrides the field error and the invalid label, and leaves a toggle's error muted", () => {
    expect(tokens).toMatch(/\.field-error:not\(\.checkbox > \*, \.switch > \*, \.radio > \*\)/);
    expect(tokens).toMatch(/\.label--invalid[\s\S]*?color:\s*var\(--danger-text\)/);
  });
});

describe("the override stays narrow (wp8-r2-6)", () => {
  // The rule is unlayered, so it beats the theme layer on every screen of both apps. A descendant selector on
  // an invalid wrapper would also repaint the option labels of an invalid CheckboxGroup or RadioGroup.
  const rule = /(\.field-error[^{]*)\{\s*color:\s*var\(--danger-text\);?\s*\}/.exec(tokens)?.[1] ?? "";
  // A comma inside :not(...) does not end a selector.
  const selectors: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of rule) {
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (char === "," && depth === 0) {
      selectors.push(current.trim());
      current = "";
    } else current += char;
  }
  if (current.trim()) selectors.push(current.trim());

  it("finds the rule", () => {
    expect(selectors.length).toBe(4);
  });

  it("reaches a wrapper's label only as a direct child, and never a toggle's option label", () => {
    for (const selector of selectors) {
      if (/^\[(data|aria)-invalid=/.test(selector)) expect(selector, selector).toMatch(/^\[(data|aria)-invalid="true"\] > \.label$/);
    }
    const byClass = selectors.find((s) => s.startsWith(".label--invalid")) ?? "";
    expect(byClass).toContain(":not(.checkbox *, .switch *, .radio *)");
  });
});

describe("no component spells the fill as text", () => {
  it("has no text-danger, text-warning or text-success in the UI sources", async () => {
    const {globSync, readFileSync: rf} = await import("node:fs");
    const root = new URL("../src/", import.meta.url);
    const offenders: string[] = [];
    for (const file of globSync("**/*.tsx", {cwd: root})) {
      if (file.endsWith(".test.tsx")) continue;
      const text = rf(new URL(file, root), "utf8");
      if (/\btext-(danger|warning|success)\b(?!-)/.test(text)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});

describe("a tertiary button keeps its own text colour inside a dialog (gate-r7-8)", () => {
  // The body of a dialog is muted text, and a tertiary button takes currentColor from it unless the rule below names a colour. On the fill that
  // the button darkens to under the pointer this was 4.22:1 in the light theme. The test reads the rule, then measures the colour it names (HeroUI's
  // `--default-foreground` is `--eclipse` in light and `--snow` in dark) against the rest fill and the hover fill of each theme, and also measures
  // the muted text that the button used to inherit, so the day the muted token changes enough to pass again the rule is still needed or not, in view.
  const rule = /\.button--tertiary\s*\{\s*--button-fg:\s*var\(--default-foreground\);?\s*\}/;
  const ECLIPSE = oklch(0.2103, 0.0059, 285.89);
  const SNOW = oklch(0.9911, 0, 0);

  it("names a foreground, unlayered, in tokens.css", () => {
    expect(tokens).toMatch(rule);
  });

  for (const [name, fg, fills] of [
    ["flat-light", ECLIPSE, ["--default", "#e1e1e2"]],
    ["flat-dark", SNOW, ["--default", "--default"]],
  ] as const) {
    it(`${name}: the foreground reaches 4.5:1 on the fill and on the hover fill`, () => {
      const surfaces = block(flat, `html.${name}`);
      for (const fill of fills) {
        const bg = fill.startsWith("#") ? hex(fill) : colour(declared(surfaces, fill), surfaces);
        expect(contrast(fg, bg), `${name} on ${fill}`).toBeGreaterThanOrEqual(4.5);
      }
    });
  }

  it("the muted text that it used to inherit is below 4.5:1 on the light hover fill", () => {
    const colours = block(tokens, "html.flat-light");
    expect(contrast(colour(declared(colours, "--muted"), colours), hex("#e1e1e2"))).toBeLessThan(4.5);
  });
});

describe("the number of the active step is not drawn in the accent (P1 gate)", () => {
  // HeroUI Pro colours it with `--stepper-active-color`, the accent: 2.33:1 on white, ten pixels of text, which axe leaves as "incomplete"
  // because the text is too short for it to decide. The painted contrast is measured in a browser by apps/panel/e2e/contrast.spec.ts; this
  // holds the rule that makes it pass, and the accent number that makes it needed.
  it("names the foreground, unlayered, in tokens.css", () => {
    expect(tokens).toMatch(/\.stepper__indicator\[data-status="active"\]\s*\{(?:[^}]*;)?\s*color:\s*var\(--foreground\);/);
  });

  it("names the foreground for the ring too, which shows the current step and needs 3:1 (WCAG 1.4.11)", () => {
    expect(tokens).toMatch(/\.stepper__indicator\[data-status="active"\]\s*\{[^}]*\bborder-color:\s*var\(--foreground\);/);
  });

  it("the accent on a white surface is below 4.5:1, so the stock colour could not stay", () => {
    const colours = block(tokens, "html.flat-light");
    expect(contrast(colour(declared(colours, "--accent"), colours), hex("#ffffff"))).toBeLessThan(4.5);
  });
});
