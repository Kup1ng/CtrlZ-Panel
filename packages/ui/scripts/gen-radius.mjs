// Turns tokens/radius.table.ts into styles/radius.generated.css.
//
//   node packages/ui/scripts/gen-radius.mjs           write the file
//   node packages/ui/scripts/gen-radius.mjs --check   exit 1 if the committed file is stale (CI)
//
// Node 26 strips TypeScript types on import, so the table stays a typed .ts file
// that the app also imports, and this script needs no build step.
import {readFile, writeFile} from "node:fs/promises";
import {dirname, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tablePath = resolve(here, "../tokens/radius.table.ts");
const outPath = resolve(here, "../styles/radius.generated.css");

// Tailwind's `sm` and HeroUI's `md`. HeroUI switches control heights at md, but
// fields switch their text size at sm, so a row can name either.
const BREAKPOINTS = [
  ["sm", "40rem"],
  ["md", "48rem"],
];

const RADIUS = "min(calc(var(--control-h) * var(--radius-control-ratio)), var(--radius-control-cap))";

// HeroUI's sheet rules round one physical edge, so the box rows do too. The
// panel's side comes from useLogicalEdge, which already resolves to a physical
// side, and these corners match the physical class that was chosen.
const CORNERS = {
  all: "var(--radius-box)",
  top: "var(--radius-box) var(--radius-box) 0 0",
  bottom: "0 0 var(--radius-box) var(--radius-box)",
  left: "var(--radius-box) 0 0 var(--radius-box)",
  right: "0 var(--radius-box) var(--radius-box) 0",
};

// What an owner exception emits instead of the formula. Tailwind writes rounded-full the same way,
// so the computed value is the same huge number HeroUI's own pills have.
const SHAPES = {pill: "calc(infinity * 1px)"};

function exceptionBlock(row) {
  const {decision, shape} = row.exception;
  if (!SHAPES[shape]) throw new Error(`${row.selector}: unknown exception shape ${shape}`);
  // No --control-h: the shape does not depend on the height, and an unused variable would suggest it does.
  return `  ${row.selector} {
    ${row.radiusProp ?? "border-radius"}: ${SHAPES[shape]}; /* ${decision} */
  }`;
}

function controlBlock(row) {
  if (row.exception) return exceptionBlock(row);
  const radiusProp = row.radiusProp ?? "border-radius";
  const out = [];
  const body = (h) => {
    const lines = [`--control-h: ${h};`];
    return lines;
  };
  const base = body(row.height.base);
  if (row.setsHeight) base.push("height: var(--control-h);");
  base.push(`${radiusProp}: ${RADIUS};`);
  out.push(`  ${row.selector} {\n${base.map((l) => `    ${l}`).join("\n")}\n  }`);
  for (const [name, width] of BREAKPOINTS) {
    const h = row.height[name];
    if (h === undefined) continue;
    out.push(`  @media (width >= ${width}) {\n    ${row.selector} { --control-h: ${h}; }\n  }`);
  }
  return out.join("\n");
}

function boxBlock(row) {
  const lines = [`border-radius: ${CORNERS[row.corners ?? "all"]};`];
  // `clip`, never `hidden`: hidden makes a scroll container and stops sticky headers.
  if (row.clip) lines.push("overflow: clip;");
  return `  ${row.selector} {\n${lines.map((l) => `    ${l}`).join("\n")}\n  }`;
}

export async function render() {
  const {rows} = await import(pathToFileURL(tablePath).href);
  const seen = new Set();
  const blocks = [];
  for (const row of rows) {
    if (seen.has(row.selector)) throw new Error(`radius.table.ts: duplicate selector ${row.selector}`);
    seen.add(row.selector);
    if (row.pendingOwner) continue;
    if (row.kind === "control") {
      if (!row.height || row.height.base === undefined) throw new Error(`${row.selector}: a control row needs height.base`);
      blocks.push(`  /* ${row.source} */\n${controlBlock(row)}`);
    } else if (row.kind === "box") {
      blocks.push(`  /* ${row.source} */\n${boxBlock(row)}`);
    } else {
      throw new Error(`radius.table.ts: unknown kind on ${JSON.stringify(row)}`);
    }
  }
  return [
    "/* GENERATED from tokens/radius.table.ts by scripts/gen-radius.mjs. Do not edit. */",
    "/* It sits in @layer components after HeroUI's rules, so an equal-specificity rule here wins. */",
    "@layer components {",
    blocks.join("\n\n"),
    "}",
    "",
  ].join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const css = await render();
  if (process.argv.includes("--check")) {
    const current = await readFile(outPath, "utf8").catch(() => "");
    if (current !== css) {
      console.error("radius.generated.css is stale. Run: node packages/ui/scripts/gen-radius.mjs");
      process.exit(1);
    }
    console.log("radius.generated.css is up to date");
  } else {
    await writeFile(outPath, css);
    console.log(`wrote ${outPath}`);
  }
}
