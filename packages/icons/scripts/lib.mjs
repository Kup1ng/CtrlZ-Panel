// Pure helpers for scripts/build.mjs: a small SVG parser, the validators of spec
// 7.3, and the component generator. No dependencies, so the build runs before
// anything is bundled and the tests can import it directly.

const SVG_NS = "http://www.w3.org/2000/svg";

// Anything that can run code, load another file or hide behind a reference.
const BANNED_ELEMENTS = new Set(["image", "script", "style", "use", "foreignobject", "iframe", "a", "animate", "set"]);

const SHAPE_ATTRS = {
  path: ["d"],
  circle: ["cx", "cy", "r"],
  rect: ["x", "y", "width", "height", "rx", "ry"],
  ellipse: ["cx", "cy", "rx", "ry"],
  line: ["x1", "y1", "x2", "y2"],
  polyline: ["points"],
  polygon: ["points"],
  g: [],
};
const PAINT_ATTRS = ["fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin"];
// Brand marks and service logos keep their own colours and may use fill rules.
const LOOSE_PAINT_ATTRS = [...PAINT_ATTRS, "fill-rule", "clip-rule", "fill-opacity", "opacity"];

const PATH_DATA = /^[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\-\s]+$/;
const POINTS_DATA = /^[0-9eE.,+\-\s]+$/;
const NUMBER = /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;

/**
 * @typedef {{name: string, attrs: Record<string, string>, children: Node[], text: string}} Node
 */

/** Parses the small subset of XML an icon may use. Throws a plain Error on anything else. */
export function parseSvg(source) {
  let text = source.replace(/<!--[\s\S]*?-->/g, "");
  if (/<\?|<!/.test(text)) throw new Error("XML declarations, doctypes and CDATA are not allowed");
  /** @type {Node[]} */
  const stack = [];
  /** @type {Node | null} */
  let root = null;
  const tag = /<\s*(\/)?\s*([A-Za-z][\w:.-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/)?\s*>/g;
  let last = 0;
  let m;
  while ((m = tag.exec(text))) {
    const between = text.slice(last, m.index);
    if (between.trim() !== "") {
      const top = stack[stack.length - 1];
      if (!top) throw new Error("text outside the root element");
      top.text += between;
    }
    last = tag.lastIndex;
    const [, closing, name, rawAttrs, selfClose] = m;
    if (closing) {
      const open = stack.pop();
      if (!open || open.name !== name) throw new Error(`unbalanced </${name}>`);
      continue;
    }
    const attrs = parseAttrs(rawAttrs ?? "", name);
    /** @type {Node} */
    const node = {name, attrs, children: [], text: ""};
    const parent = stack[stack.length - 1];
    if (parent) parent.children.push(node);
    else if (root) throw new Error("more than one root element");
    else root = node;
    if (!selfClose) stack.push(node);
  }
  if (text.slice(last).trim() !== "") throw new Error("text outside the root element");
  if (stack.length) throw new Error(`<${stack[stack.length - 1].name}> is never closed`);
  if (!root) throw new Error("no <svg> element");
  return root;
}

function parseAttrs(raw, element) {
  const attrs = {};
  const re = /([A-Za-z_:][\w:.-]*)\s*=\s*"([^"]*)"/g;
  let rest = raw;
  let m;
  while ((m = re.exec(raw))) {
    if (Object.hasOwn(attrs, m[1])) throw new Error(`<${element}> repeats attribute ${m[1]}`);
    attrs[m[1]] = m[2];
    rest = rest.replace(m[0], "");
  }
  if (rest.trim() !== "") throw new Error(`<${element}> has an attribute that is not name="value": ${rest.trim()}`);
  return attrs;
}

function walk(node, fn) {
  fn(node);
  for (const child of node.children) walk(child, fn);
}

/**
 * Validates an icon from svg/<group>/<name>.svg against spec 7.3.
 * Returns a list of problems, empty when the file is fine.
 */
export function validateIconSvg(source) {
  const errors = [];
  let root;
  try {
    root = parseSvg(source);
  } catch (e) {
    return [e.message];
  }
  if (root.name !== "svg") return [`root element is <${root.name}>, not <svg>`];

  const rootRequired = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "1.5",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
  };
  for (const [k, v] of Object.entries(rootRequired)) {
    if (root.attrs[k] === undefined) errors.push(`<svg> lacks ${k}="${v}"`);
    else if (root.attrs[k] !== v) errors.push(`<svg> has ${k}="${root.attrs[k]}", expected "${v}"`);
  }
  for (const k of Object.keys(root.attrs)) {
    if (k === "xmlns") {
      if (root.attrs[k] !== SVG_NS) errors.push(`xmlns must be the SVG namespace`);
    } else if (!(k in rootRequired)) {
      errors.push(`<svg> must not set ${k}; size comes from CSS`);
    }
  }

  walk(root, (node) => {
    const lower = node.name.toLowerCase();
    if (BANNED_ELEMENTS.has(lower)) {
      errors.push(`<${node.name}> is not allowed`);
      return;
    }
    if (node.text.trim() !== "") errors.push(`<${node.name}> holds text`);
    if (node === root) return;
    const shape = SHAPE_ATTRS[node.name];
    if (!shape) {
      errors.push(`<${node.name}> is not allowed; use path, circle, rect, ellipse, line, polyline, polygon or g`);
      return;
    }
    for (const [k, v] of Object.entries(node.attrs)) {
      if (k === "id") errors.push(`<${node.name}> has an id`);
      else if (/^(xlink:)?href$/i.test(k)) errors.push(`<${node.name}> has ${k}`);
      else if (/^on/i.test(k)) errors.push(`<${node.name}> has an event handler ${k}`);
      else if (k === "fill" || k === "stroke") {
        if (v !== "currentColor" && v !== "none") errors.push(`<${node.name}> ${k}="${v}": only currentColor or none`);
      } else if (k === "stroke-width") {
        if (v !== "1.5") errors.push(`<${node.name}> stroke-width="${v}": only 1.5`);
      } else if (k === "stroke-linecap" || k === "stroke-linejoin") {
        if (v !== "round") errors.push(`<${node.name}> ${k}="${v}": only round`);
      } else if (!shape.includes(k)) {
        errors.push(`<${node.name}> has ${k}, which is not allowed here`);
      } else if (k === "d") {
        if (!PATH_DATA.test(v)) errors.push(`<path> d holds a character that path data does not use`);
      } else if (k === "points") {
        if (!POINTS_DATA.test(v)) errors.push(`<${node.name}> points holds a bad character`);
      } else if (!NUMBER.test(v)) {
        errors.push(`<${node.name}> ${k}="${v}" is not a plain number`);
      }
    }
  });

  // Last, a blunt scan. The namespace is the one place "http" is legitimate.
  const withoutNs = source.replace(`xmlns="${SVG_NS}"`, "");
  if (/http/i.test(withoutNs)) errors.push(`contains "http"`);
  if (/javascript:/i.test(source)) errors.push(`contains "javascript:"`);
  return errors;
}

/**
 * Validates a brand mark or a service logo. These keep their own colours, so
 * this checks only what could run code or reach the network.
 */
export function validateLooseSvg(source) {
  const errors = [];
  let root;
  try {
    root = parseSvg(source);
  } catch (e) {
    return [e.message];
  }
  if (root.name !== "svg") return [`root element is <${root.name}>, not <svg>`];
  if (!root.attrs.viewBox || !/^0 0 \d+(\.\d+)? \d+(\.\d+)?$/.test(root.attrs.viewBox)) {
    errors.push(`<svg> needs a viewBox that starts at 0 0`);
  }
  walk(root, (node) => {
    const lower = node.name.toLowerCase();
    if (BANNED_ELEMENTS.has(lower)) {
      errors.push(`<${node.name}> is not allowed`);
      return;
    }
    for (const [k, v] of Object.entries(node.attrs)) {
      if (k === "id") errors.push(`<${node.name}> has an id`);
      else if (/^(xlink:)?href$/i.test(k)) errors.push(`<${node.name}> has ${k}`);
      else if (/^on/i.test(k)) errors.push(`<${node.name}> has an event handler ${k}`);
      else if (/url\(/i.test(v)) errors.push(`<${node.name}> ${k} refers to url()`);
    }
    if (node === root) {
      for (const k of Object.keys(node.attrs)) {
        if (!["viewBox", "fill", "xmlns", "width", "height", "role", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin"].includes(k)) {
          errors.push(`<svg> has ${k}, which is not allowed`);
        }
      }
      return;
    }
    if (node.name === "title") return;
    const shape = SHAPE_ATTRS[node.name];
    if (!shape) {
      errors.push(`<${node.name}> is not allowed`);
      return;
    }
    for (const k of Object.keys(node.attrs)) {
      if (!shape.includes(k) && !LOOSE_PAINT_ATTRS.includes(k)) errors.push(`<${node.name}> has ${k}, which is not allowed here`);
    }
    if (node.attrs.d !== undefined && !PATH_DATA.test(node.attrs.d)) errors.push(`<path> d holds a bad character`);
  });
  const withoutNs = source.replace(`xmlns="${SVG_NS}"`, "");
  if (/http/i.test(withoutNs)) errors.push(`contains "http"`);
  if (/javascript:/i.test(source)) errors.push(`contains "javascript:"`);
  return errors;
}

/** `ads-trackers` to `AdsTrackers`. */
export function pascal(slug) {
  return slug
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");
}

const jsxName = (attr) => attr.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

function jsxNode(node, depth) {
  const pad = "  ".repeat(depth);
  const attrs = Object.entries(node.attrs)
    .map(([k, v]) => ` ${jsxName(k)}="${v}"`)
    .join("");
  if (node.children.length === 0) return `${pad}<${node.name}${attrs} />`;
  return `${pad}<${node.name}${attrs}>\n${node.children.map((c) => jsxNode(c, depth + 1)).join("\n")}\n${pad}</${node.name}>`;
}

/**
 * One forwardRef component per SVG. The root attributes are re-stated here, not
 * copied from the file, so a file cannot smuggle in anything the validator did
 * not look at. `{...props}` comes last so a caller can still override.
 */
export function componentSource({exportName, sourcePath, svg, brand}) {
  const root = parseSvg(svg);
  const rootAttrs = brand
    ? `viewBox="${root.attrs.viewBox}" fill="${root.attrs.fill ?? "none"}"`
    : `viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"`;
  const children = root.children
    .filter((c) => c.name !== "title")
    .map((c) => jsxNode(c, 3))
    .join("\n");
  return `// GENERATED by scripts/build.mjs from ${sourcePath}. Do not edit.
import {forwardRef} from "react";
import type {SVGProps} from "react";

export const ${exportName} = forwardRef<SVGSVGElement, SVGProps<SVGSVGElement>>(function ${exportName}(props, ref) {
  // Decorative unless the caller names it. An icon next to text must not be read twice.
  const named = props["aria-label"] !== undefined || props["aria-labelledby"] !== undefined;
  return (
    <svg
      ref={ref}
      ${rootAttrs}
      width="1em"
      height="1em"
      focusable="false"
      aria-hidden={named ? undefined : true}
      role={named ? "img" : undefined}
      {...props}
    >
${children}
    </svg>
  );
});
`;
}

/** The generated registry: slug to component, per group, with types derived from it. */
export function registrySource(groups) {
  const lines = [`// GENERATED by scripts/build.mjs. Do not edit.`, `import type {ForwardRefExoticComponent, RefAttributes, SVGProps} from "react";`, ``];
  for (const [group, names] of groups) {
    for (const name of names) lines.push(`import {${pascal(name)} as ${pascal(group)}${pascal(name)}} from "./${group}/${pascal(name)}.tsx";`);
  }
  lines.push(
    ``,
    `export type IconComponent = ForwardRefExoticComponent<SVGProps<SVGSVGElement> & RefAttributes<SVGSVGElement>>;`,
    ``,
  );
  for (const [group, names] of groups) {
    lines.push(`export const ${group}Icons = {`);
    for (const name of names) lines.push(`  ${JSON.stringify(name)}: ${pascal(group)}${pascal(name)},`);
    lines.push(`} as const satisfies Record<string, IconComponent>;`, ``);
  }
  lines.push(`export const registry = {`);
  for (const [group] of groups) lines.push(`  ${group}: ${group}Icons,`);
  lines.push(
    `} as const;`,
    ``,
    `export type IconGroup = keyof typeof registry;`,
    `export type IconName<G extends IconGroup> = keyof (typeof registry)[G];`,
    ``,
  );
  return lines.join("\n");
}

/** Provenance rows: `| file | author | date | method |`. */
export function parseProvenance(markdown) {
  const rows = new Map();
  for (const line of markdown.split(/\r?\n/)) {
    if (!line.startsWith("|")) continue;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length !== 4) continue;
    const file = cells[0].replace(/^`|`$/g, "");
    if (!/^(svg|brand)\//.test(file)) continue;
    rows.set(file, {author: cells[1], date: cells[2], method: cells[3]});
  }
  return rows;
}

export const METHOD = {svg: "drawn from scratch", brand: "supplied by the owner"};
