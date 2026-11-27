// Turns a selector of tokens/radius.table.ts into the smallest markup that matches it, for the rows whose
// sample the token lab does not draw with a real component (a popover, a sheet, our own tiles). The result is
// plain data, so a test can read it without a browser. The class names are the point: the stylesheet decides
// what the element looks like, which is the thing the radius test measures.
//
// Supported shapes, which are the ones the table uses: `.a`, `.a.b`, `.a .b` (descendant), `.a, .b` (a list),
// `[name]`, `[name=value]` and `:has(<selector>)`. Anything else throws, so a new row with a new kind of
// selector fails the unit test instead of silently drawing the wrong thing.

export type BareNode = {classes: string[]; attrs: Record<string, string>; children: BareNode[]};

/** Splits on `sep` outside (...) and [...]. */
function splitTop(source: string, sep: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of source) {
    if (ch === "(" || ch === "[") depth++;
    if (ch === ")" || ch === "]") depth--;
    if (depth === 0 && ch === sep) {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

// A descendant combinator is whitespace, so a space inside :has(...) or [...] must not split.
function splitDescendants(source: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of source) {
    if (ch === "(" || ch === "[") depth++;
    if (ch === ")" || ch === "]") depth--;
    if (depth === 0 && /\s/.test(ch)) {
      if (cur) parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur) parts.push(cur);
  return parts;
}

function parseCompound(source: string): BareNode {
  const node: BareNode = {classes: [], attrs: {}, children: []};
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === ".") {
      const m = /^\.([A-Za-z0-9_-]+)/.exec(source.slice(i));
      if (!m) throw new Error(`bad class in "${source}"`);
      node.classes.push(m[1]!);
      i += m[0].length;
    } else if (ch === "[") {
      const end = source.indexOf("]", i);
      if (end < 0) throw new Error(`unclosed [ in "${source}"`);
      const inner = source.slice(i + 1, end);
      const eq = inner.indexOf("=");
      if (eq < 0) node.attrs[inner] = "";
      else node.attrs[inner.slice(0, eq)] = inner.slice(eq + 1).replace(/^["']|["']$/g, "");
      i = end + 1;
    } else if (source.startsWith(":has(", i)) {
      let depth = 0;
      let j = i + 4;
      for (; j < source.length; j++) {
        if (source[j] === "(") depth++;
        if (source[j] === ")" && --depth === 0) break;
      }
      if (depth !== 0) throw new Error(`unclosed :has( in "${source}"`);
      node.children.push(...parseChain(source.slice(i + 5, j)));
      i = j + 1;
    } else {
      throw new Error(`unsupported selector part "${source.slice(i)}" in "${source}"`);
    }
  }
  if (node.classes.length === 0 && Object.keys(node.attrs).length === 0) throw new Error(`empty compound in "${source}"`);
  return node;
}

/** One descendant chain, `.a .b .c`, as the roots it holds: a single root whose last descendant is `.c`. */
function parseChain(source: string): BareNode[] {
  const nodes = splitDescendants(source).map(parseCompound);
  // The target of the chain is its last compound, so :has() children of an earlier one stay beside it.
  for (let k = 0; k < nodes.length - 1; k++) nodes[k]!.children.push(nodes[k + 1]!);
  return nodes.length ? [nodes[0]!] : [];
}

/** One root per alternative of a comma list. The element that matches the selector is the deepest descendant of each. */
export function bareMarkup(selector: string): BareNode[] {
  return splitTop(selector, ",").flatMap(parseChain);
}
