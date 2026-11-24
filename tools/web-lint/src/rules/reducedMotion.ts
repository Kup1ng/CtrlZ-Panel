import type {Rule} from "eslint";

import {ancestors, jsxRootName, type Node} from "./helpers.ts";

// Spec 16.1, `ctrlz/reduced-motion` (T-465): a class that moves something needs a partner for people
// who asked for less motion. The partner is a `motion-reduce:` token in the same place as the moving
// class, or the moving class itself sits behind `motion-safe:`. "The same place" is the nearest
// enclosing attribute, object property, variable or return, so
// `cn("transition", x && "motion-reduce:transition-none")` and a `tv` slot each count as one place.
// Spinner and Skeleton animate by design and are exempt by name.

// A class token, with any variants in front of it: `hover:md:transition-colors`.
const TOKEN = /(?:^|\s)((?:[^\s:]+:)*)(!?)(animate-\S+|transition(?:-\S+)?)(?=\s|$)/g;
const REDUCE_TOKEN = /(?:^|\s)(?:[^\s:]+:)*motion-reduce:\S+/;
const EXEMPT_ELEMENTS = new Set(["Spinner", "Skeleton"]);
const PLACES = new Set(["JSXAttribute", "Property", "VariableDeclarator", "ReturnStatement", "ExportDefaultDeclaration", "ExpressionStatement"]);

/** The moving tokens of a class string that nothing in the string itself excuses. */
function movingTokens(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(TOKEN)) {
    const [, variants = "", , name = ""] = m;
    if (name === "transition-none" || name === "animate-none") continue;
    // motion-safe:transition-x only moves for people who did not ask for less.
    if (variants.split(":").includes("motion-safe") || variants.split(":").includes("motion-reduce")) continue;
    out.push(`${variants}${name}`);
  }
  return out;
}

export const reducedMotion: Rule.RuleModule = {
  meta: {
    type: "problem",
    docs: {description: "animate-* and transition* classes come with a motion-reduce: partner"},
    schema: [],
    messages: {
      motion: "`{{token}}` moves something and has no `motion-reduce:` partner in the same class list (T-465). Add `motion-reduce:transition-none` or `motion-reduce:animate-none`.",
    },
  },
  create(context) {
    type Place = {moving: {node: Node; token: string}[]; reduced: boolean};
    const places = new Map<Node, Place>();

    function visit(node: Node, text: string) {
      const moving = movingTokens(text);
      const reduced = REDUCE_TOKEN.test(text);
      if (moving.length === 0 && !reduced) return;
      const chain = ancestors(node);
      // The nearest opening element owns the attribute that holds this string.
      const owner = chain.find((a) => a.type === "JSXOpeningElement");
      if (owner && EXEMPT_ELEMENTS.has(jsxRootName(owner.name) ?? "")) return;
      const place = chain.find((a) => PLACES.has(a.type)) ?? node;
      const entry = places.get(place) ?? {moving: [], reduced: false};
      for (const token of moving) entry.moving.push({node, token});
      if (reduced) entry.reduced = true;
      places.set(place, entry);
    }

    return {
      Literal(node: Node) {
        if (typeof node.value === "string") visit(node, node.value);
      },
      TemplateElement(node: Node) {
        visit(node, node.value.cooked ?? "");
      },
      "Program:exit"() {
        for (const {moving, reduced} of places.values()) {
          if (reduced) continue;
          for (const {node, token} of moving) context.report({node, messageId: "motion", data: {token}});
        }
      },
    };
  },
};
