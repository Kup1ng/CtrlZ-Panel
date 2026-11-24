import type {Rule} from "eslint";

import {ancestors, jsxRootName, type Node} from "./helpers.ts";

// Spec 16.1, `ctrlz/no-raw-text`: every word the user reads comes from the fa and en messages, so a
// letter in JSX text, or in a string that becomes an accessible name, is a missing translation.
// `<Tech>` holds domains, IPs and other tokens that are the same in both languages.
const TEXT_PROPS = new Set(["aria-label", "title", "alt", "placeholder", "label"]);
const LETTER = /\p{L}/u;

const inTech = (node: Node) => ancestors(node).some((a) => a.type === "JSXElement" && jsxRootName(a.openingElement.name) === "Tech");

/** The string parts of an expression that would be shown as it is: a literal, a template, either branch of a condition. */
function shownStrings(expr: Node | null | undefined): Node[] {
  if (!expr) return [];
  switch (expr.type) {
    case "Literal":
      return typeof expr.value === "string" ? [expr] : [];
    case "TemplateLiteral":
      return expr.quasis;
    case "ConditionalExpression":
      return [...shownStrings(expr.consequent), ...shownStrings(expr.alternate)];
    case "LogicalExpression":
      return [...shownStrings(expr.left), ...shownStrings(expr.right)];
    default:
      return [];
  }
}

const textOf = (node: Node) => (node.type === "TemplateElement" ? (node.value.cooked ?? "") : String(node.value));

export const noRawText: Rule.RuleModule = {
  meta: {
    type: "problem",
    docs: {description: "UI text comes from the messages, not from JSX text or string props"},
    schema: [],
    messages: {
      text: "Raw text in JSX. Every word the user reads comes from t() so it exists in fa and en. Technical tokens go in <Tech> (spec 16.1).",
      prop: "Raw text in `{{prop}}`. Use t() so it exists in fa and en (spec 16.1).",
    },
  },
  create(context) {
    return {
      JSXText(node: Node) {
        if (LETTER.test(node.value) && !inTech(node)) context.report({node, messageId: "text"});
      },
      JSXExpressionContainer(node: Node) {
        // A string child: {"Save"}. An attribute value is handled with its attribute below.
        if (node.parent.type !== "JSXElement" && node.parent.type !== "JSXFragment") return;
        if (inTech(node)) return;
        for (const s of shownStrings(node.expression)) if (LETTER.test(textOf(s))) context.report({node: s, messageId: "text"});
      },
      JSXAttribute(node: Node) {
        const prop = node.name.type === "JSXIdentifier" ? node.name.name : null;
        if (!prop || !TEXT_PROPS.has(prop) || !node.value) return;
        if (inTech(node)) return;
        const value = node.value.type === "JSXExpressionContainer" ? node.value.expression : node.value;
        for (const s of shownStrings(value)) {
          if (LETTER.test(textOf(s))) context.report({node: s, messageId: "prop", data: {prop}});
        }
      },
    };
  },
};
