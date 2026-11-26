import type {Rule} from "eslint";

import type {Ban} from "../bans.ts";

/** A loose view of an ESTree node: the rules read a few fields by name and never build nodes, and ESLint's own node types do not model JSX. */
export type Node = any; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A rule made of selectors, so `eslint.config.mjs` can turn one ban off for one file. */
export function selectorRule(description: string, bans: Ban[]): Rule.RuleModule {
  return {
    meta: {type: "problem", docs: {description}, schema: [], messages: {banned: "{{message}}"}},
    create(context) {
      const listeners: Record<string, (node: Rule.Node) => void> = {};
      for (const {selector, message} of bans) {
        listeners[selector] = (node) => context.report({node, messageId: "banned", data: {message}});
      }
      return listeners;
    },
  };
}

/** The ancestors of `node`, nearest first. */
export function ancestors(node: Node): Node[] {
  const out: Node[] = [];
  for (let p = node.parent as Node | null | undefined; p; p = p.parent as Node | null | undefined) out.push(p);
  return out;
}

/** The name of a JSX element: `Button`, or the root of `Dropdown.Item`. */
export function jsxRootName(name: Node | undefined): string | null {
  let n = name;
  while (n && n.type === "JSXMemberExpression") n = n.object;
  return n && n.type === "JSXIdentifier" ? n.name : null;
}
