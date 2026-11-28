import type {Rule} from "eslint";

import {jsxRootName, type Node} from "./helpers.ts";

// Spec 16.1, `ctrlz/use-on-press`: HeroUI components take `onPress`, which react-aria fires for
// mouse, touch, keyboard and screen readers alike. `onClick` on one of them is silently ignored
// or fires twice, and jsx-a11y cannot see it because the element is not a DOM button.
const HEROUI = /^@heroui(-pro)?\x2freact(\x2f|$)/;

export const useOnPress: Rule.RuleModule = {
  meta: {
    type: "problem",
    docs: {description: "No onClick on a HeroUI component"},
    schema: [],
    messages: {press: "`onClick` on <{{name}}>, a HeroUI component. Use `onPress` (react-aria fires it for every input, spec 16.1)."},
  },
  create(context) {
    const fromHeroUi = new Set<string>();
    return {
      ImportDeclaration(node: Node) {
        if (!HEROUI.test(String(node.source.value))) return;
        for (const spec of node.specifiers) fromHeroUi.add(spec.local.name);
      },
      JSXOpeningElement(node: Node) {
        const root = jsxRootName(node.name);
        if (!root || !fromHeroUi.has(root)) return;
        for (const attr of node.attributes) {
          if (attr.type === "JSXAttribute" && attr.name.type === "JSXIdentifier" && attr.name.name === "onClick") {
            context.report({node: attr, messageId: "press", data: {name: root}});
          }
        }
      },
    };
  },
};
