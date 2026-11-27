import type {Rule} from "eslint";

import type {Node} from "./helpers.ts";

// Spec 14.1, `ctrlz/no-next-fetch`: the web tier does no data fetching. A Server Component or a
// Route Handler that calls `fetch` would need a path from the web container to the API, which the
// network layout (AUTH 17.2) does not give it, and would hide the failure until production. Data
// comes from the browser to /api/v1 through Caddy. The config applies this rule to `app/` only.
const GLOBALS = new Set(["globalThis", "window", "self"]);

export const noNextFetch: Rule.RuleModule = {
  meta: {
    type: "problem",
    docs: {description: "No fetch in a Server Component or a Route Handler"},
    schema: [],
    messages: {fetch: "`fetch` in a Server Component or Route Handler. The web tier does no data fetching: call the API from the browser through the generated client (spec 14.1)."},
  },
  create(context) {
    let client = false;
    return {
      Program(node: Node) {
        client = node.body.some((s: Node) => s.type === "ExpressionStatement" && s.directive === "use client");
      },
      CallExpression(node: Node) {
        if (client) return;
        const c = node.callee;
        const direct = c.type === "Identifier" && c.name === "fetch";
        const viaGlobal = c.type === "MemberExpression" && c.object.type === "Identifier" && GLOBALS.has(c.object.name) && c.property.name === "fetch";
        if (direct || viaGlobal) context.report({node, messageId: "fetch"});
      },
    };
  },
};
