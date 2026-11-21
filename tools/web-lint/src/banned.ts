// The bans of spec 16.1 that ESLint's own `no-restricted-imports` and `no-restricted-syntax`
// can carry, so they need no plugin. eslint.config.mjs imports this file and test/banned.test.ts
// runs the same lists against one passing and one failing sample each, because a rule that
// silently never fires is worse than none (spec 16.1).
//
// The class-string rules look at string literals and template text. A bare `left` in a class
// string is wrong for the same reason as a bare `left` in a `placement` prop: Persian is the
// default, and a physical edge is the wrong edge in RTL.

export type Restriction = {selector: string; message: string; tag: "placement" | "class" | "dark" | "url" | "intl" | "script"};

// A class token written with a physical edge. `rounded-lg` and `border-light` do not match,
// because the edge letter must be followed by `-`, a space or the end.
//
// The patterns are regex literals whose `.source` is pasted into the selector. A string
// literal would need every backslash doubled, and a missed one turns `\s` into a plain `s`
// without any error, so the rule would silently never fire.
const EDGE_START = String.raw`(^|[\s:!\["'\x60])`;
const PHYSICAL_CLASS = new RegExp(
  [
    `${EDGE_START}-?(ml|mr|pl|pr|left|right|scroll-ml|scroll-mr|scroll-pl|scroll-pr)-`,
    `${EDGE_START}(text|float|clear)-(left|right)(\\s|$)`,
    `${EDGE_START}(border|rounded)-(l|r|tl|tr|bl|br)(-|\\s|$)`,
  ].join("|"),
).source;

const DARK_VARIANT = new RegExp(`${EDGE_START}dark:`).source;

const PLACEMENT = /(^|\s)(left|right)(\s|$)/.source;

// esquery ends a regex at the first slash and has no escape for one, so the slashes of a URL
// are written as their hex code.
const URL_IN_TEXT = /(^|[^A-Za-z0-9])https?:\x2f\x2f/.source;

/** `selector` strings are esquery, so a regex is written between slashes. */
const re = (source: string) => `/${source}/`;

export const restrictedSyntax: Restriction[] = [
  {
    tag: "placement",
    selector: `JSXAttribute[name.name='placement'] Literal[value=${re(PLACEMENT)}]`,
    message: "A bare left or right in `placement` is the wrong edge in RTL. Use useLogicalEdge (spec 8.2).",
  },
  {
    tag: "placement",
    selector: `Property[key.name='placement'] > Literal[value=${re(PLACEMENT)}]`,
    message: "A bare left or right in `placement` is the wrong edge in RTL. Use useLogicalEdge (spec 8.2).",
  },
  {
    tag: "class",
    selector: `Literal[value=${re(PHYSICAL_CLASS)}]`,
    message: "A physical class (ml-, pr-, left-, text-left, border-l, rounded-r, ...). Use the logical one: ms-, pe-, start-, text-start, border-s, rounded-e.",
  },
  {
    tag: "class",
    selector: `TemplateElement[value.raw=${re(PHYSICAL_CLASS)}]`,
    message: "A physical class (ml-, pr-, left-, text-left, border-l, rounded-r, ...). Use the logical one: ms-, pe-, start-, text-start, border-s, rounded-e.",
  },
  {
    tag: "dark",
    selector: `Literal[value=${re(DARK_VARIANT)}]`,
    message: "No `dark:` variant: semantic tokens already change per theme (DESIGN.md).",
  },
  {
    tag: "dark",
    selector: `TemplateElement[value.raw=${re(DARK_VARIANT)}]`,
    message: "No `dark:` variant: semantic tokens already change per theme (DESIGN.md).",
  },
  {
    tag: "dark",
    selector: "BinaryExpression[left.name='resolved'][right.value='dark']",
    message: "Do not branch on the theme in component code. Only packages/ui/src/theme may.",
  },
  {
    tag: "url",
    // An xmlns value is a namespace, not a request, so it is the one exemption.
    selector: `Literal[value=${re(URL_IN_TEXT)}]:not(JSXAttribute[name.name=/^xmlns/] > Literal)`,
    message: "No http(s) URL in code: nothing may load from outside at run time (fixed rule 9). Add a reviewed line to tools/web-lint/url-allow.txt if it is a name, not a request.",
  },
  {
    tag: "url",
    selector: `TemplateElement[value.raw=${re(URL_IN_TEXT)}]`,
    message: "No http(s) URL in code: nothing may load from outside at run time (fixed rule 9).",
  },
  {
    tag: "intl",
    selector: "NewExpression[callee.object.name='Intl']",
    message: "No raw Intl: format through packages/i18n/src/format.ts, which knows the Persian calendar and digits (spec 4.4).",
  },
  {
    tag: "intl",
    selector: "CallExpression[callee.object.name='Intl']",
    message: "No raw Intl: format through packages/i18n/src/format.ts (spec 4.4).",
  },
  {
    tag: "intl",
    selector: "CallExpression[callee.property.name=/^toLocale(Date|Time)?String$/]",
    message: "No toLocale*String: format through packages/i18n/src/format.ts (spec 4.4).",
  },
  {
    tag: "script",
    selector: "JSXOpeningElement[name.name='Script'] > JSXAttribute[name.name='src']",
    message: "No next/script with a src: nothing external, and the CSP has no script-src for it.",
  },
];

export const restrictedImports = {
  patterns: [
    {group: ["lucide", "lucide-*", "lucide/*"], message: "lucide is banned. General icons come from Hugeicons through packages/icons, specific ones are drawn by us."},
    {group: ["@iconify/*"], message: "@iconify/react fetches icons from a public API at run time, which this project forbids."},
    {group: ["@gravity-ui/*"], message: "Not our icon set. Use packages/icons."},
    {group: ["next-themes"], message: "next-themes is banned: our controller in packages/ui/src/theme is the one store (spec 5.1)."},
  ],
  paths: [
    {name: "next/font/google", message: "No remote font: Dana comes from a local file through next/font/local."},
    {name: "@heroui/react", importNames: ["useTheme"], message: "useTheme of HeroUI is a second theme store. Use packages/ui/src/theme/useTheme.ts."},
  ],
};

/** Files that are allowed to do what the lists above forbid, and the reason. */
export const exemptFiles = {
  // The one module that wraps Intl, and the logo component that needs a collator for its monogram.
  rawIntl: ["packages/i18n/src/format.ts", "packages/icons/src/ServiceLogo.tsx", "packages/icons/src/monogram.ts"],
  // The theme controller reads the resolved mode.
  themeBranch: ["packages/ui/src/theme/**"],
};

/** The syntax bans for a file that is exempt from the given tags. */
export const syntaxExcept = (...tags: Restriction["tag"][]) =>
  restrictedSyntax.filter((r) => !tags.includes(r.tag)).map(({selector, message}) => ({selector, message}));
