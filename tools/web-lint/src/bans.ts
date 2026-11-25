// The selector bans of spec 16.1 that need a rule of their own because a file may be exempt
// from one of them and not from the others. ESLint's `no-restricted-syntax` takes one list per
// file, so an exemption there replaces every other ban (that is how banned.ts works, and why its
// exemptions are few). Here each ban is a `ctrlz/*` rule, and a file turns off exactly one.
//
// The regexes are regex literals pasted through `.source`, and a slash is written `\x2f`: esquery
// ends a regex at the first slash and has no escape for it (see the note in banned.ts).

export type Ban = {selector: string; message: string};

const re = (r: RegExp) => `/${r.source}/${r.flags}`;

// `@hugeicons/*` is imported in two files (spec 7.2), so the one place that knows which icon is
// which is also the one place that can be replaced if the set changes.
const HUGEICONS = /^@hugeicons\x2f/;

const PHYSICAL_PROP = /^(left|right|margin(Left|Right)|padding(Left|Right)|border(Left|Right)(Width|Style|Color)?|border(Top|Bottom)(Left|Right)Radius|scroll(Margin|Padding)(Left|Right)|inset(Left|Right))$/;
const PHYSICAL_PROP_MSG = "A physical edge in a style object. Use the logical property: insetInlineStart, marginInlineEnd, paddingInlineStart, textAlign: start, borderStartStartRadius (spec 16.1).";
const PHYSICAL_NAME = `Property[key.name=${re(PHYSICAL_PROP)}]`;
const PHYSICAL_STRING_KEY = `Property[key.value=${re(PHYSICAL_PROP)}]`;
const PHYSICAL_ALIGN = "Property[key.name=/^(textAlign|float|clear)$/][value.value=/^(left|right)$/]";
// Where a style object lives: the `style` prop, a `style` key, or a constant typed as CSSProperties.
const STYLE_ROOTS = ["JSXAttribute[name.name='style'] ", "Property[key.name='style'] ", "VariableDeclarator[id.typeAnnotation.typeAnnotation.typeName.name='CSSProperties'] "];
const inStyle = (target: string) => STYLE_ROOTS.map((root) => root + target).join(", ");

export const hugeiconsBans: Ban[] = [
  {selector: `ImportDeclaration[source.value=${re(HUGEICONS)}]`, message: "Import Hugeicons only in packages/icons/src/hugeicons.ts and Icon.tsx. Everything else asks packages/icons for an icon (spec 7.2)."},
  {selector: `ExportNamedDeclaration[source.value=${re(HUGEICONS)}]`, message: "Re-exporting Hugeicons outside the allowlist (spec 7.2)."},
  {selector: `ExportAllDeclaration[source.value=${re(HUGEICONS)}]`, message: "Re-exporting Hugeicons outside the allowlist (spec 7.2)."},
  {selector: `ImportExpression[source.value=${re(HUGEICONS)}]`, message: "Import Hugeicons only in packages/icons/src/hugeicons.ts and Icon.tsx (spec 7.2)."},
  {selector: `CallExpression[callee.name='require'][arguments.0.value=${re(HUGEICONS)}]`, message: "Import Hugeicons only in packages/icons/src/hugeicons.ts and Icon.tsx (spec 7.2)."},
];

export const physicalStyleBans: Ban[] = [
  {selector: inStyle(PHYSICAL_NAME), message: PHYSICAL_PROP_MSG},
  {selector: inStyle(PHYSICAL_STRING_KEY), message: PHYSICAL_PROP_MSG},
  {selector: inStyle(PHYSICAL_ALIGN), message: "text-align, float and clear take start and end, not left and right."},
];

// `//host` is a request that keeps the page's scheme, so it is as external as `https://host`.
// A letter after the slashes and a dot later on, so a path like "a//b" and a comment do not match.
const PROTOCOL_RELATIVE = /(^|[\s"'(=,])\x2f\x2f[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/;
export const protocolRelativeBans: Ban[] = [
  {selector: `Literal[value=${re(PROTOCOL_RELATIVE)}]`, message: "No //host URL in code: nothing may load from outside at run time (fixed rule 9)."},
  {selector: `TemplateElement[value.raw=${re(PROTOCOL_RELATIVE)}]`, message: "No //host URL in code: nothing may load from outside at run time (fixed rule 9)."},
];

// An arrow key is physical, and in Persian the "next" item is on the left. useDirectionalKeys is the
// one place that maps a direction to a key (T-466).
const ARROW = /^Arrow(Left|Right)$/;
export const physicalArrowBans: Ban[] = [
  {selector: `Literal[value=${re(ARROW)}]`, message: "A literal ArrowLeft or ArrowRight is the wrong key in RTL. Use useDirectionalKeys (T-466)."},
  {selector: `TemplateElement[value.cooked=${re(ARROW)}]`, message: "A literal ArrowLeft or ArrowRight is the wrong key in RTL. Use useDirectionalKeys (T-466)."},
  {selector: `Property[key.name=${re(ARROW)}]`, message: "A key table with ArrowLeft or ArrowRight is the wrong key in RTL. Use useDirectionalKeys (T-466)."},
];

// T-111: the service has no email address anywhere. Not a type, not a name, not a word on screen.
const EMAIL = /e-?mail|ایمیل|ای‌میل|پست الکترونیک/i;
export const noEmailBans: Ban[] = [
  {selector: "JSXAttribute[name.name='type'][value.value='email']", message: "No email field: the account is a phone number (T-111)."},
  {selector: `Identifier[name=${re(EMAIL)}]`, message: "Nothing is named after email (T-111)."},
  {selector: `Literal[value=${re(EMAIL)}]`, message: "No email in a string: the service has no email address (T-111)."},
  {selector: `TemplateElement[value.cooked=${re(EMAIL)}]`, message: "No email in a string: the service has no email address (T-111)."},
  {selector: `JSXText[value=${re(EMAIL)}]`, message: "No email in the text: the service has no email address (T-111)."},
];

// R21: a URL lands in history, logs and the Referer of the next request. A one-time value must
// never ride in it. A parameter is matched by what its name contains and not by the exact word, because the screens name what they carry
// (`totp_code`, `invite_code`, `recovery_code`, `otp`, `challenge`, `reset_ticket`, `new_password`) and an exact list sees none of them (gate-r9-6).
// The cost is a false hit on a name that merely contains a word (`codes`, `encode`): rename it or give it a reviewed disable with the reason.
export const SECRET_WORDS = "ticket|secret|code|pass|token|otp|recover|challenge|invite|credential";
const SECRET = new RegExp(`(${SECRET_WORDS})`, "i");
const SECRET_PAIR = new RegExp(String.raw`[?&#][\w.-]*(${SECRET_WORDS})[\w.-]*=`, "i");
const SEARCH_PARAMS_OBJECT = "[callee.object.name=/params$/i], [callee.object.property.name=/params$/i]";
// A query key is kept in the cache for the query's gcTime and is readable there, in a heap snapshot and in the devtools of a shared PC, so a secret
// in one (`["totp-setup", otpauthUri]`, `resetKeys.detail(ticket)`) outlives the screen that asked, as a secret in a URL would. The same words, in the
// places a key is written: the `queryKey` option, and the first argument of the cache calls that take a key (gate-r22-8). The key factories are
// `*Keys` objects in packages/api-client, and `queryKeys.test.ts` walks every one of them and every `*QueryOptions`.
const KEY_CALLS = /^(setQueryData|getQueryData|setQueriesData|getQueriesData|prefetchQuery|fetchQuery|ensureQueryData|invalidateQueries|cancelQueries|removeQueries|resetQueries|refetchQueries)$/;
const KEY_ROOTS = ["Property[key.name='queryKey']", `CallExpression[callee.property.name=${re(KEY_CALLS)}]`];
// Only names that carry a value are judged: a literal such as "passkeys" names the resource and is no secret.
const KEY_MESSAGE = "A name that reads as a secret in a query key: the key stays in the cache and is readable there (14.4, gate-r22-8).";
const queryKeyBans: Ban[] = KEY_ROOTS.flatMap((root) => [
  {selector: `${root} ArrayExpression > Identifier[name=${re(SECRET)}]`, message: KEY_MESSAGE},
  {selector: `${root} ArrayExpression > MemberExpression[property.name=${re(SECRET)}]`, message: KEY_MESSAGE},
  {selector: `${root} ArrayExpression TemplateLiteral > Identifier[name=${re(SECRET)}]`, message: KEY_MESSAGE},
  {selector: `${root} ArrayExpression Property[key.name=${re(SECRET)}]`, message: KEY_MESSAGE},
  {selector: `${root} ArrayExpression Property[value.name=${re(SECRET)}]`, message: KEY_MESSAGE},
]);
// A key built by a factory: `keys.detail(ticket)`. The callee's own name is not a value, so only the arguments are looked at.
const keyFactoryBans: Ban[] = [0, 1, 2, 3].map((i) => ({
  selector: `Property[key.name='queryKey'] CallExpression[arguments.${i}.name=${re(SECRET)}]`,
  message: KEY_MESSAGE,
}));
export const noSecretParamBans: Ban[] = [
  {selector: `CallExpression[callee.name='useUrlDialog'][arguments.0.value=${re(SECRET)}]`, message: "A dialog parameter named like a secret would put it in the URL (R21)."},
  ...["get", "getAll", "has", "set", "append", "delete"].flatMap((method) =>
    SEARCH_PARAMS_OBJECT.split(", ").map((object) => ({
      selector: `CallExpression[callee.property.name='${method}']${object}[arguments.0.value=${re(SECRET)}]`,
      message: "A search parameter named like a secret would put it in the URL (R21).",
    })),
  ),
  {selector: `NewExpression[callee.name='URLSearchParams'] Property[key.name=${re(SECRET)}]`, message: "A search parameter named like a secret would put it in the URL (R21)."},
  {selector: `NewExpression[callee.name='URLSearchParams'] Property[key.value=${re(SECRET)}]`, message: "A search parameter named like a secret would put it in the URL (R21)."},
  {selector: `Literal[value=${re(SECRET_PAIR)}]`, message: "A secret in a query string or fragment (R21)."},
  {selector: `TemplateElement[value.cooked=${re(SECRET_PAIR)}]`, message: "A secret in a query string or fragment (R21)."},
  ...queryKeyBans,
  ...keyFactoryBans,
];

// 14.4: nothing about the session is readable by script, and nothing else may be kept in the browser
// without a reviewed reason. The files that may are in tools/web-lint/storage-allow.txt.
// A cookie, IndexedDB and CacheStorage keep a value as long as local storage does, and a cookie also travels on every
// request to the Next server and to Caddy, so they are held to the same list (gate-r1-20). The system clipboard is a store as well: what Copy
// puts there outlives the screen, the tab and the session, so `navigator.clipboard` has one reviewed writer, api-client/src/clipboard.ts (gate-r5-8).
const STORAGE = /^(localStorage|sessionStorage|indexedDB|caches|cookieStore)$/;
const STORAGE_MESSAGE = "No browser storage, cookie, IndexedDB, CacheStorage or clipboard write outside the reviewed files in tools/web-lint/storage-allow.txt (spec 14.4).";
export const noStorageBans: Ban[] = [
  {selector: `Identifier[name=${re(STORAGE)}]`, message: STORAGE_MESSAGE},
  {selector: `Literal[value=${re(STORAGE)}]`, message: STORAGE_MESSAGE},
  // document.cookie, and window.document.cookie or globalThis.document.cookie.
  {selector: "MemberExpression[property.name='cookie'][object.name='document']", message: STORAGE_MESSAGE},
  {selector: "MemberExpression[property.name='cookie'][object.property.name='document']", message: STORAGE_MESSAGE},
  {selector: "MemberExpression[computed=true][property.value='cookie']", message: STORAGE_MESSAGE},
  // navigator.clipboard, window.navigator.clipboard and navigator["clipboard"]: use copyOneTimeSecret.
  {selector: "MemberExpression[property.name='clipboard']", message: STORAGE_MESSAGE + " Copy a one-time value with copyOneTimeSecret."},
  {selector: "MemberExpression[computed=true][property.value='clipboard']", message: STORAGE_MESSAGE + " Copy a one-time value with copyOneTimeSecret."},
];
