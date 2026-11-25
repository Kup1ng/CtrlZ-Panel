// The `ctrlz` ESLint plugin of spec 16.1. eslint.config.mjs turns each rule on for the shipped
// code and off, one line and one reason each, for the files in tools/web-lint/*-allow.txt.
import {hugeiconsBans, noEmailBans, noSecretParamBans, noStorageBans, physicalArrowBans, physicalStyleBans, protocolRelativeBans} from "./bans.ts";
import {selectorRule} from "./rules/helpers.ts";
import {noNextFetch} from "./rules/noNextFetch.ts";
import {noRawText} from "./rules/rawText.ts";
import {reducedMotion} from "./rules/reducedMotion.ts";
import {useOnPress} from "./rules/useOnPress.ts";

export const rules = {
  "hugeicons-only-in-allowlist": selectorRule("@hugeicons/* only in packages/icons/src/hugeicons.ts and Icon.tsx (T-475)", hugeiconsBans),
  "no-physical-style": selectorRule("Logical properties in style objects (the style-object half of logical-properties)", physicalStyleBans),
  "no-protocol-relative-url": selectorRule("No //host URL (the //host half of no-external-url)", protocolRelativeBans),
  "no-physical-arrow": selectorRule("No literal ArrowLeft or ArrowRight outside useDirectionalKeys (T-466)", physicalArrowBans),
  "no-email": selectorRule("No email field, name or word (T-111)", noEmailBans),
  "no-secret-param": selectorRule("No secret in a URL parameter (R21)", noSecretParamBans),
  "no-storage": selectorRule("No localStorage, sessionStorage, cookie, IndexedDB or CacheStorage outside the reviewed files (spec 14.4)", noStorageBans),
  "no-raw-text": noRawText,
  "reduced-motion": reducedMotion,
  "use-on-press": useOnPress,
  "no-next-fetch": noNextFetch,
};

const plugin = {meta: {name: "ctrlz"}, rules};
export default plugin;
