export type CspOptions = {
  /** `https://*.verify.dns.<domain>`, panel only, from CTRLZ_VERIFY_ORIGIN. buildCsp checks it with parseVerifyOrigin and throws on any other shape. */
  verifyOrigin?: string;
  dev: boolean;
};

export function buildCsp(nonce: string, opts: CspOptions): string {
  const connect = ["'self'"];
  // Validated here too, not only by the caller: a string that is typed `string` can be anything, and this is the one place where it becomes
  // part of the policy. `*` or `https://x; script-src *` would otherwise widen it with no error (gate-r4-3). Idempotent, so a value the caller
  // has parsed passes unchanged.
  const verifyOrigin = parseVerifyOrigin(opts.verifyOrigin);
  if (verifyOrigin) connect.push(verifyOrigin);
  if (opts.dev) connect.push("ws:");
  // A nonce disables 'unsafe-inline', and next dev injects plain style tags.
  const styleElem = opts.dev ? "'self' 'unsafe-inline'" : `'self' 'nonce-${nonce}'`;
  return [
    "default-src 'none'",
    // No 'strict-dynamic': it makes the browser ignore 'self' and every host, so a script element that a trusted script
    // builds at run time would load from any origin. Every script of the HTML has the nonce, and Next serves every
    // chunk it adds later from /_next/static, which 'self' covers (wp5-r18-3).
    `script-src 'self' 'nonce-${nonce}'${opts.dev ? " 'unsafe-eval'" : ""}`,
    `style-src ${styleElem}`,
    `style-src-elem ${styleElem}`,
    // React Aria positions overlays with `style`, and HeroUI sets CSS
    // variables with `style` during SSR. An inline style attribute cannot
    // carry a selector, and img-src and font-src stay closed. Elements stay
    // nonce-only. Spec 15.2, open question 5.
    "style-src-attr 'unsafe-inline'",
    // No data: here. Nothing in the built CSS or JS of either app uses a data: URI (checked on the
    // production build of 2026-11-14), and the guard of spec 17.2 fails a test on any violation, so the
    // first component that needs one will say so. Never blob: before P5's map asks for it.
    "img-src 'self'",
    "font-src 'self'",
    `connect-src ${connect.join(" ")}`,
    // Closed on purpose (gate-r19-3): neither app has a manifest route, file or <link rel="manifest">, and a markup injection
    // must not be able to make the browser fetch and apply a same-origin file as a web-app manifest (install name, start_url).
    // A PWA manifest later is a spec change made together in this file, expectedCsp.ts and spec 15.2, like the img-src data: rule.
    "manifest-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "worker-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}

const VERIFY_ORIGIN = /^https:\/\/\*\.verify\.dns\.[a-z0-9.-]+[a-z0-9]$/;

/**
 * Reads CTRLZ_VERIFY_ORIGIN. An absent or empty value means no extra origin.
 * A wrong value throws when the proxy file loads, so every page and every route of Next answers 500 and nothing is served
 * with a wrong policy (the process itself stays up, and only the files of public/ such as `/logo.png` are still served,
 * spec 15.5; verifyOrigin.spec.ts starts a server with a wrong value and checks this): a typo must not widen the
 * policy, and it must not silently narrow it either (spec 15.3).
 */
export function parseVerifyOrigin(value: string | undefined): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!VERIFY_ORIGIN.test(value) || value.includes("..")) {
    throw new Error("CTRLZ_VERIFY_ORIGIN must look like https://*.verify.dns.<domain>");
  }
  return value;
}

/** 16 random bytes, base64. Fresh for every request. */
export function newNonce(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");
}
