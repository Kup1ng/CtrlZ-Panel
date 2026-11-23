export type CspOptions = {
  /** `https://*.verify.dns.<domain>`, panel only, from CTRLZ_VERIFY_ORIGIN. */
  verifyOrigin?: string;
  dev: boolean;
};

export function buildCsp(nonce: string, opts: CspOptions): string {
  const connect = ["'self'"];
  if (opts.verifyOrigin) connect.push(opts.verifyOrigin);
  if (opts.dev) connect.push("ws:");
  // A nonce disables 'unsafe-inline', and next dev injects plain style tags.
  const styleElem = opts.dev ? "'self' 'unsafe-inline'" : `'self' 'nonce-${nonce}'`;
  return [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${opts.dev ? " 'unsafe-eval'" : ""}`,
    `style-src ${styleElem}`,
    `style-src-elem ${styleElem}`,
    // React Aria positions overlays with `style`, and HeroUI sets CSS
    // variables with `style` during SSR. An inline style attribute cannot
    // carry a selector, and img-src and font-src stay closed. Elements stay
    // nonce-only. Spec 15.2, open question 5.
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src ${connect.join(" ")}`,
    "manifest-src 'self'",
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
 * A wrong value throws, so the app refuses to start: a typo must not widen the
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
