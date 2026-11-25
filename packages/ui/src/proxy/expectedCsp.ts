// The policy of spec 15.2, written out by hand and apart from `buildCsp` (csp.ts), so a change to csp.ts has to change this file too. It has
// no Playwright import, so the vitest tests of the proxies (createProxy.test.ts) and the browser spec (headersSpec.ts) read the same
// text: the single source of "what the exact policy is" for both apps (gate-r20-1). The policy is the same on both apps except for
// connect-src, which the panel alone may extend with the verify origin (15.3).
//
// `NONCE` stands for the per-request value.

export const EXPECTED_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'nonce-NONCE'",
  "style-src 'self' 'nonce-NONCE'",
  "style-src-elem 'self' 'nonce-NONCE'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "worker-src 'none'",
  "upgrade-insecure-requests",
] as const;

/** The whole header value for a request that was given `nonce`, with `connect` as the sources of connect-src. */
export function expectedPolicy(nonce: string, connect: readonly string[] = ["'self'"]): string {
  return EXPECTED_DIRECTIVES.map((d) => (d.startsWith("connect-src") ? `connect-src ${connect.join(" ")}` : d))
    .join("; ")
    .replaceAll("NONCE", nonce);
}
