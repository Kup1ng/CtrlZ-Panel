import createMiddleware from "next-intl/middleware";
import {NextRequest, type NextResponse} from "next/server";
import {routing} from "@ctrlz/i18n/routing.ts";

import {buildCsp, newNonce} from "./csp.ts";
import {gateRedirect, type GateConfig} from "./gate.ts";

export type ProxyConfig = GateConfig & {
  /** Panel only. Already validated by parseVerifyOrigin. */
  verifyOrigin?: string;
};

/**
 * The proxy of one app: a nonce and the CSP on every response, the session
 * gate, and next-intl's locale routing (spec 15.4).
 */
export function createProxy(cfg: ProxyConfig) {
  const i18n = createMiddleware(routing);
  const dev = process.env.NODE_ENV === "development";

  return function proxy(request: NextRequest): NextResponse {
    const nonce = newNonce();
    const csp = buildCsp(nonce, {verifyOrigin: cfg.verifyOrigin, dev});

    // Next reads the nonce from the CSP header of the request while it
    // renders, and the layout reads x-nonce for the theme script.
    const headers = new Headers(request.headers);
    headers.set("x-nonce", nonce);
    headers.set("Content-Security-Policy", csp);
    const forwarded = new NextRequest(request, {headers});

    const response = gateRedirect(forwarded, cfg) ?? i18n(forwarded);
    response.headers.set("Content-Security-Policy", csp);
    return response;
  };
}
