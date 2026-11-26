import type {ReactNode} from "react";

// A domain, IP, token name or any other technical string. `<bdi dir="ltr">` isolates it from the
// surrounding direction, so a Persian sentence keeps it in reading order and the punctuation
// around it does not jump to the wrong side (spec 4.5, ctrlz-frontend). It is a server-safe
// component: no hooks, no client code.
//
// `translate="no"` is part of it (gate-r3-12). A domain, an IP, a key or a code is never prose, and the browser's own page translation is
// started by the visitor's browser, not by the page: it sends every translatable text node to the vendor's server, and neither the CSP nor the
// 17.2 guard can see it. For a one-time secret (the TOTP seed, the recovery codes) that would be the secret leaving the origin, and it
// would also rewrite the digits a person copies by hand.

export function Tech({children, className, mono = true}: {children: ReactNode; className?: string; mono?: boolean}) {
  return (
    <bdi dir="ltr" translate="no" className={[mono ? "font-mono" : "", className ?? ""].filter(Boolean).join(" ") || undefined}>
      {children}
    </bdi>
  );
}
