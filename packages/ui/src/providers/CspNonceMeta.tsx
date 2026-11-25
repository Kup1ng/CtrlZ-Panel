"use client";

// Spec 15.2, gate-r1-1. React Aria (getMetaValue) and OtpField read the nonce from this tag at run time and put it
// on the <style> elements they create. The CSP of the document is the one of the first response and never changes, so
// the tag must not change either. A server render under a new request (router.refresh(), an error boundary reset) brings
// a new nonce down as the prop, and a plain <meta content={nonce}> would let React write it into the tag: every reader
// after that would get a value that the browser refuses.
//
// The value is held in a variable of this module, outside React, and only in the browser. A component's state is lost when
// global-error.tsx replaces the whole document (its <html> has no head, so the old tag is removed) and Try again mounts the
// layout again: the new instance would find no tag and take the prop, which after a router.refresh() is the nonce of a later
// request (gate-r9-1). A module is evaluated once per document, and a full load is a new document with a new CSP, so the
// variable lives exactly as long as the nonce it holds. The first browser render takes what the server wrote into the tag (the
// same string as the prop, so hydration matches), else the prop; no later prop replaces it. On the server nothing is held,
// because the module is shared by every request there.
//
// gate-r30-1. The value is the tag's nonce attribute and not its content. Chrome hides the nonce attribute of every element in a
// document whose CSP came in a header (getAttribute returns "" and only the .nonce property keeps the value), so an attribute
// selector such as meta[content^="a"], or outerHTML, cannot read it. A plain content attribute stayed readable for the whole life
// of the document. React Aria's getMetaValue reads meta.nonce first, and OtpField reads the property too.

const SELECTOR = 'meta[name="csp-nonce"]';

function documentNonce(): string | undefined {
  if (typeof document === "undefined") return undefined;
  // The property, not the attribute: Chrome empties the nonce attribute of every element once the document's CSP came in a header
  // and keeps the value only in the .nonce property (gate-r30-1).
  const value = (document.querySelector(SELECTOR) as HTMLMetaElement | null)?.nonce;
  return value ? value : undefined;
}

let held: string | undefined;

export function CspNonceMeta({nonce}: {nonce: string}) {
  let value = nonce;
  if (typeof document !== "undefined") {
    held ??= documentNonce() ?? nonce;
    value = held;
  }
  return <meta name="csp-nonce" nonce={value} />;
}
