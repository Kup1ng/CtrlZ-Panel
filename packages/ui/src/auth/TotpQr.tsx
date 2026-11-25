"use client";

import {QRCodeSVG} from "qrcode.react";

// The QR code of an `otpauth://` URI. One component so the apps need no QR dependency of their own, and so the
// colours are set once: a phone reads dark modules on a light ground, whatever the theme (the account page's wizard
// draws the same). The URI holds the secret, so it is only ever a prop of a screen that shows it once.

export function TotpQr({uri, title, size = 176}: {uri: string; title: string; size?: number}) {
  return <QRCodeSVG value={uri} size={size} level="M" bgColor="#ffffff" fgColor="#000000" title={title} />;
}
