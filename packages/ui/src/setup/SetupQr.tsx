"use client";

import {QRCodeSVG} from "qrcode.react";

// The QR code of a download or share link (spec p3 7.4, T-245): drawn here, in the browser, from the URL in state; no request is made and
// nothing is sent anywhere. Dark modules on a white ground in both themes, because a phone camera reads that and not an inverted code.
// A margin of four modules (the standard quiet zone) is part of the SVG so the white shows around it inside a dark dialog.
// The URL is a secret of its dialog: it is never put in an attribute, and the accessible name is the title only.

export function SetupQr({value, title, size = 192}: {value: string; title: string; size?: number}) {
  return (
    <div className="inline-flex rounded-(--radius-box) bg-white p-2" data-testid="setup-qr">
      <QRCodeSVG value={value} size={size} level="M" bgColor="#ffffff" fgColor="#000000" marginSize={4} title={title} />
    </div>
  );
}
