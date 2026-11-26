# QR codes (spec p3 7.4, T-245)

**Outcome: allowed.**

Written for the setup screens (S7) on 2026-11-25. The licence fields are those of the packages in `pnpm-lock.yaml`.

| Package | Version | Licence | Where |
|---|---|---|---|
| `qrcode.react` | 4.2.0 | ISC | `packages/ui`, shipped: draws a QR code as inline SVG in the browser (`setup/SetupQr.tsx`, the TOTP wizard of the account page) |
| `jsqr` | 1.4.0 | Apache-2.0 | `apps/panel` dev dependency only, used by the Playwright specs to read a drawn code back. It is not in the shipped bundle |

`qrcode.react` runs in the browser and sends nothing: the URL is a prop, and the result is an `<svg>` of `path` elements, so no `img-src` is needed and the page's policy stays as it is. The URL of a download or share link is a secret of its dialog; it is not put in an attribute of the SVG.

Both licences allow use, copying and sale with no restriction on closed source. ISC and Apache-2.0 are on the allow list of `tools/web-lint/licences.allow.txt`. The third-party notices of the release (P8) list both.

## Conditions

1. A change of version or package is a new run of this note.
2. `jsqr` stays a dev dependency: a case that needs a QR decoder in the shipped app is a new decision.
