# Dana (`DanaVF.woff2`)

Checked by WP1 on 2026-11-07 for T-471, spec section 7.5. File: `packages/ui/fonts/DanaVF.woff2`, 71 984 bytes, copied from the workspace root. It is the only copy in the repository.

## Outcome: `allowed`, on the owner's word (D38)

The font's own `name` table says a licence from the foundry is required. The owner answered on 2026-11-07 that they bought the font from fontiran.com and need no separate licence for this use. D38 is closed and Dana is no longer a P8 release condition. The licence text itself is not in the workspace.

| Question (spec 7.5) | Answer |
|---|---|
| May it be embedded in a web app and self-hosted, in a product that is sold? | Yes, per the owner, who bought it from the foundry (D38). The terms were not read here |

## What the file says

Read with `fontkit` 2.0.4 in a scratch folder outside the repository. Nothing was downloaded from any website, and the foundry's site was not opened.

| `name` record | Value |
|---|---|
| Family, subfamily, PostScript | `DanaVF`, Regular, `DanaVF-Regular` |
| Version | `Version 3.100;FEAKit 1.0` |
| Copyright | `Copyright (c) 2022 by www.fontiran.com (Moslem Ebrahimi). All rights reserved.` |
| Designer | Moslem Ebrahimi (`moslemebrahimi.com`) |
| Manufacturer | Shahrzad Akbari, Moslem Ebrahimi |
| Vendor URL | `fontiran.com` |
| `license` (id 13) | `To use this font, it is necessary to obtain the license from www.fontiran.com` |
| `licenseURL` (id 14) | `https://fontiran.com/licenses` |
| Trademark | `Dana is a trademark of www.fontiran.com (Moslem Ebrahimi).` |

`OS/2.fsType` is 0x0100: embedding is not restricted, and subsetting is not allowed. `next/font/local` does not subset a local file, so the product complies with that flag. Do not add a subsetting step (`pyftsubset`, `glyphhanger`, a build plugin) for this file without the owner's licence terms.

The licence URL above is a string inside the font. It is data, never fetched by the product, and it appears in no page.

## If the font ever changes

The code needs no change for a swap: `packages/ui/src/fonts/dana.ts` is the one place that names the file.

## Technical facts read from the file (T-469)

These close DESIGN.md Open question 9 and the "Dana facts" of spec Open question 21.

| Fact | Value | Consequence |
|---|---|---|
| Axes | `wght` 10 to 990 (default 10), and `KASH` (kashida) 0 to 100 | `weight: "10 990"` in `dana.ts`. The default instance is the thinnest, so the `@font-face` must declare the range or the browser would synthesise weights |
| Glyphs | 784 | |
| Latin | A to Z, a to z and 0 to 9 are complete. Latin-1 Supplement has 18 of 96 | English text renders in Dana. Accented Latin letters would fall back, and the product has none |
| Arabic block | 112 of 256 in U+0600 to U+06FF, plus presentation forms | The Persian letters پ چ ژ گ ک ی are all present, with ZWNJ, ZWJ, LRM, RLM and the Arabic comma, semicolon and question mark |
| Digits | Persian U+06F0 to U+06F9 and Arabic-Indic U+0660 to U+0669 are both present | Persian digits in `fa` need no fallback |
| OpenType features | `aalt calt ccmp dlig dnom fina frac init kern mark medi mkmk numr rclt rlig sinf ss02 ss03 subs sups` | **No `tnum` and no `pnum`**: `tabular-nums` does nothing for Dana |
| Digit widths at the default instance | Latin 533 to 544 units, Persian 340 to 669 units, per 1000 em | Not tabular. Digits in a right-aligned column will not line up exactly. Keep numbers in tables in a fixed-width cell, or accept the drift |
| Vertical metrics | unitsPerEm 1000, ascent 1000, descent 430, line gap 0, `USE_TYPO_METRICS` set | The natural line box is 1.43em |
| Ink extent of Arabic-script glyphs at the default instance | 0.844em above the baseline (U+FEF8) to 0.465em below (U+0695), so 1.31em | Closes DESIGN.md Q8. A line height under about 1.35 lets the marks of two lines touch. `base.css` gives `fa` 1.5 at `text-xs` and 1.35 for `5xl` to `9xl`, which stock sets to 1.33 and 1.0 |
| Glyph heights | cap height 700, x-height 500 | |

The two ink extents were measured at the default (thinnest) instance only, because `fontkit` cannot instantiate glyph outlines of this font at other weights. Heavier weights change them very little, but they are unchecked.
