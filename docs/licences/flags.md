# Country flags (FE 7.5, P2 open question 5)

**Outcome: allowed.**

Written for the P2 and P3 screens foundation on 2026-11-25. Read from the package itself (`npm pack country-flag-icons@1.6.20`, unpacked in a scratch folder, not a dependency of the project), not from a website.

## What was read

| Package | Version | `license` in `package.json` | Licence file |
|---|---|---|---|
| `country-flag-icons` | 1.6.20 | MIT | `LICENSE`: MIT, "Copyright (c) 2020 @catamphetamine" |

The package's README says its `3x2/*.svg` files are the vector flags for every ISO 3166-1 code, minified, and tells readers to take the files from the package and nowhere else (the repository copies are not minified). Our 249 files are the `3x2` files of the 249 codes of `packages/i18n/src/countries.ts`, byte for byte (only the line ending is normalised). Nothing else of the package is used.

## Questions

- **May they be bundled in a closed application?** Yes. MIT allows use, copy, modification, distribution and sale, with no restriction on closed source.
- **Attribution?** Not on screen. MIT requires the copyright and permission notice to go with "all copies or substantial portions of the Software". `packages/icons/flags/LICENSE` holds the text and travels with the files; the third-party notices file of the release (P8) lists it with Hugeicons.
- **The flags as national symbols.** The licence covers the drawings. A flag of a state is not a trademark of the maintainer. The Iranian flag, with its emblem, is among them, and so are the flags of states the owner's users may find sensitive; the product shows a flag next to a location only because a node serves from there, and the choice of locations is the owner's.

## How they ship

`packages/icons/flags/<CC>.svg` are the sources. `packages/icons/scripts/flags.mjs` checks them (only `svg`, `g`, `path`, `circle` and `ellipse`, a short list of attributes, no link, id, style or script) and writes `src/flagTable.generated.ts`, a table of element trees that the `Flag` component builds with React. They are inline SVG, loaded as one lazy chunk (173 KB before compression) on the first flag a page draws. No flag is a request to another origin, and none is an `<img>` (the CSP's `img-src` is `'self'` only). `node scripts/flags.mjs --check` fails when the table is stale, and is part of `build:check`.

## Conditions

1. Keep `packages/icons/flags/LICENSE` with the files, and list the notice in the third-party notices of the release.
2. A change of the set (a code added, a new package version) is a new run of this note.
