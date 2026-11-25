# Hugeicons free set (T-471)

**Outcome: allowed.**

Written by WP2 (Icons) on 2026-11-07. Read from the installed packages in `node_modules`, not from the website.

## What was read

| Package | Version | `license` in `package.json` | Licence file |
|---|---|---|---|
| `@hugeicons/core-free-icons` | 4.4.0 | MIT | `LICENSE.md`: MIT, "Copyright (c) 2025 Hugeicons" |
| `@hugeicons/react` | 1.1.10 | MIT | `LICENSE.md`: the same MIT text. `PRO-LICENSE.md` is a summary of a separate, paid Pro licence |

The README of the icon package says the icons and the source code are MIT and may be used, modified and redistributed in personal and commercial projects. The README of the React package says it only renders icons and grants no rights to icon assets, and sends the reader to the licence of whichever icon package is installed. For us that is `@hugeicons/core-free-icons`, so the MIT file above is the one that governs the artwork.

## Questions in the spec

- **May it be bundled in a closed application?** Yes. MIT allows use, copy, modification, merging, publishing, distribution, sublicensing and sale, with no restriction on closed source.
- **Does it require attribution?** Not on screen. MIT requires that the copyright and permission notice go with "all copies or substantial portions of the Software". Our bundle contains the icon data of every icon we import, which is a copy of a portion of the Software, so the notice has to ship with the product.

## Conditions

1. **Keep the notice.** Add the Hugeicons MIT notice to whatever third-party notices file or page the product ships (P8 release work). Until that file exists, this note is the reminder. The text is in `node_modules/@hugeicons/core-free-icons/LICENSE.md` and is unchanged between the two packages.
2. **Free set only.** `@hugeicons-pro/*` needs a paid, per-seat licence that forbids redistributing the source files. `pnpm-lock.yaml` has no `hugeicons-pro` entry (0 matches on 2026-11-07), and none may be added without the owner's decision.
3. **Allowlist.** `packages/icons/src/hugeicons.ts` is the only file that imports the icon package, so the set of icons we ship is the 41 lines in that file.

## Not checked

- The licence page on hugeicons.com (`hugeicons.com/license-agreement`) was not opened. The spec's wording, that the site states free use at no cost, was not re-verified. The package files are what we redistribute, and they say MIT, so this does not change the outcome. It would matter only if the website claimed terms that contradict the files shipped in the package.
