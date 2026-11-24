# Simple Icons (T-471)

**Outcome: unknown.** This does not block P1, which ships an empty `packages/icons/logos/manifest.json`. It blocks adding any logo from this set until each logo has been checked (spec 7.5), and the trademark question below has an answer from the owner.

Written by WP2 (Icons) on 2026-11-07. Read from `npm pack simple-icons` (version 16.36.0) unpacked in a scratch folder. It is not a dependency of the project.

## What was read

- `package.json` says `license: CC0-1.0`, and `LICENSE.md` is the CC0 1.0 Universal text. That waives the maintainers' own rights in the collection and in their drawings.
- `LICENSE.md` also says, in the CC0 text, that no trademark or patent rights held by the affirmer are waived or licensed. That clause concerns the affirmer's rights, and the brands are not the affirmer, so it does not reach their marks either way. It only means CC0 gives us nothing on trademarks.
- `DISCLAIMER.md` is the part that decides the outcome. In my words: the collection is CC0, but that does not mean every icon in it is CC0. The project carries per-icon licence data where it has it, and says its absence does not mean there is no licence. It asks users to read each brand's guidelines, says it cannot be held responsible for legal action by a brand, and tells users to get the permissions their own project needs. Brands can ask for an icon to be updated or removed.
- `data/simple-icons.json` has 3,467 icons. Only 224 of them have a `license` entry, and 839 have a `guidelines` link. The licences that do appear are mixed: CC0, MIT, Apache-2.0, BSD, but also CC-BY, CC-BY-SA, CC-BY-NC, CC-BY-NC-ND, GPL and AGPL, and 23 "custom". A logo under CC-BY-SA, a non-commercial term, or GPL could not be bundled into a product that is sold. So "the package is CC0" is not enough to copy a logo, and a logo with no licence entry is not cleared either.

## Questions in the spec

- **What are the terms?** CC0 for the collection. For each logo, whatever its entry says, or nothing; and every logo is the owner's trademark.
- **Trademark terms for the logos we would copy.** The package states none of its own. It points to each brand's guidelines, via the `guidelines` link and the `source` URL of each entry. Those are the terms that apply.

## Why `unknown`, not `not allowed`

Nothing here forbids the use. What is missing is a decision that depends on facts we do not have yet: which logos the catalogue will use, each one's licence entry and brand guidelines, and whether the owner accepts showing a brand's mark next to its name in a DNS filtering product. Showing the logo only to identify the service the user is filtering is the usual reading, and it is a legal judgement that belongs to the owner, not to this note.

## Procedure when a logo is added (P2 or P6)

1. Open the entry for the slug in `data/simple-icons.json` of the version in use. Copy its `license` (or note "none given"), `source` and `guidelines`.
2. Refuse a logo whose licence is share-alike, non-commercial, no-derivatives or copyleft, and any logo whose guidelines forbid use of the mark in a product like ours. It gets the monogram instead.
3. Copy the SVG to `packages/icons/logos/<slug>.svg` and add a line to `manifest.json`: `{slug, source, licence, licenceUrlAsText}`. `source` names the package version and slug. `licence` is the entry's licence, or "CC0-1.0 for the drawing; trademark of <brand>" when the entry gives none. `licenceUrlAsText` is the guidelines URL kept as plain text. It is never fetched or linked at run time. `scripts/build.mjs` fails if a file has no line or a line has no file.
4. Record the decision for the whole set in `Plan.md`.

T-471 closes for this set when the owner decides, or when the catalogue uses no Simple Icons logo at all.
