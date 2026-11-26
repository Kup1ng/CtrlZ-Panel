# HeroUI Pro (`@heroui-pro/react` 1.0.0-beta.11)

Added on 2026-11-07 after the review of the Flat switch (D17, T-485).

## Outcome: used inside our licensed application only

HeroUI Pro's licence lets a licensed user build the package into their own application. It forbids sharing, publishing or redistributing the package or any part of its source. The `LICENSE` file in the package was read on 2026-11-07, and spec 5.4 records the reading. The owner has not confirmed that reading; the package is installed under the owner's Pro licence.

## What of it is copied into this repository

`packages/ui/styles/glass-carryover.css` reproduces about 100 lines of the Pro Glass theme's stylesheet (26 declarations in 18 rules), verbatim apart from two renamed variables and two respelled colour literals (the file's header lists every difference). They are the rules the approved Flat look depends on (spec 5.4 of `p1-frontend.md`). Nothing else of Pro's source is copied. Everything else is imported from the installed package.

## Before the repository goes public

Review `packages/ui/styles/glass-carryover.css` first. Either:

- replace each rule with our own declarations, written from the computed result and not from the Pro file, and delete the file; or
- get the owner's written confirmation that the licence allows these lines to be published.

`packages/ui/styles/glass-carryover.test.ts` and the carried-over-rules test in `apps/panel/e2e/lab.spec.ts` describe the rules' effect, so a rewrite can be checked against them.

This repository is private and has no remote (fixed rule 5), so nothing is shared today. The item is also a risk entry for `Plan.md`, which the orchestrator owns.
