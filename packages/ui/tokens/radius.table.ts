// The only place the radius numbers live (D16, DESIGN.md "Shape and radius").
//
//   control: radius = min(0.4 x height, 30px)
//   box:     radius = 20px, whatever the height
//   pill:    fully round, for the one exception the owner made (D47: the switch track and thumb)
//
// scripts/gen-radius.mjs turns this file into styles/radius.generated.css.
// Run `node packages/ui/scripts/gen-radius.mjs` after any edit, and commit both
// files. `--check` fails when the generated file is stale (CI).
//
// Row order is emission order. Later rows win over earlier rows of the same
// specificity, so a size modifier (`.button--sm`) must come after its base
// (`.button`). When HeroUI's own rule is more specific than a single class (the
// pagination sizes are `.pagination--sm .pagination__link`), the row uses that
// same selector, never `!important`.
//
// Heights are written the way HeroUI writes them, so they follow `--spacing`
// (4.25px) where HeroUI's do. Where HeroUI pins no height (inputs, selects) the
// height is padding plus line height plus border, spelled out the same way and
// confirmed in a browser (WP1 check, T-474 in WP11).

/** A height that may change at a breakpoint. `sm` is 40rem, `md` is 48rem. */
export type Height = {base: string; sm?: string; md?: string};

/** The only exception today: D47 made the switch track and thumb pills, like stock HeroUI. */
export type Exception = {decision: "D47"; shape: "pill"};

export type ControlRow = {
  kind: "control";
  selector: string;
  height: Height;
  /** Stylesheet or decision the figures come from. */
  source: string;
  /**
   * True only for the two explicit size utilities, which set the height too.
   * Everywhere else HeroUI owns the height and this table only reads it.
   */
  setsHeight?: boolean;
  /** Custom property to set instead of `border-radius` (Avatar traces `--avatar-radius`). */
  radiusProp?: string;
  /**
   * An owner decision that exempts this control from the 0.4 rule. Absent means the rule applies,
   * which is the answer D47 gave for avatars, checkboxes and the round header buttons (DESIGN.md Q5).
   * The generator emits the named shape instead of the formula and nothing else, so the exception
   * cannot drift into a typed number.
   */
  exception?: Exception;
  /** Proposed extension, skipped by the generator until the owner flips it. */
  pendingOwner?: boolean;
  note?: string;
};

export type BoxRow = {
  kind: "box";
  selector: string;
  source: string;
  /** Physical corners, for HeroUI rules that round one edge (sheets). Default all four. */
  corners?: "all" | "top" | "bottom" | "left" | "right";
  /**
   * Clip children to the rounded corners. `clip`, not `hidden`: `overflow: hidden`
   * would turn the box into a scroll container and break `position: sticky` inside it.
   */
  clip?: boolean;
  pendingOwner?: boolean;
  note?: string;
};

export type Row = ControlRow | BoxRow;

const PILL: Exception = {decision: "D47", shape: "pill"};

const step = (n: number) => `calc(var(--spacing) * ${n})`;

// Padding 2 steps each side, border 1px each side, plus one text line.
const field = (line: string) => `calc(var(--spacing) * 4 + ${line} + 2px)`;
const FIELD_TALL = field("1.5rem"); // text-base, below sm
const FIELD_SHORT = field("1.25rem"); // sm:text-sm, from sm

export const rows: Row[] = [
  // Buttons. Icon-only buttons are the same height, so the same rows serve them.
  {kind: "control", selector: ".button", height: {base: step(10), md: step(9)}, source: "button.css (h-10 md:h-9)"},
  {kind: "control", selector: ".button--sm", height: {base: step(9), md: step(8)}, source: "button.css (h-9 md:h-8)"},
  {kind: "control", selector: ".button--lg", height: {base: step(11), md: step(10)}, source: "button.css (h-11 md:h-10)"},

  // Single-line fields. Input text is text-base below sm and text-sm from sm.
  {kind: "control", selector: ".input", height: {base: FIELD_TALL, sm: FIELD_SHORT}, source: "input.css, derived"},
  {
    kind: "control",
    selector: ".textarea",
    height: {base: FIELD_TALL, sm: FIELD_SHORT},
    source: "textarea.css, derived",
    note: "A multi-line box keeps the one-line field radius, not 0.4 x its own height (DESIGN.md).",
  },
  {kind: "control", selector: ".select__trigger", height: {base: FIELD_TALL, sm: FIELD_SHORT}, source: "select.css, derived (min-h-9 is below the natural height)"},
  {kind: "control", selector: ".autocomplete__trigger", height: {base: FIELD_TALL, sm: FIELD_SHORT}, source: "autocomplete.css, derived"},
  {kind: "control", selector: ".native-select__select", height: {base: FIELD_SHORT}, source: "native-select.css, derived (text-sm at every width, unlike Input)"},
  {kind: "control", selector: ".input-group", height: {base: FIELD_TALL, sm: FIELD_SHORT}, source: "input-group.css, derived"},
  {kind: "control", selector: ".search-field__group", height: {base: step(9)}, source: "search-field.css (h-9)"},
  {kind: "control", selector: ".number-field__group", height: {base: step(9)}, source: "number-field.css (h-9)"},
  {kind: "control", selector: ".date-input-group", height: {base: step(9)}, source: "date-input-group.css (h-9)"},
  {kind: "control", selector: ".color-input-group", height: {base: step(9)}, source: "color-input-group.css (h-9)"},
  {kind: "control", selector: ".input-otp__slot", height: {base: step(10)}, source: "input-otp.css (h-10)"},
  {kind: "control", selector: ".cell-select .cell-select__trigger", height: {base: step(9)}, source: "cell-select.css (h-9)"},
  {
    kind: "control",
    selector: ".cell-switch .cell-switch__trigger",
    height: {base: step(9)},
    source: "cell-switch.css (h-9)",
    note: "The row follows the rule. The track inside is a stock Switch.Control, so the D47 pill rows below reach it too.",
  },
  {kind: "control", selector: ".cell-color-picker .cell-color-picker__trigger", height: {base: step(9)}, source: "cell-color-picker.css (h-9)"},
  {kind: "control", selector: ".cell-slider .cell-slider__track", height: {base: step(9)}, source: "cell-slider.css (h-9)"},
  {kind: "control", selector: ".select__clear-button", height: {base: step(5)}, source: "select.css (size-5)"},
  {kind: "control", selector: ".autocomplete__clear-button", height: {base: step(5)}, source: "autocomplete.css (size-5)"},

  // Tabs. The list is the pill: tab h-8 plus p-1 twice.
  {kind: "control", selector: ".tabs__list-container", height: {base: step(10)}, source: "tabs.css (tab h-8 + p-1 x2)"},
  {kind: "control", selector: ".tabs__list", height: {base: step(10)}, source: "tabs.css (tab h-8 + p-1 x2)"},
  {kind: "control", selector: ".tabs__tab", height: {base: step(8)}, source: "tabs.css (h-8)"},
  {kind: "control", selector: ".tabs__indicator", height: {base: step(8)}, source: "tabs.css (size-full of a h-8 tab)"},

  // Segment. HeroUI has no container size class: the container is as tall as its
  // items plus padding, so the md container is `.segment` itself.
  {kind: "control", selector: ".segment", height: {base: step(10)}, source: "segment.css (item h-8 + p-1 x2)"},
  {kind: "control", selector: ".segment--sm", height: {base: step(8)}, source: "segment.css (item h-7 + p-0.5 x2)"},
  {kind: "control", selector: ".segment:has(.segment__item--lg)", height: {base: step(12)}, source: "segment.css (item h-10 + p-1 x2)"},
  {kind: "control", selector: ".segment__item", height: {base: step(8)}, source: "segment.css (h-8)"},
  {kind: "control", selector: ".segment__item--sm", height: {base: step(7)}, source: "segment.css (h-7)"},
  {kind: "control", selector: ".segment__item--lg", height: {base: step(10)}, source: "segment.css (h-10)"},

  // Pagination. The size classes sit on the parent, so the selectors are nested.
  {kind: "control", selector: ".pagination__link", height: {base: step(9), md: step(8)}, source: "pagination.css (size-9 md:size-8)"},
  {kind: "control", selector: ".pagination--sm .pagination__link", height: {base: step(8), md: step(7)}, source: "pagination.css (size-8 md:size-7)"},
  {kind: "control", selector: ".pagination--lg .pagination__link", height: {base: step(10), md: step(9)}, source: "pagination.css (size-10 md:size-9)"},

  // NumberStepper. HeroUI Pro's group and buttons are stock pills (radius 3.4e38px).
  // A size modifier adds p-0.5 twice, which is one spacing step. The bare group has
  // p-0 and is as tall as its button, and the modifier rows below come later and win.
  {kind: "control", selector: ".number-stepper__group", height: {base: step(9), md: step(8)}, source: "number-stepper.css (button h-9 md:h-8, p-0)"},
  {kind: "control", selector: ".number-stepper__group--sm", height: {base: `calc(${step(8)} + var(--spacing))`, md: `calc(${step(7)} + var(--spacing))`}, source: "number-stepper.css"},
  {kind: "control", selector: ".number-stepper__group--md", height: {base: `calc(${step(9)} + var(--spacing))`, md: `calc(${step(8)} + var(--spacing))`}, source: "number-stepper.css"},
  {kind: "control", selector: ".number-stepper__group--lg", height: {base: `calc(${step(10)} + var(--spacing))`, md: `calc(${step(9)} + var(--spacing))`}, source: "number-stepper.css"},
  {kind: "control", selector: ".number-stepper__decrement-button, .number-stepper__increment-button", height: {base: step(9), md: step(8)}, source: "number-stepper.css (h-9 md:h-8)"},
  {kind: "control", selector: ".number-stepper__decrement-button--sm, .number-stepper__increment-button--sm", height: {base: step(8), md: step(7)}, source: "number-stepper.css"},
  {kind: "control", selector: ".number-stepper__decrement-button--md, .number-stepper__increment-button--md", height: {base: step(9), md: step(8)}, source: "number-stepper.css"},
  {kind: "control", selector: ".number-stepper__decrement-button--lg, .number-stepper__increment-button--lg", height: {base: step(10), md: step(9)}, source: "number-stepper.css"},

  // Chip, Badge, Kbd. Chip height is its line (leading-5) plus py.
  {kind: "control", selector: ".chip", height: {base: step(6)}, source: "chip.css (leading-5 + py-0.5 x2)"},
  {kind: "control", selector: ".chip--sm", height: {base: step(5)}, source: "chip.css (leading-5, py-0)"},
  {kind: "control", selector: ".chip--lg", height: {base: step(7)}, source: "chip.css (leading-5 + py-1 x2)"},
  {kind: "control", selector: ".badge", height: {base: step(7)}, source: "badge.css (min-h-7)"},
  {kind: "control", selector: ".badge--sm", height: {base: step(4)}, source: "badge.css (min-h-4)"},
  {kind: "control", selector: ".badge--lg", height: {base: step(8)}, source: "badge.css (min-h-8)"},
  {kind: "control", selector: ".kbd", height: {base: step(6)}, source: "kbd.css (h-6)"},

  // Very small controls: DESIGN.md Q5, answered by D47. Avatars and the checkbox follow the formula.
  // The switch is the one exception: a pill track and a pill thumb, like stock HeroUI. The height is
  // kept because the DESIGN.md table and the lab test read it; it no longer feeds a radius.
  {kind: "control", selector: ".avatar", height: {base: step(10)}, radiusProp: "--avatar-radius", source: "avatar.css (size-10)"},
  {kind: "control", selector: ".avatar--sm", height: {base: step(8)}, radiusProp: "--avatar-radius", source: "avatar.css (size-8)"},
  {kind: "control", selector: ".avatar--lg", height: {base: step(12)}, radiusProp: "--avatar-radius", source: "avatar.css (size-12)"},
  {kind: "control", selector: ".switch__control", height: {base: "1.25rem"}, source: "switch.css (fixed rem, not scaled by --spacing)", exception: PILL},
  {kind: "control", selector: ".switch--sm .switch__control", height: {base: "1rem"}, source: "switch.css", exception: PILL},
  {kind: "control", selector: ".switch--lg .switch__control", height: {base: "1.5rem"}, source: "switch.css", exception: PILL},
  {kind: "control", selector: ".switch__thumb", height: {base: "1rem"}, source: "switch.css", exception: PILL},
  {kind: "control", selector: ".switch--sm .switch__thumb", height: {base: "0.75rem"}, source: "switch.css", exception: PILL},
  {kind: "control", selector: ".switch--lg .switch__thumb", height: {base: "1.25rem"}, source: "switch.css", exception: PILL},
  {kind: "control", selector: ".checkbox__control", height: {base: step(4)}, source: "checkbox.css (size-4)"},

  // Icon tiles and the sidebar item.
  {kind: "control", selector: ".item-card__icon", height: {base: step(9)}, source: "item-card.css (size-9)"},
  {kind: "control", selector: ".kpi__icon", height: {base: step(8)}, source: "kpi.css (size-8)"},
  {kind: "control", selector: ".modal__icon", height: {base: step(10)}, source: "modal.css (size-10)"},
  {kind: "control", selector: ".sidebar__menu-item-content", height: {base: step(9)}, source: "sidebar.css (min-h-9); spec 6.2"},

  // Tiles and chrome of our own. A component that needs a rounded square names a row here
  // instead of typing the formula or a pixel value, so the ratio and the cap stay in one place.
  // `.tile-N` is a square of N spacing steps (use it with `size-N`).
  {kind: "control", selector: ".tile-6", height: {base: step(6)}, source: "our own: a 6-step square, the redirect flag of a profile icon"},
  {kind: "control", selector: ".tile-11", height: {base: step(11)}, source: "our own: an 11-step square, the profile icon of a list row"},
  {kind: "control", selector: ".service-logo", height: {base: step(9)}, source: "icons/ServiceLogo.tsx (size-9)"},
  {kind: "control", selector: ".skip-link", height: {base: step(9)}, source: "shell.css, skip link (spec 8.1)"},
  {kind: "control", selector: ".page-header__icon", height: {base: step(10)}, source: "shell.css, page header icon (size-10)"},

  // Owner examples (D16). These are utilities our own code uses.
  {kind: "control", selector: ".control-50", height: {base: "var(--size-50)"}, setsHeight: true, source: "D16: height 50 gives radius 20"},
  {kind: "control", selector: ".control-75", height: {base: "var(--size-75)"}, setsHeight: true, source: "D16: height 75 gives radius 30, the cap"},

  // Boxes and sections: always --radius-box.
  {kind: "box", selector: ".card", source: "card.css (min(32px, 3 x radius))"},
  {kind: "box", selector: ".modal__dialog", source: "modal.css"},
  {kind: "box", selector: ".sheet__content[data-detached]", source: "sheet.css (rounded-2xl)"},
  {kind: "box", selector: ".sheet__content[data-detached] .sheet__dialog", source: "sheet.css (rounded-2xl)"},
  {kind: "box", selector: ".sheet__content--bottom", corners: "top", source: "sheet.css (rounded-t-2xl)"},
  {kind: "box", selector: ".sheet__content--top", corners: "bottom", source: "sheet.css (rounded-b-2xl)"},
  {kind: "box", selector: ".sheet__content--left", corners: "right", source: "sheet.css (rounded-r-2xl)"},
  {kind: "box", selector: ".sheet__content--right", corners: "left", source: "sheet.css (rounded-l-2xl)"},
  {kind: "box", selector: ".sheet__dialog--bottom", corners: "top", source: "sheet.css (rounded-t-2xl)"},
  {kind: "box", selector: ".sheet__dialog--top", corners: "bottom", source: "sheet.css (rounded-b-2xl)"},
  {kind: "box", selector: ".sheet__dialog--left", corners: "right", source: "sheet.css (rounded-r-2xl)"},
  {kind: "box", selector: ".sheet__dialog--right", corners: "left", source: "sheet.css (rounded-l-2xl)"},
  {kind: "box", selector: ".popover", source: "popover.css (min(32px, 3 x radius))"},
  {kind: "box", selector: ".dropdown__popover", source: "dropdown.css (min(32px, 2 x radius + 1.5 x spacing))"},
  {kind: "box", selector: ".data-grid", clip: true, source: "data-grid.css has none; the wrapper gets 20px and clips its table"},
  {kind: "box", selector: ".table-root--primary", source: "table.css (min(32px, 2.5 x radius), which is 20px at radius 8; kept so it cannot drift)"},
  {kind: "box", selector: ".kpi", source: "kpi.css (2 x radius)"},
  {kind: "box", selector: ".item-card", source: "item-card.css (2 x radius)"},

  // Proposed extensions (DESIGN.md "Same class, proposed extension"). Skipped by the
  // generator until the owner flips `pendingOwner`.
  {kind: "box", selector: ".item-card-group", pendingOwner: true, clip: true, source: "item-card-group.css (2 x radius)"},
  {kind: "box", selector: ".widget", pendingOwner: true, source: "widget.css (2 x radius)"},
  {kind: "box", selector: ".alert", pendingOwner: true, source: "alert.css (min(32px, 3 x radius))"},
  {kind: "box", selector: ".toast", pendingOwner: true, source: "toast.css (min(32px, 3 x radius))"},
  {kind: "box", selector: ".accordion--surface", pendingOwner: true, source: "accordion.css (min(32px, 3 x radius))"},
  {kind: "box", selector: ".select__popover", pendingOwner: true, source: "select.css (min(32px, 2 x radius + 1.5 x spacing))"},
  {kind: "box", selector: ".autocomplete__popover", pendingOwner: true, source: "autocomplete.css"},
  {kind: "box", selector: ".combo-box__popover", pendingOwner: true, source: "combo-box.css"},
  {kind: "box", selector: ".sidebar--floating", pendingOwner: true, source: "sidebar.css (2 x radius)"},
];
