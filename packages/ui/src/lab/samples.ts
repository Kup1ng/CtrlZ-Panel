// The two lists of selectors that the token lab does not draw as bare markup, as plain data, so that the lab, its
// unit test and the radius spec (apps/panel/e2e/radius.spec.ts, which runs in Node and cannot load a component)
// read one list. TokenLab.tsx types its sample maps by these, so a selector in a list without a sample, or a sample
// without a selector, fails the type checker; the unit test and the spec check the other side, that each selector is
// still a row of tokens/radius.table.ts. Without that, a renamed row would turn a component sample into bare markup
// and every test would stay green (wp11-r1-1).

/** Rows drawn with the real component, where its height comes from content or the product uses the component. */
export const COMPONENT_SELECTORS = [
  ".button",
  ".button--sm",
  ".button--lg",
  ".input",
  ".textarea",
  ".select__trigger",
  ".autocomplete__trigger",
  ".native-select__select",
  ".input-group",
  ".search-field__group",
  ".number-field__group",
  ".input-otp__slot",
  ".cell-switch .cell-switch__trigger",
  ".tabs__list-container",
  ".tabs__list",
  ".tabs__tab",
  ".tabs__indicator",
  ".segment",
  ".segment--sm",
  ".segment:has(.segment__item--lg)",
  ".segment__item",
  ".segment__item--sm",
  ".segment__item--lg",
  ".pagination__link",
  ".pagination--sm .pagination__link",
  ".pagination--lg .pagination__link",
  ".chip",
  ".chip--sm",
  ".chip--lg",
  ".badge",
  ".badge--sm",
  ".badge--lg",
  ".kbd",
  ".avatar",
  ".avatar--sm",
  ".avatar--lg",
  ".switch__control",
  ".switch--sm .switch__control",
  ".switch--lg .switch__control",
  ".switch__thumb",
  ".switch--sm .switch__thumb",
  ".switch--lg .switch__thumb",
  ".checkbox__control",
  ".item-card__icon",
  ".item-card",
  ".kpi__icon",
  ".kpi",
  ".card",
  ".alert",
] as const;

/** Rows drawn by hand: markup that holds more than the selector names (the stepper group is as tall as its buttons; a toast needs the queue of its region, so the lab draws its anatomy). */
export const HAND_SELECTORS = [
  ".number-stepper__group",
  ".number-stepper__group--sm",
  ".number-stepper__group--md",
  ".number-stepper__group--lg",
  ".number-stepper__decrement-button, .number-stepper__increment-button",
  ".number-stepper__decrement-button--sm, .number-stepper__increment-button--sm",
  ".number-stepper__decrement-button--md, .number-stepper__increment-button--md",
  ".number-stepper__decrement-button--lg, .number-stepper__increment-button--lg",
  ".toast",
] as const;

export type ComponentSelector = (typeof COMPONENT_SELECTORS)[number];
export type HandSelector = (typeof HAND_SELECTORS)[number];
