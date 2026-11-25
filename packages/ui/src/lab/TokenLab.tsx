"use client";

import {
  Autocomplete,
  Avatar,
  Badge,
  Button,
  Card,
  Checkbox,
  Chip,
  Input,
  InputGroup,
  InputOTP,
  Kbd,
  ListBox,
  NumberField,
  Pagination,
  SearchField,
  Select,
  Switch,
  Tabs,
  TextArea,
} from "@heroui/react";
import {CellSwitch, ItemCard, NativeSelect, Segment} from "@heroui-pro/react";
import {KPI} from "@heroui-pro/react/kpi";
import {useTranslations} from "next-intl";
import {createElement, type ReactNode} from "react";

import {rows, type Row} from "../../tokens/radius.table.ts";
import {PageHeader} from "../shell/PageHeader.tsx";
import {Tech} from "../data/Tech.tsx";
import {bareMarkup, type BareNode} from "./bareMarkup.ts";
import {COMPONENT_SELECTORS, HAND_SELECTORS, type ComponentSelector, type HandSelector} from "./samples.ts";
import {SectionTitle} from "./SectionTitle.tsx";

// Spec 6.3 (T-474). One sample of every row of tokens/radius.table.ts, for apps/panel/e2e/radius.spec.ts, which
// reads the same table, finds each sample by its row index, and measures the height and the corner radius of the
// elements the row's selector matches. Nothing here repeats a number: the page draws, the test compares.
//
// A row is drawn with a real component where its height comes from the content (a field's text line, a chip's
// leading) or where the component is what the product uses. Otherwise it is drawn as the smallest markup that
// carries the row's classes (bareMarkup.ts), which is the honest test of a stylesheet rule: HeroUI's own height
// classes (`h-9`, `size-10`, `min-h-7`) apply to a bare element exactly as they do to a component's. A sample says
// which it is in `data-sample`, so a reader of a failure knows what was measured. Overlays (popover, sheet, modal,
// dropdown) are bare: an open overlay would not sit on a page, and the radius is a rule of the stylesheet.
//
// The page is closed unless CTRLZ_LAB is "1" (the (lab) layout).

// Rows that the stylesheet gives no height to, so a bare element of the class would be zero high. Our own tiles
// and chrome are sized by the Tailwind class their component adds (`size-11`), which the row's source names.
const BARE_SIZE: Record<string, string> = {
  ".tile-6": "size-6",
  ".tile-11": "size-11",
  ".row-counter": "h-10 w-16",
  ".service-logo": "size-9",
  ".skip-link": "h-9 w-24",
  ".page-header__icon": "size-10",
  ".control-50": "w-24",
  ".control-75": "w-24",
  ".select__clear-button": "w-5",
  ".autocomplete__clear-button": "w-5",
};

// For a box, `extra` goes to every node of a chain, not only the root: a box row such as `.sheet__content[data-detached]
// .sheet__dialog` names the child, and a child with no height of its own is zero high, so its radius would be read
// from an element that draws nothing (wp11-r1-2).
function Bare({node, extra, deep = false}: {node: BareNode; extra?: string; deep?: boolean}) {
  const className = [...node.classes, extra].filter(Boolean).join(" ");
  return createElement(
    "div",
    {className, ...node.attrs},
    node.children.map((child, i) => <Bare key={i} node={child} extra={deep ? extra : undefined} deep={deep} />),
  );
}

// A box is 20px "at any height" (spec 6.3), so a bare box is drawn twice, short and tall, and the spec reads both.
const BOX_HEIGHTS = ["h-8 w-full", "h-40 w-full"] as const;

function bareSample(row: Row) {
  // A control with no size class of ours is as wide as its cell, so that it reads as a field in the lab.
  const extras = row.kind === "box" ? BOX_HEIGHTS : [BARE_SIZE[row.selector] ?? "w-full"];
  return (
    <div className="flex flex-wrap items-start gap-2">
      {extras.flatMap((extra) => bareMarkup(row.selector).map((node, i) => <Bare key={`${extra}-${i}`} node={node} extra={extra} deep={row.kind === "box"} />))}
    </div>
  );
}

// input-otp writes a <style> of its own in an effect, which the page's CSP allows only with the page's nonce.
// forms/OtpField.tsx reads it the same way (WP8's file, so the few lines are repeated, not imported).
function pageNonce(): string | undefined {
  if (typeof document === "undefined") return undefined;
  // The .nonce property: the attribute reads "" in a document with a CSP header, and the tag carries the nonce there and not as content (gate-r30-1).
  return (document.querySelector('meta[name="csp-nonce"]') as HTMLMetaElement | null)?.nonce || undefined;
}

type T = ReturnType<typeof useTranslations<"lab.tokenLab">>;

// Pro's NumberStepper needs a peer that this project does not install, so its rows are markup, and the group
// carries buttons of its own size (the group is as tall as them, spec 6.1).
function stepper(size: "sm" | "md" | "lg" | null) {
  const mod = size ? `--${size}` : "";
  return (
    <div className={`number-stepper__group${mod} inline-flex`}>
      <div className={`number-stepper__decrement-button${mod}`} />
      <div className={`number-stepper__increment-button${mod}`} />
    </div>
  );
}

// One Tabs serves the four rows (list container, list, tab, indicator): the test finds each by its own selector.
function tabs(t: T) {
  return (
    <Tabs defaultSelectedKey="a">
      <Tabs.ListContainer>
        <Tabs.List aria-label={t("tab")}>
          <Tabs.Tab id="a">
            {t("tab")}
            <Tabs.Indicator />
          </Tabs.Tab>
        </Tabs.List>
      </Tabs.ListContainer>
    </Tabs>
  );
}

function segment(t: T, size: "sm" | "md" | "lg") {
  return (
    <Segment aria-label={t("tab")} defaultSelectedKey="a" size={size}>
      <Segment.Item id="a">{t("tab")}</Segment.Item>
      <Segment.Item id="b">{t("tab")}</Segment.Item>
    </Segment>
  );
}

function pagination(t: T, size?: "sm" | "lg") {
  return (
    <Pagination size={size}>
      <Pagination.Content>
        <Pagination.Item>
          <Pagination.Link isActive>{t("page")}</Pagination.Link>
        </Pagination.Item>
      </Pagination.Content>
    </Pagination>
  );
}

function chip(t: T, size?: "sm" | "lg") {
  return (
    <Chip size={size}>
      <Chip.Label>{t("chipLabel")}</Chip.Label>
    </Chip>
  );
}

function badge(t: T, size?: "sm" | "lg") {
  return (
    <Badge.Anchor>
      <Avatar size="sm">
        <Avatar.Fallback>{t("avatarInitial")}</Avatar.Fallback>
      </Avatar>
      <Badge color="accent" size={size}>
        {t("badgeLabel")}
      </Badge>
    </Badge.Anchor>
  );
}

function avatar(t: T, size?: "sm" | "lg") {
  return (
    <Avatar size={size}>
      <Avatar.Fallback>{t("avatarInitial")}</Avatar.Fallback>
    </Avatar>
  );
}

function sw(t: T, size: "sm" | "md" | "lg") {
  return (
    <Switch aria-label={t("sample")} defaultSelected size={size}>
      <Switch.Content>
        <Switch.Control>
          <Switch.Thumb />
        </Switch.Control>
      </Switch.Content>
    </Switch>
  );
}

function button(t: T, size?: "sm" | "lg") {
  return <Button size={size}>{t("sample")}</Button>;
}

function select(t: T) {
  return (
    <Select aria-label={t("sample")} className="w-full" placeholder={t("sample")}>
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox>
          <ListBox.Item id="a" textValue={t("option")}>
            {t("option")}
          </ListBox.Item>
        </ListBox>
      </Select.Popover>
    </Select>
  );
}

function autocomplete(t: T) {
  return (
    <Autocomplete aria-label={t("sample")} className="w-full" placeholder={t("sample")}>
      <Autocomplete.Trigger>
        <Autocomplete.Value />
        <Autocomplete.Indicator />
      </Autocomplete.Trigger>
      <Autocomplete.Popover>
        <Autocomplete.Filter>
          <ListBox>
            <ListBox.Item id="a" textValue={t("option")}>
              {t("option")}
            </ListBox.Item>
          </ListBox>
        </Autocomplete.Filter>
      </Autocomplete.Popover>
    </Autocomplete>
  );
}

// Samples drawn by hand, not by a component and not by bareMarkup.ts, because the markup has to hold more than the
// selector names: the stepper's group is as tall as the buttons inside it.
const HAND: Record<HandSelector, () => ReactNode> = {
  ".number-stepper__group": () => stepper(null),
  ".number-stepper__group--sm": () => stepper("sm"),
  ".number-stepper__group--md": () => stepper("md"),
  ".number-stepper__group--lg": () => stepper("lg"),
  ".number-stepper__decrement-button, .number-stepper__increment-button": () => stepper(null),
  ".number-stepper__decrement-button--sm, .number-stepper__increment-button--sm": () => stepper("sm"),
  ".number-stepper__decrement-button--md, .number-stepper__increment-button--md": () => stepper("md"),
  ".number-stepper__decrement-button--lg, .number-stepper__increment-button--lg": () => stepper("lg"),
};

// The samples that are components. A selector the table has and this map does not is drawn as bare markup.
const REAL: Record<ComponentSelector, (t: T) => ReactNode> = {
  ".button": (t) => button(t),
  ".button--sm": (t) => button(t, "sm"),
  ".button--lg": (t) => button(t, "lg"),
  ".input": (t) => <Input aria-label={t("sample")} className="w-full" placeholder={t("sample")} />,
  ".textarea": (t) => <TextArea aria-label={t("sample")} className="w-full" placeholder={t("sample")} rows={1} />,
  ".select__trigger": select,
  ".autocomplete__trigger": autocomplete,
  ".native-select__select": (t) => (
    <NativeSelect className="w-full">
      <NativeSelect.Trigger aria-label={t("sample")}>
        <NativeSelect.Option value="a">{t("option")}</NativeSelect.Option>
        <NativeSelect.Option value="b">{t("optionOther")}</NativeSelect.Option>
        <NativeSelect.Indicator />
      </NativeSelect.Trigger>
    </NativeSelect>
  ),
  ".input-group": (t) => (
    <InputGroup className="w-full">
      <InputGroup.Prefix>
        <Tech>{t("prefix")}</Tech>
      </InputGroup.Prefix>
      <InputGroup.Input aria-label={t("sample")} placeholder={t("sample")} />
    </InputGroup>
  ),
  ".search-field__group": (t) => (
    <SearchField aria-label={t("search")} className="w-full">
      <SearchField.Group>
        <SearchField.SearchIcon />
        <SearchField.Input placeholder={t("search")} />
        <SearchField.ClearButton />
      </SearchField.Group>
    </SearchField>
  ),
  ".number-field__group": (t) => (
    <NumberField aria-label={t("number")} className="w-full" defaultValue={3}>
      <NumberField.Group>
        <NumberField.DecrementButton aria-label={t("stepperMinus")} />
        <NumberField.Input />
        <NumberField.IncrementButton aria-label={t("stepperPlus")} />
      </NumberField.Group>
    </NumberField>
  ),
  ".input-otp__slot": (t) => (
    <InputOTP aria-label={t("code")} maxLength={2} nonce={pageNonce()}>
      <InputOTP.Group>
        <InputOTP.Slot index={0} />
        <InputOTP.Slot index={1} />
      </InputOTP.Group>
    </InputOTP>
  ),
  ".cell-switch .cell-switch__trigger": (t) => (
    <CellSwitch defaultSelected aria-label={t("cellLabel")} className="w-full">
      <CellSwitch.Trigger>
        <CellSwitch.Label>{t("cellLabel")}</CellSwitch.Label>
        <CellSwitch.Control />
      </CellSwitch.Trigger>
    </CellSwitch>
  ),
  ".tabs__list-container": (t) => tabs(t),
  ".tabs__list": (t) => tabs(t),
  ".tabs__tab": (t) => tabs(t),
  ".tabs__indicator": (t) => tabs(t),
  ".segment": (t) => segment(t, "md"),
  ".segment--sm": (t) => segment(t, "sm"),
  ".segment:has(.segment__item--lg)": (t) => segment(t, "lg"),
  ".segment__item": (t) => segment(t, "md"),
  ".segment__item--sm": (t) => segment(t, "sm"),
  ".segment__item--lg": (t) => segment(t, "lg"),
  ".pagination__link": (t) => pagination(t),
  ".pagination--sm .pagination__link": (t) => pagination(t, "sm"),
  ".pagination--lg .pagination__link": (t) => pagination(t, "lg"),
  ".chip": (t) => chip(t),
  ".chip--sm": (t) => chip(t, "sm"),
  ".chip--lg": (t) => chip(t, "lg"),
  ".badge": (t) => badge(t),
  ".badge--sm": (t) => badge(t, "sm"),
  ".badge--lg": (t) => badge(t, "lg"),
  ".kbd": (t) => (
    <Kbd>
      <Kbd.Content>{t("kbdKey")}</Kbd.Content>
    </Kbd>
  ),
  ".avatar": (t) => avatar(t),
  ".avatar--sm": (t) => avatar(t, "sm"),
  ".avatar--lg": (t) => avatar(t, "lg"),
  ".switch__control": (t) => sw(t, "md"),
  ".switch--sm .switch__control": (t) => sw(t, "sm"),
  ".switch--lg .switch__control": (t) => sw(t, "lg"),
  ".switch__thumb": (t) => sw(t, "md"),
  ".switch--sm .switch__thumb": (t) => sw(t, "sm"),
  ".switch--lg .switch__thumb": (t) => sw(t, "lg"),
  ".checkbox__control": (t) => (
    <Checkbox aria-label={t("sample")} defaultSelected>
      <Checkbox.Content>
        <Checkbox.Control>
          <Checkbox.Indicator />
        </Checkbox.Control>
      </Checkbox.Content>
    </Checkbox>
  ),
  ".item-card__icon": (t) => itemCard(t),
  ".item-card": (t) => itemCard(t),
  ".kpi__icon": (t) => kpi(t),
  ".kpi": (t) => kpi(t),
  ".card": (t) => (
    <Card>
      <Card.Content>{t("sample")}</Card.Content>
    </Card>
  ),
};

function itemCard(t: T) {
  return (
    <ItemCard>
      <ItemCard.Icon>
        <span aria-hidden className="size-4 rounded-full bg-current" />
      </ItemCard.Icon>
      <ItemCard.Content>
        <ItemCard.Title>{t("itemTitle")}</ItemCard.Title>
        <ItemCard.Description>{t("itemText")}</ItemCard.Description>
      </ItemCard.Content>
    </ItemCard>
  );
}

function kpi(t: T) {
  return (
    <KPI>
      <KPI.Header>
        <KPI.Icon>
          <span aria-hidden className="size-4 rounded-full bg-current" />
        </KPI.Icon>
        <KPI.Title role="term">{t("kpiTitle")}</KPI.Title>
      </KPI.Header>
      <KPI.Content>
        <span className="kpi__value">{t("kpiValue")}</span>
      </KPI.Content>
    </KPI>
  );
}

const isComponent = (selector: string): selector is ComponentSelector => (COMPONENT_SELECTORS as readonly string[]).includes(selector);
const isHand = (selector: string): selector is HandSelector => (HAND_SELECTORS as readonly string[]).includes(selector);

export function TokenLab() {
  const t = useTranslations("lab.tokenLab");
  // The test finds a sample by the row's index in the table, which pending rows keep, so a row that the owner
  // flips later does not renumber the others.
  const drawn = rows.map((row, index) => ({row, index})).filter(({row}) => !row.pendingOwner);

  return (
    <>
      <PageHeader icon="activityLog" title={t("title")} subtitle={t("subtitle")} />
      <div className="@container flex flex-col gap-8">
        <p className="max-w-prose text-sm text-muted">{t("intro")}</p>
        {(["control", "box"] as const).map((kind) => (
          <section key={kind} aria-labelledby={`radius-${kind}`} className="flex flex-col gap-3">
            <SectionTitle id={`radius-${kind}`} title={t(kind === "control" ? "controls" : "boxes")} />
            <ul className="grid list-none grid-cols-1 gap-3 p-0 @lg:grid-cols-2 @3xl:grid-cols-3">
              {drawn
                .filter(({row}) => row.kind === kind)
                .map(({row, index}) => {
                  const real = isComponent(row.selector) ? REAL[row.selector] : undefined;
                  const hand = isHand(row.selector) ? HAND[row.selector] : undefined;
                  return (
                    <li
                      key={row.selector}
                      className="flex min-w-0 flex-col gap-2 rounded-(--radius-box) bg-surface p-3 shadow-surface"
                      data-radius-row={index}
                      data-sample={real ? "component" : "markup"}
                    >
                      <Tech className="text-xs break-all text-muted">{row.selector}</Tech>
                      {/* contain-layout: a bare overlay class may be position: fixed, and must stay in its cell. */}
                      <div className="relative min-w-0 overflow-clip contain-layout">{real ? real(t) : hand ? hand() : bareSample(row)}</div>
                    </li>
                  );
                })}
            </ul>
          </section>
        ))}
      </div>
    </>
  );
}
