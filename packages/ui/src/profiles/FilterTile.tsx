"use client";

import {Button, buttonVariants, Chip, Description, Popover, Radio, RadioGroup, Switch} from "@heroui/react";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon, hasSubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {ItemTile} from "../data/CardGrid.tsx";
import {MODE_LEVEL, MODE_LEVEL_MAX, NEW_DOMAINS, type FilterCard} from "./filtersModel.ts";

// One card of the Filters grid, Native or 3rd Party (spec p2 9.3, WF "Filters"): the filter's icon at the start and its switch at the end,
// then the name, the status in words (Blocked while it is on, Allowed while it is off), the mode with its menu, and the info button.
//
// The switch and the mode menu are controls of their own with the filter's name in their accessible names; the card is not a button.
// "Choosing a mode applies at once" (T-147): there is no preview and no Save.

export type FilterTileProps = {
  card: FilterCard;
  name: string;
  readOnly: boolean;
  onToggle: (enabled: boolean) => void;
  onMode: (mode: string) => void;
  onInfo: () => void;
};

const BAR_HEIGHT = ["h-1.5", "h-2", "h-2.5"] as const;

/** The strength of a mode as three segments. Decoration: the name of the mode is beside it, and the level is in words for a reader. */
function ModeMeter({mode}: {mode: string}) {
  const level = MODE_LEVEL[mode];
  if (level === undefined) return <Icon name="filters" className="size-4 shrink-0" />;
  return (
    <span aria-hidden="true" className="mode-meter inline-flex shrink-0 items-end gap-0.5">
      {Array.from({length: MODE_LEVEL_MAX}, (_, i) => (
        <span key={i} data-on={i < level || undefined} className={["bg-muted/40 data-[on]:bg-foreground inline-block w-1", BAR_HEIGHT[i]].join(" ")} />
      ))}
    </span>
  );
}

/** The mode's name from the messages, or the catalogue's own word for one that has no text yet. */
function useModeText() {
  const t = useTranslations("profiles");
  return {
    name: (mode: string) => (t.has(`filters.modes.${mode}.name` as never) ? t(`filters.modes.${mode}.name` as never) : mode),
    text: (mode: string) => (t.has(`filters.modes.${mode}.text` as never) ? t(`filters.modes.${mode}.text` as never) : ""),
  };
}

function ModeMenu({card, name, readOnly, onMode}: {card: FilterCard; name: string; readOnly: boolean; onMode: (mode: string) => void}) {
  const t = useTranslations("profiles");
  const modeText = useModeText();
  const [open, setOpen] = useState(false);
  const current = card.mode ?? card.modes[0]!;
  return (
    <Popover isOpen={open} onOpenChange={setOpen}>
      <Button
        size="sm"
        variant="secondary"
        isDisabled={readOnly}
        className="min-w-0 max-w-full justify-start gap-1.5"
        aria-label={t("filters.modeButton", {name, mode: modeText.name(current)})}
      >
        <ModeMeter mode={current} />
        <span className="truncate">{modeText.name(current)}</span>
        <Icon name="chevron" className="size-3.5 shrink-0 rotate-90" />
      </Button>
      <Popover.Content placement="bottom start" className="w-72 max-w-[calc(100vw-2rem)]">
        <Popover.Dialog aria-label={t("filters.modeTitle", {name})} className="flex flex-col gap-2 p-1">
          <RadioGroup
            aria-label={t("filters.modeGroup", {name})}
            value={current}
            onChange={(value) => {
              setOpen(false);
              if (value !== current) onMode(value);
            }}
            className="flex flex-col gap-1"
          >
            {card.modes.map((mode) => (
              <Radio key={mode} value={mode} className="w-full">
                <Radio.Content className="flex w-full min-w-0 items-center gap-2 py-1">
                  <Radio.Control>
                    <Radio.Indicator />
                  </Radio.Control>
                  <ModeMeter mode={mode} />
                  <span className="min-w-0 flex-1 text-sm">{modeText.name(mode)}</span>
                </Radio.Content>
                <Description className="ps-7 text-xs">{modeText.text(mode)}</Description>
              </Radio>
            ))}
          </RadioGroup>
          {card.id === NEW_DOMAINS ? (
            <p className="text-muted flex items-start gap-1 text-xs">
              <Icon name="warning" className="mt-0.5 size-3.5 shrink-0" />
              <span>{t("filters.newDomains.warning")}</span>
            </p>
          ) : null}
        </Popover.Dialog>
      </Popover.Content>
    </Popover>
  );
}

export function FilterTile({card, name, readOnly, onToggle, onMode, onInfo}: FilterTileProps) {
  const t = useTranslations("profiles");
  const note = card.deprecated ? t("filters.deprecatedNote") : card.unavailable ? t("filters.unavailableNote") : null;
  return (
    <ItemTile
      state={readOnly ? "disabled" : card.enabled ? "on" : "off"}
      icon={hasSubIcon("filters", card.id) ? <SubIcon group="filters" name={card.id as never} className="size-6" /> : <Icon name="filters" className="size-6" />}
      toggle={
        <Switch
          isSelected={card.enabled}
          isDisabled={readOnly || !card.canToggle}
          onChange={onToggle}
          aria-label={t("card.toggle", {name})}
          data-filter={card.id}
        >
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      }
      title={name}
      status={card.status === "blocked" ? t("card.status.blocked") : t("card.status.allowed")}
      footer={
        <>
          <Button isIconOnly size="sm" variant="ghost" aria-label={t("card.info", {name})} onPress={onInfo}>
            <Icon name="info" className="size-4" />
          </Button>
          {card.deprecated || card.unavailable ? (
            <Chip size="sm" variant="soft">
              <Chip.Label>{card.deprecated ? t("filters.deprecated") : t("filters.unavailable")}</Chip.Label>
            </Chip>
          ) : null}
        </>
      }
    >
      {card.enabled && card.modes.length > 0 ? <ModeMenu card={card} name={name} readOnly={readOnly} onMode={onMode} /> : null}
      {note ? (
        <p className="text-muted flex items-start gap-1 text-xs">
          <Icon name="info" className="mt-0.5 size-3.5 shrink-0" />
          <span>{note}</span>
        </p>
      ) : null}
    </ItemTile>
  );
}

/** Native and 3rd Party: two pages, so two links (WF: the switch at the end of the top row). The current one says so with `aria-current`, by weight and by variant. */
export function FilterKindNav({current, nativeHref, thirdPartyHref}: {current: "native" | "third-party"; nativeHref: string; thirdPartyHref: string}) {
  const t = useTranslations("profiles");
  const items = [
    {id: "native", href: nativeHref, label: t("filters.tabNative")},
    {id: "third-party", href: thirdPartyHref, label: t("filters.tabThirdParty")},
  ] as const;
  return (
    <nav aria-label={t("filters.navLabel")}>
      <ul className="flex items-center gap-1">
        {items.map((item) => (
          <li key={item.id}>
            <Link
              href={item.href}
              aria-current={item.id === current ? "page" : undefined}
              className={buttonVariants({variant: item.id === current ? "secondary" : "ghost", size: "sm"})}
            >
              {item.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
