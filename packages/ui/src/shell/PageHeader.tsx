"use client";

import {Button, Dropdown, Label, SearchField, Tooltip} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState, type ReactNode} from "react";

import {useHaptics} from "../hooks/useHaptics.ts";
import type {HelpKey} from "./SectionHelp.tsx";
import {useShellDialog} from "./useShellDialog.ts";

// T-116, spec 8.4. One row: icon, title, a one-line subtitle, the help button;
// then, at the end, search, the three-dot menu and "+". A button renders only
// when it has something to do, so there is never a dead button or an empty menu.

export type HeaderAction = {
  id: string;
  label: string;
  icon?: GeneralIconName;
  variant?: "default" | "danger";
  onAction: () => void;
};

export type PageHeaderProps = {
  icon: GeneralIconName;
  title: string;
  subtitle?: string;
  helpKey?: HelpKey;
  /** Renders the three-dot menu, when not empty. */
  actions?: HeaderAction[];
  /** Renders the search button, and on small screens an always-visible field (T-115). */
  onSearch?: (query: string) => void;
  /** Renders "+". */
  onCreate?: () => void;
  /** Names the "+" button for screen readers, for example "Create user". */
  createLabel?: string;
  /** Profile pages put the ProfileSwitcher here (T-123). */
  leading?: ReactNode;
};

function HeaderSearch({onSearch, className, focusOnMount}: {onSearch: (q: string) => void; className?: string; focusOnMount?: boolean}) {
  const t = useTranslations("shell");
  const input = useRef<HTMLInputElement>(null);
  // The field opens from a button press, so focus follows the user's own action.
  useEffect(() => {
    if (focusOnMount) input.current?.focus();
  }, [focusOnMount]);
  return (
    <SearchField aria-label={t("header.search")} className={className} onChange={onSearch}>
      <SearchField.Group>
        <SearchField.SearchIcon>
          <Icon name="search" className="size-4" />
        </SearchField.SearchIcon>
        <SearchField.Input ref={input} placeholder={t("header.searchPlaceholder")} />
        <SearchField.ClearButton />
      </SearchField.Group>
    </SearchField>
  );
}

function IconTip({label, children}: {label: string; children: ReactNode}) {
  return (
    <Tooltip delay={400}>
      {children}
      <Tooltip.Content>{label}</Tooltip.Content>
    </Tooltip>
  );
}

export function PageHeader({icon, title, subtitle, helpKey, actions, onSearch, onCreate, createLabel, leading}: PageHeaderProps) {
  const t = useTranslations("shell");
  const help = useShellDialog("helpPane");
  const {buzz} = useHaptics();
  const [searchOpen, setSearchOpen] = useState(false);
  const hasActions = !!actions && actions.length > 0;

  return (
    <header className="page-header">
      <div className="page-header__row">
        {leading}
        <span className="page-header__icon" aria-hidden="true">
          <Icon name={icon} className="size-5" />
        </span>
        <div className="page-header__text">
          <h1 className="page-header__title">{title}</h1>
          {subtitle ? <p className="page-header__subtitle">{subtitle}</p> : null}
        </div>
        {helpKey ? (
          <IconTip label={t("header.help")}>
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("header.help")} onPress={() => help.open(helpKey)}>
              <Icon name="help" className="size-5" />
            </Button>
          </IconTip>
        ) : null}

        <div className="page-header__tools">
          {onSearch && searchOpen ? <HeaderSearch focusOnMount className="page-header__search-inline" onSearch={onSearch} /> : null}
          {onSearch ? (
            <span className="page-header__search-button">
              <IconTip label={t("header.search")}>
                <Button
                  isIconOnly
                  variant="outline"
                  aria-label={t("header.search")}
                  aria-expanded={searchOpen}
                  onPress={() => setSearchOpen((open) => !open)}
                >
                  <Icon name="search" className="size-5" />
                </Button>
              </IconTip>
            </span>
          ) : null}
          {hasActions ? (
            <Dropdown>
              <IconTip label={t("header.more")}>
                <Button isIconOnly variant="outline" aria-label={t("header.more")}>
                  <Icon name="more" className="size-5" />
                </Button>
              </IconTip>
              <Dropdown.Popover placement="bottom end">
                <Dropdown.Menu
                  aria-label={t("header.more")}
                  onAction={(key) => actions.find((a) => a.id === String(key))?.onAction()}
                >
                  {actions.map((a) => (
                    <Dropdown.Item key={a.id} id={a.id} textValue={a.label} variant={a.variant}>
                      {a.icon ? <Icon name={a.icon} className="size-4 shrink-0" /> : null}
                      <Label>{a.label}</Label>
                    </Dropdown.Item>
                  ))}
                </Dropdown.Menu>
              </Dropdown.Popover>
            </Dropdown>
          ) : null}
          {onCreate ? (
            <IconTip label={createLabel ?? t("header.create")}>
              <Button
                isIconOnly
                variant="primary"
                aria-label={createLabel ?? t("header.create")}
                onPress={() => {
                  buzz();
                  onCreate();
                }}
              >
                <Icon name="plus" className="size-5" />
              </Button>
            </IconTip>
          ) : null}
        </div>
      </div>

      {/* Below md the field is always there, and the button above is hidden (T-115). */}
      {onSearch ? <HeaderSearch className="page-header__search-mobile" onSearch={onSearch} /> : null}
    </header>
  );
}
