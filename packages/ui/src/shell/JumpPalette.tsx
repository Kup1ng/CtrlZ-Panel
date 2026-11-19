"use client";

import {Command} from "@heroui-pro/react";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {flattenLinks, type NavItem} from "./nav.ts";

// Spec 8.13, the thin version: the nav routes, opened with mod+k. No Plan row
// asks for it and it is the first thing to drop. The header's search button does
// not depend on it. P2 adds profiles.

const fold = (s: string) => normalizeFaSearch(s).toLocaleLowerCase();
const faAwareFilter = (text: string, input: string) => fold(text).includes(fold(input));

export function JumpPalette({nav, isOpen, onOpenChange}: {nav: NavItem[]; isOpen: boolean; onOpenChange: (open: boolean) => void}) {
  const t = useTranslations("shell");
  const c = useTranslations("common");
  const router = useRouter();
  const links = flattenLinks(nav);

  return (
    <Command>
      <Command.Backdrop isOpen={isOpen} onOpenChange={onOpenChange}>
        <Command.Container size="md">
          <Command.Dialog aria-label={t("palette.label")} filter={faAwareFilter}>
            <Command.InputGroup>
              <Command.InputGroup.Prefix>
                <Icon name="search" className="size-4" />
              </Command.InputGroup.Prefix>
              <Command.InputGroup.Input placeholder={t("palette.placeholder")} />
              <Command.InputGroup.ClearButton />
            </Command.InputGroup>
            <Command.List renderEmptyState={() => <p className="text-muted p-4 text-center text-sm">{c("noResults")}</p>}>
              <Command.Group heading={t("palette.pages")}>
                {links.map((l) => (
                  <Command.Item
                    key={l.id}
                    id={l.id}
                    textValue={l.label}
                    onAction={() => {
                      onOpenChange(false);
                      router.push(l.href);
                    }}
                  >
                    <Icon name={l.icon} className="size-4" />
                    <span>{l.label}</span>
                  </Command.Item>
                ))}
              </Command.Group>
            </Command.List>
          </Command.Dialog>
        </Command.Container>
      </Command.Backdrop>
    </Command>
  );
}
