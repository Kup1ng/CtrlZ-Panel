"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {COUNTRY_CODES} from "@ctrlz/i18n/countries.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {ComboBox, Input, ListBox, Tag, TagGroup, toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useMemo, useRef, useState} from "react";

import {useErrorText} from "../feedback/errorText.ts";
import {SettingRow} from "./AccountSection.tsx";
import {accountApi, putHomeCountries} from "./accountApi.ts";

// Spec 12.6 (T-311): the countries the account treats as home, at most three. The list is the ISO 3166
// alpha-2 codes of `packages/i18n`, and the names come from the language in use, so a search by name
// works in Persian (typed on either keyboard) and in English. Flags are not shown in P1: no licensed flag
// set is in the repository yet. Each change is saved at once, and a fourth choice is not offered: the
// combo box is off, with the line that says why. The server enforces the limit too (422).

export const HOME_LIMIT = 3;

type Item = {id: string; name: string};

/** Fold what is typed and what is searched the same way, so a Persian search typed on an Arabic keyboard still finds it. */
export function matchesCountry(name: string, query: string): boolean {
  const fold = (text: string) => normalizeFaSearch(text).toLowerCase();
  return fold(name).includes(fold(query.trim()));
}

export function HomeCountries({countries}: {countries: string[]}) {
  const t = useTranslations("account");
  const f = useAppFormat();
  const locale = useLocale();
  const queryClient = useQueryClient();
  const errorText = useErrorText();
  const [pending, setPending] = useState(false);
  // The same fact as `pending`, readable at once: the PUT replaces the whole list, so a second change built from the
  // list on screen before the first answer would put the first one back (wp9-r1-4). One write at a time, for add and remove.
  const writing = useRef(false);
  // The combo box is made again after each choice. It stayed open after a pick (the chosen country leaves its list,
  // and the list does not close when its collection changes), and an open list hides the rest of the page from a
  // screen reader. A new one is closed and empty, and the focus is put back in it (the person just acted there).
  const [round, setRound] = useState(0);
  // A pick wants the focus back once the field can take it: it is off while the PUT runs, and a disabled input
  // ignores focus() (wp9-r2-1). Removing a tag does not set this, so it never takes the focus from the tags.
  const refocus = useRef(false);
  // What is typed, only to say that nothing matches: the combo box owns the field, and it shows no list at all for an empty result.
  const [query, setQuery] = useState("");
  const field = useRef<HTMLDivElement>(null);
  const full = countries.length >= HOME_LIMIT;
  useEffect(() => {
    if (!refocus.current || pending) return;
    refocus.current = false;
    // With the third country chosen the field stays off, and there is nothing in it to focus.
    if (!full) field.current?.querySelector("input")?.focus();
  }, [round, pending, full]);

  const all = useMemo<Item[]>(
    () => COUNTRY_CODES.map((id) => ({id, name: f.regionName(id)})).sort((a, b) => a.name.localeCompare(b.name, locale)),
    [f, locale],
  );
  const chosen = useMemo(() => countries.map((id) => ({id, name: f.regionName(id)})), [countries, f]);
  const available = useMemo(() => all.filter((item) => !countries.includes(item.id)), [all, countries]);

  async function write(next: string[]) {
    if (writing.current) return;
    writing.current = true;
    setPending(true);
    try {
      const saved = await accountApi.setHomeCountries(next);
      putHomeCountries(queryClient, saved.countries);
    } catch (error) {
      toast.danger(errorText(error));
    } finally {
      writing.current = false;
      setPending(false);
    }
  }

  return (
    <SettingRow id="home-countries" label={t("home.label")} description={t("home.description")}>
      <div ref={field}>
      <ComboBox
        key={round}
        aria-label={t("home.search")}
        variant="secondary"
        fullWidth
        // defaultItems, not items: the list is filtered by `defaultFilter` only when the combo box owns the collection.
        defaultItems={available}
        selectedKey={null}
        onSelectionChange={(key) => {
          if (key === null || full || writing.current) return;
          setQuery("");
          refocus.current = true;
          setRound((n) => n + 1);
          void write([...countries, String(key)]);
        }}
        defaultFilter={matchesCountry}
        isDisabled={full || pending}
        menuTrigger="input"
        onInputChange={setQuery}
      >
        <ComboBox.InputGroup>
          <Input placeholder={t("home.placeholder")} />
          <ComboBox.Trigger />
        </ComboBox.InputGroup>
        <ComboBox.Popover>
          <ListBox>
            {(item: Item) => (
              <ListBox.Item id={item.id} textValue={item.name}>
                {item.name}
                <ListBox.ItemIndicator />
              </ListBox.Item>
            )}
          </ListBox>
        </ComboBox.Popover>
      </ComboBox>
      </div>
      {query.trim() !== "" && !available.some((item) => matchesCountry(item.name, query)) ? (
        <p role="status" className="text-muted text-sm">
          {t("home.noMatch")}
        </p>
      ) : null}
      <p className={full ? "text-sm text-(--warning-text)" : "text-muted text-xs"} role={full ? "status" : undefined}>
        {full ? t("home.full", {max: HOME_LIMIT}) : t("home.count", {count: countries.length, max: HOME_LIMIT})}
      </p>
      <TagGroup
        aria-label={t("home.chosen")}
        // Each tag's remove button is off while a write runs (it is back when the answer is in).
        disabledKeys={pending ? countries : undefined}
        onRemove={(keys) => void write(countries.filter((code) => !keys.has(code)))}
      >
        <TagGroup.List items={chosen} renderEmptyState={() => <span className="text-muted text-sm">{t("home.empty")}</span>}>
          {(item: Item) => (
            <Tag id={item.id} textValue={item.name}>
              {item.name}
            </Tag>
          )}
        </TagGroup.List>
      </TagGroup>
    </SettingRow>
  );
}
