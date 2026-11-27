"use client";

import {Button, ComboBox, Input, ListBox} from "@heroui/react";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Flag, loadFlags} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useMemo, useState} from "react";

import {MiniSelect} from "./MiniSelect.tsx";
import type {Geo} from "./rulesModel.ts";

// The Geo Rule rows of the rule dialog (spec p2 9.6, WF "Rules", T-181): each row is one rule, "the destination (or the source) is (not) this
// country". The four forms are one choice, the country a search box with its flag; the country names come from the language's own region names,
// and the codes from the flag set (every country has a flag, so the two lists are the same list).

export type GeoRow = Geo & {id: number};

const fold = (text: string) => normalizeFaSearch(text).toLocaleLowerCase();
const FORMS = ["dest", "destNot", "src", "srcNot"] as const;
type Form = (typeof FORMS)[number];
const formOf = (g: Geo): Form => `${g.side}${g.negated ? "Not" : ""}` as Form;
const geoOf = (form: Form): Pick<Geo, "side" | "negated"> => ({side: form.startsWith("dest") ? "dest" : "src", negated: form.endsWith("Not")});

/** The ISO codes that have a flag, once the flag set is loaded. */
function useCountryCodes(): string[] {
  const [codes, setCodes] = useState<string[]>([]);
  useEffect(() => {
    let live = true;
    void loadFlags().then((table) => live && setCodes(Object.keys(table).filter((code) => /^[A-Z]{2}$/.test(code))));
    return () => {
      live = false;
    };
  }, []);
  return codes;
}

function CountryBox({value, onChange, label, isDisabled}: {value: string; onChange: (code: string) => void; label: string; isDisabled?: boolean}) {
  const t = useTranslations("rules");
  const format = useAppFormat();
  const codes = useCountryCodes();
  const items = useMemo(() => codes.map((code) => ({code, name: format.regionName(code)})).sort((a, b) => format.compare(a.name, b.name)), [codes, format]);
  return (
    <ComboBox
      aria-label={label}
      variant="secondary"
      className="min-w-40 flex-1"
      isDisabled={isDisabled}
      selectedKey={value === "" ? null : value}
      onSelectionChange={(key) => typeof key === "string" && onChange(key)}
      defaultFilter={(text, input) => input === "" || fold(text).includes(fold(input)) || fold(text).startsWith(fold(input))}
    >
      <ComboBox.InputGroup>
        <Input placeholder={t("geo.countryPlaceholder")} autoComplete="off" />
        <ComboBox.Trigger />
      </ComboBox.InputGroup>
      <ComboBox.Popover>
        <ListBox>
          {items.map((item) => (
            <ListBox.Item key={item.code} id={item.code} textValue={item.name}>
              <Flag code={item.code} />
              {item.name}
              <ListBox.ItemIndicator />
            </ListBox.Item>
          ))}
        </ListBox>
      </ComboBox.Popover>
    </ComboBox>
  );
}

export type GeoRowsProps = {
  rows: readonly GeoRow[];
  onChange: (rows: GeoRow[]) => void;
  isDisabled?: boolean;
  /** An edit has the one rule's row and no `+ Geo Rule` or remove. */
  single?: boolean;
  /** The server's word for a row, by its index. */
  errors?: ReadonlyMap<number, string>;
};

export function GeoRows({rows, onChange, isDisabled = false, single = false, errors}: GeoRowsProps) {
  const t = useTranslations("rules");
  const next = rows.reduce((max, r) => Math.max(max, r.id), 0) + 1;
  const patch = (id: number, change: Partial<Geo>) => onChange(rows.map((r) => (r.id === id ? {...r, ...change} : r)));
  return (
    <div className="flex flex-col gap-2">
      {rows.length > 0 ? (
        <ul aria-label={t("geo.rowsLabel")} className="flex flex-col gap-2">
          {rows.map((row, index) => {
            const number = index + 1;
            return (
              <li key={row.id} className="bg-default/40 flex flex-col gap-1 p-2" data-geo-row={row.id}>
                <div className="flex flex-wrap items-center gap-2">
                  <SubIcon group="rules" name={row.side === "dest" ? "geo-destination" : "geo-source"} className="size-5 shrink-0" />
                  <MiniSelect
                    label={t("geo.formLabel", {number})}
                    className="w-44 shrink-0"
                    value={formOf(row)}
                    isDisabled={isDisabled}
                    onChange={(form) => patch(row.id, geoOf(form as Form))}
                    options={FORMS.map((form) => ({id: form, label: t(`geo.form.${form}`), textValue: t(`geo.form.${form}`)}))}
                  />
                  <CountryBox label={t("geo.countryLabel", {number})} value={row.country} isDisabled={isDisabled} onChange={(country) => patch(row.id, {country})} />
                  {single ? null : (
                    <Button isIconOnly size="sm" variant="ghost" isDisabled={isDisabled} aria-label={t("geo.remove", {number})} onPress={() => onChange(rows.filter((r) => r.id !== row.id))}>
                      <Icon name="trash" className="size-4" />
                    </Button>
                  )}
                </div>
                {errors?.has(index) ? <p className="text-xs text-(--danger-text)">{errors.get(index)}</p> : null}
              </li>
            );
          })}
        </ul>
      ) : null}
      {single ? null : (
        <Button size="sm" variant="secondary" className="self-start" isDisabled={isDisabled} onPress={() => onChange([...rows, {id: next, side: "dest", negated: false, country: ""}])}>
          <Icon name="plus" className="size-4" />
          {t("geo.add")}
        </Button>
      )}
    </div>
  );
}
