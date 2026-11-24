"use client";

import {localeAutonym, locales, type Locale} from "@ctrlz/i18n/locale.ts";
import {Segment} from "@heroui-pro/react";
import {useId} from "react";

// The language of a message the admin has someone else receive (a new user's language, an invite's SMS). The labels are
// the languages' own names, as in the language switch, so they do not change with the page language. The control has a
// visible label and is named by it.

export function LocaleSegment({label, value, onChange, isDisabled}: {label: string; value: Locale; onChange: (value: Locale) => void; isDisabled?: boolean}) {
  const labelId = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <span id={labelId} className="text-sm font-medium">
        {label}
      </span>
      <Segment aria-labelledby={labelId} selectedKey={value} isDisabled={isDisabled} onSelectionChange={(key) => onChange(key as Locale)}>
        {locales.map((l) => (
          <Segment.Item key={l} id={l}>
            <bdi>{localeAutonym[l]}</bdi>
          </Segment.Item>
        ))}
      </Segment>
    </div>
  );
}
