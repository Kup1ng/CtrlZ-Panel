"use client";

import {Button, Description, Input, Label, TextField} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {stripInvisible} from "../../forms/invisible.ts";
import {addTags, MAX_PATTERNS, splitTokens} from "./rulesModel.ts";

// The domain tags of the rule dialog (spec p2 9.6, WF "Rules", T-180): one rule is made for each tag. A name is typed and ended with Enter, a
// space or a comma, or pasted as a list (any of them splits it). A tag is the text the person wrote, checked by the server when the form is
// sent: the API's word for each refused tag (`errors[index]`) is shown under the tags, with the tag's name in it, since a field error that
// named only a position would send the person counting.

// The hint in the empty box. A reserved example name, the same in both languages, so it is a value and not a message.
const EXAMPLE_DOMAIN = "example.com";

export type DomainTagsProps = {
  tags: readonly string[];
  onChange: (tags: string[]) => void;
  /** The server's word for a tag, by its index in `tags`. */
  errors?: ReadonlyMap<number, string>;
  isDisabled?: boolean;
  /** `1` for an edit: the one rule has one name. */
  max?: number;
  /** The text typed and not yet made a tag. The dialog keeps it, so Add sends it too. */
  pending: string;
  onPending: (text: string) => void;
};

export function DomainTags({tags, onChange, errors, isDisabled = false, max = MAX_PATTERNS, pending: text, onPending: setText}: DomainTagsProps) {
  const t = useTranslations("rules");
  const format = useAppFormat();
  const [note, setNote] = useState<string | null>(null);

  const commit = (typed: string) => {
    // A name has no invisible character; one that came with a paste is dropped before the name is made.
    const value = stripInvisible(typed);
    if (value.trim() === "") {
      setText("");
      return;
    }
    // One name (an edit) is replaced by the new one; several are added.
    const result = max === 1 ? {tags: [splitTokens(value)[0] ?? ""].filter(Boolean), added: 1, duplicates: 0, over: Math.max(0, splitTokens(value).length - 1)} : addTags(tags, value, max);
    onChange(result.tags);
    setText("");
    setNote(result.over > 0 ? t("dialog.tagsOver", {count: result.over, max: format.number(max)}) : result.duplicates > 0 ? t("dialog.tagsDuplicate", {count: result.duplicates}) : null);
  };

  const failed = [...(errors?.entries() ?? [])].filter(([index]) => tags[index] !== undefined);

  return (
    <div className="flex flex-col gap-2">
      <TextField
        value={text}
        onChange={(value) => {
          // A space, a comma or a line break ends a tag, so a pasted list becomes tags at once.
          if (/[\s,;،؛]$/u.test(value) || /[\s]/u.test(value.trim())) commit(value);
          else setText(value);
        }}
        isDisabled={isDisabled}
        aria-label={t("dialog.domains")}
      >
        <Label>{t("dialog.domains")}</Label>
        <div className="flex items-center gap-2">
          <Input
            dir="ltr"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            className="min-w-0 flex-1"
            placeholder={EXAMPLE_DOMAIN}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                // Enter adds the tag; the form is sent by its own button.
                event.preventDefault();
                commit(text);
              }
            }}
            onBlur={() => commit(text)}
          />
          <Button variant="secondary" isDisabled={isDisabled || text.trim() === ""} onPress={() => commit(text)}>
            {t("dialog.addTag")}
          </Button>
        </div>
        <Description>{max === 1 ? t("dialog.domainHelpOne") : t("dialog.domainHelp")}</Description>
      </TextField>
      {tags.length > 0 ? (
        <ul aria-label={t("dialog.tagsLabel")} className="flex max-h-40 flex-wrap gap-1.5 overflow-auto">
          {tags.map((tag, index) => {
            const bad = errors?.has(index) ?? false;
            return (
              <li
                key={tag}
                data-invalid={bad || undefined}
                className="bg-default data-[invalid]:border-danger flex min-w-0 max-w-full items-center gap-1 rounded-full border border-transparent ps-3 pe-1 text-sm"
              >
                {bad ? <Icon name="warning" className="size-3.5 shrink-0 text-(--danger-text)" /> : null}
                <span className="truncate">
                  <Tech>{tag}</Tech>
                </span>
                <Button isIconOnly size="sm" variant="ghost" isDisabled={isDisabled} aria-label={t("dialog.removeTag", {pattern: tag})} onPress={() => onChange(tags.filter((_, i) => i !== index))}>
                  <Icon name="close" className="size-3.5" />
                </Button>
              </li>
            );
          })}
        </ul>
      ) : null}
      <p className="text-muted text-xs" aria-live="polite">
        {t("dialog.tagCount", {count: format.number(tags.length), max: format.number(max)})}
        {note ? ` ${note}` : ""}
      </p>
      {failed.length > 0 ? (
        <ul className="flex flex-col gap-0.5 text-xs text-(--danger-text)" role="alert">
          {failed.map(([index, message]) => (
            <li key={index}>
              <Tech>{tags[index]}</Tech>: {message}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
