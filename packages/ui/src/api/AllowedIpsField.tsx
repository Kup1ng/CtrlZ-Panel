"use client";

import {Button, Description, FieldError, Input, Label, Tag, TagGroup, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useImperativeHandle, useState, type Ref} from "react";

import {Tech} from "../data/Tech.tsx";
import {MAX_ALLOWED, checkAllowed, type AllowedProblem} from "./tokenModel.ts";

// The Allowed IPs of a token (spec p3 6.1, 6.3): addresses and subnets the token may be used from, one at a time with an Add button (Enter adds
// too), as tags under the field. An empty list means any address, and the field says so. A server refusal of one entry (`/allowed_ips/<i>`)
// arrives as `serverProblem` with the entry's text, since the server names a place and the person knows the value.
//
// What is typed and not yet added is not part of the list, and a dialog that sent `items` alone would drop it and make an unrestricted token the
// person believes is locked to their network (S8-r1-2). So the dialog asks the field to `flush` on submit: the pending text is added if it is an
// address, and shown as a problem (and the submit stopped) if it is not.

/** What a dialog may ask of the field. */
export type AllowedIpsHandle = {
  /** The list with the pending text added, or `null` when that text cannot be added (the field shows why). With nothing typed it is `items`. */
  flush: () => string[] | null;
};

export function AllowedIpsField({
  items,
  onChange,
  isDisabled = false,
  serverProblem,
  ref,
}: {
  items: string[];
  onChange: (items: string[]) => void;
  isDisabled?: boolean;
  /** What the server said about the list (text, already in words). Shown until the list changes. */
  serverProblem?: string;
  ref?: Ref<AllowedIpsHandle>;
}) {
  const t = useTranslations("api");
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState<AllowedProblem | null>(null);

  /** Adds what is typed. Returns the new list, `null` when the text is refused, and `items` when nothing was typed. */
  function add(): string[] | null {
    if (typed.trim() === "") return items;
    const result = checkAllowed(typed, items);
    if (result.problem) {
      setProblem(result.problem);
      return null;
    }
    const next = [...items, result.value];
    setProblem(null);
    setTyped("");
    onChange(next);
    return next;
  }

  useImperativeHandle(ref, () => ({flush: add}));

  const message = problem ? t(`allowed.problems.${problem}`, {max: MAX_ALLOWED}) : serverProblem;

  return (
    <div className="flex flex-col gap-2" data-testid="allowed-ips-field">
      <TextField
        value={typed}
        onChange={(value) => {
          setTyped(value);
          if (problem) setProblem(null);
        }}
        isInvalid={message !== undefined}
        isDisabled={isDisabled}
        fullWidth
        variant="secondary"
      >
        <Label>{t("allowed.label")}</Label>
        <div className="flex items-start gap-2">
          <Input
            className="min-w-0 flex-1"
            dir="ltr"
            placeholder="203.0.113.0/24"
            autoComplete="off"
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                add();
              }
            }}
          />
          <Button variant="secondary" onPress={add} isDisabled={isDisabled || items.length >= MAX_ALLOWED} aria-label={t("allowed.addAria")}>
            {t("allowed.add")}
          </Button>
        </div>
        <Description>{items.length === 0 ? t("allowed.anyAddress") : t("allowed.count", {count: items.length, max: MAX_ALLOWED})}</Description>
        <FieldError>{message}</FieldError>
      </TextField>
      {items.length > 0 ? (
        <TagGroup aria-label={t("allowed.listLabel")} onRemove={isDisabled ? undefined : (keys) => onChange(items.filter((item) => !keys.has(item)))}>
          <TagGroup.List>
            {items.map((item) => (
              <Tag key={item} id={item} textValue={item}>
                <Tech>{item}</Tech>
              </Tag>
            ))}
          </TagGroup.List>
        </TagGroup>
      ) : null}
    </div>
  );
}
