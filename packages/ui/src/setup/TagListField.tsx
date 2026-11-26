"use client";

import {Button, Description, FieldError, Input, Label, Tag, TagGroup, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {Tech} from "../data/Tech.tsx";
import type {EntryProblem} from "./appleModel.ts";

// A list the person builds one entry at a time (the Wi-Fi networks and the domains of the Apple builder): a field with an Add button
// (Enter adds too), and the entries as removable tags under it. `check` says whether a typed value may be added (and what it becomes),
// so the rules live in appleModel.ts and this stays a control.

export function TagListField({
  label,
  description,
  items,
  onChange,
  check,
  max,
  tech = false,
}: {
  label: string;
  description?: string;
  items: string[];
  onChange: (items: string[]) => void;
  /** The value as it would be kept, and what is wrong with it. */
  check: (typed: string, list: readonly string[]) => {value: string; problem: EntryProblem | null};
  max: number;
  /** Entries are technical text (domains): drawn left to right. */
  tech?: boolean;
}) {
  const t = useTranslations("setup");
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState<EntryProblem | null>(null);

  function add() {
    const result = check(typed, items);
    if (result.problem) {
      setProblem(result.problem);
      return;
    }
    setProblem(null);
    setTyped("");
    onChange([...items, result.value]);
  }

  return (
    <div className="flex flex-col gap-2">
      <TextField
        value={typed}
        onChange={(value) => {
          setTyped(value);
          if (problem) setProblem(null);
        }}
        isInvalid={problem !== null}
        fullWidth
        variant="secondary"
      >
        <Label>{label}</Label>
        <div className="flex items-start gap-2">
          <Input
            className="min-w-0 flex-1"
            dir={tech ? "ltr" : undefined}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                add();
              }
            }}
          />
          <Button variant="secondary" onPress={add} isDisabled={items.length >= max} aria-label={t("apple.addTo", {name: label})}>
            {t("apple.add")}
          </Button>
        </div>
        {description ? <Description>{description}</Description> : null}
        <FieldError>{problem ? t(`apple.problems.${problem}`, {max}) : null}</FieldError>
      </TextField>
      <p className="text-muted text-xs" role="status">
        {t("apple.counter", {count: items.length, max})}
      </p>
      {items.length > 0 ? (
        <TagGroup aria-label={t("apple.added", {name: label})} onRemove={(keys) => onChange(items.filter((item) => !keys.has(item)))}>
          <TagGroup.List>
            {items.map((item) => (
              <Tag key={item} id={item} textValue={item}>
                {tech ? <Tech>{item}</Tech> : item}
              </Tag>
            ))}
          </TagGroup.List>
        </TagGroup>
      ) : null}
    </div>
  );
}
