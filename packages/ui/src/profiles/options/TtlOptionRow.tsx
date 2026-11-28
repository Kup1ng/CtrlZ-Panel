"use client";

import type {Options, OptionsPatch} from "@ctrlz/api-client/hooks/options.ts";
import {Button, FieldError, Input, Label, TextField} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {stripInvisible} from "../../forms/invisible.ts";
import {useApiForm} from "../../forms/useApiForm.ts";
import {InPlaceActions} from "./InPlaceActions.tsx";
import {OptionRow} from "./OptionRow.tsx";
import {parseTtl, TTL_DEFAULT, TTL_MAX, TTL_MIN, ttlProblem, type OptionRow as RowName, type TtlOption} from "./optionModel.ts";
import {useFocusBack} from "./useFocusBack.ts";
import {useOptionWriter} from "./useOptionWriter.ts";

// Block TTL, Redirect TTL and Bypass TTL (T-204): a number of seconds from 1 to 86,400. The row shows the value and an Edit button;
// the field opens in place with Save (T-215). It is a text field read by `parseTtl`, and the page checks the bounds on Save and says what is wrong. A value that is not set shows the default of SC 6 (Block and Redirect 60 s, Bypass keeps
// each answer's own TTL), and "Use the default" clears it.

export function TtlOptionRow({
  profileId,
  options,
  name,
  readOnly,
  onLearnMore,
}: {
  profileId: string;
  options: Options;
  name: TtlOption;
  readOnly: boolean;
  onLearnMore: (name: RowName) => void;
}) {
  const t = useTranslations("rules");
  const title = t(`options.rows.${name}.name`);
  const stored = options[name];
  const [editing, setEditing] = useState(false);
  // Save and Cancel are gone when the field closes; the focus goes back to Edit (S2-r1-3).
  const editRef = useFocusBack<HTMLButtonElement>(editing);
  // A form that was open when the profile got locked closes: its Save would only be refused with 423 (S2-r2-6, T-140).
  if (readOnly && editing) setEditing(false);
  const seconds = (count: number) => t("options.ttl.seconds", {count});
  const fallback = TTL_DEFAULT[name];
  const shown = stored !== undefined ? seconds(stored) : fallback === null ? t("options.ttl.keeps") : t("options.ttl.defaultIs", {value: seconds(fallback)});
  return (
    <OptionRow
      name={name}
      title={title}
      description={t(`options.rows.${name}.description`)}
      onLearnMore={onLearnMore}
      control={
        editing ? null : (
          <>
            <span data-testid={`${name}-value`} className="text-sm">
              {shown}
            </span>
            <Button ref={editRef} size="sm" variant="outline" isDisabled={readOnly} aria-label={t("options.editAria", {name: title})} onPress={() => setEditing(true)}>
              {t("options.ttl.edit")}
            </Button>
          </>
        )
      }
    >
      {editing ? <TtlForm profileId={profileId} name={name} title={title} stored={stored} onDone={() => setEditing(false)} /> : null}
    </OptionRow>
  );
}

function TtlForm({profileId, name, title, stored, onDone}: {profileId: string; name: TtlOption; title: string; stored: number | undefined; onDone: () => void}) {
  const t = useTranslations("rules");
  const writer = useOptionWriter(profileId);
  const form = useApiForm({focus: name});
  const format = useAppFormat();
  // Typed as text, in the digits the language writes, and read by `parseTtl`: a number field would clamp a value on blur and save it
  // without the reader seeing that it changed, and in `fa` it would not take the Latin digits of an English keyboard.
  const initial = stored ?? TTL_DEFAULT[name];
  const [text, setText] = useState(initial === null ? "" : format.number(initial, {useGrouping: false}));
  const [pending, setPending] = useState(false);

  async function write(body: OptionsPatch) {
    setPending(true);
    form.clear();
    const error = await writer.send(body);
    setPending(false);
    if (error === null) return onDone();
    form.fail(error, {rename: {[`/${name}`]: name}});
  }

  function submit() {
    if (pending || form.blocked) return;
    const value = parseTtl(text);
    const problem = ttlProblem(value);
    if (problem) return form.setFieldError(name, t(`options.ttl.${problem}`, {min: TTL_MIN, max: TTL_MAX}));
    void write({[name]: value});
  }

  const message = form.fieldMessage(name);
  return (
    <AuthForm form={form} onSubmit={submit}>
      <TextField
        name={name}
        variant="secondary"
        value={text}
        isDisabled={pending}
        isInvalid={message !== undefined}
        fullWidth
        className="max-w-xs"
        onChange={(next) => form.bind(name, setText).onChange(stripInvisible(next))}
      >
        <Label>{t("options.ttl.field", {name: title})}</Label>
        <Input dir="ltr" inputMode="numeric" autoComplete="off" spellCheck={false} />
        <p className="text-muted text-xs">{t("options.ttl.hint", {min: TTL_MIN, max: TTL_MAX})}</p>
        <FieldError>{message}</FieldError>
      </TextField>
      <FormError error={form.formError} form={form} onRetry={submit} />
      <InPlaceActions
        subject={title}
        isPending={pending}
        retryIn={form.retryIn}
        onCancel={onDone}
        extra={
          stored !== undefined ? (
            <Button variant="ghost" isDisabled={pending} aria-label={t("options.ttl.useDefaultAria", {name: title})} onPress={() => void write({clear: [name]})}>
              {t("options.ttl.useDefault")}
            </Button>
          ) : null
        }
      />
    </AuthForm>
  );
}
