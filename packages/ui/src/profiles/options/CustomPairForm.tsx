"use client";

import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {FieldError, Input, Label, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {stripInvisible} from "../../forms/invisible.ts";
import {useApiForm} from "../../forms/useApiForm.ts";
import {InPlaceActions} from "./InPlaceActions.tsx";
import type {CustomDraft} from "./optionModel.ts";

// The two fields that Custom opens in place, an IPv4 value and an IPv6 value, with Save: the addresses of a Custom Block Response and the
// subnets of a Custom ECS (T-205, T-210). Either may be empty, not both. The page checks what it can (the family, the prefix, host bits)
// and words the problem under the field; the API decides last, and its field codes (`/ecs/v4`) are worded under the same fields.
// The form stays open after a save (a stored Custom is this form), so a saved draft is said in a polite status beside the buttons, and the
// fields show the value that was sent, in Latin digits, until the next edit (S2-r3-1).

export type PairProblems = {v4?: string; v6?: string; form?: string};

export function CustomPairForm({
  subject,
  initial,
  labels,
  placeholder,
  validate,
  rename,
  v4InputMode = "decimal",
  readOnly = false,
  focusFirst = true,
  onSave,
  onCancel,
}: {
  /** The option's name, in the names of the buttons. */
  subject: string;
  initial: CustomDraft;
  labels: {v4: string; v6: string};
  placeholder: {v4: string; v6?: string};
  /** The page's own checks, as the text to show per field, or `null` when the draft may be sent. A `form` text goes under v4. */
  validate: (draft: CustomDraft) => PairProblems | null;
  /** The names the API gives the two fields (JSON pointers), as this form calls them. */
  rename: Record<string, "v4" | "v6">;
  /** The keypad of the IPv4 field. A subnet is written with a slash, which the decimal pad of a phone does not have (S2-r2-1). */
  v4InputMode?: "decimal" | "text";
  /** The profile is locked: the fields and the buttons are off, and what is shown is what is stored (S2-r2-6). */
  readOnly?: boolean;
  /** The form was opened by the reader's own choice, so its first field takes the focus. A form that is simply there (a stored Custom, or one that
   * started over after Cancel) must not: it would take the focus on page load, and from the Cancel that was meant to leave it (S2-r2-2). */
  focusFirst?: boolean;
  /** Sends the draft. Resolves to null when it worked, or to the error. */
  onSave: (draft: CustomDraft) => Promise<unknown>;
  onCancel: () => void;
}) {
  const t = useTranslations("rules");
  const form = useApiForm({focus: focusFirst ? "v4" : undefined});
  const [draft, setDraft] = useState<CustomDraft>(initial);
  const [pending, setPending] = useState(false);
  const [saved, setSaved] = useState(false);

  async function submit() {
    if (pending || readOnly || form.blocked) return;
    // A keyboard in Iran types Persian digits as often as Latin ones; the checks and the API read Latin digits (S2-r2-1).
    const clean = {v4: toAsciiDigits(stripInvisible(draft.v4)).trim(), v6: toAsciiDigits(stripInvisible(draft.v6)).trim()};
    const problems = validate(clean);
    if (problems) {
      const first = problems.v4 ? (["v4", problems.v4] as const) : problems.v6 ? (["v6", problems.v6] as const) : (["v4", problems.form ?? ""] as const);
      return form.setFieldError(first[0], first[1]);
    }
    setPending(true);
    setSaved(false);
    form.clear();
    const error = await onSave(clean);
    setPending(false);
    if (error !== null) return form.fail(error, {rename});
    setDraft(clean);
    setSaved(true);
  }

  const field = (name: "v4" | "v6", ipv6: boolean) => {
    const message = form.fieldMessage(name);
    return (
      <TextField
        key={name}
        name={name}
        variant="secondary"
        fullWidth
        isDisabled={pending || readOnly}
        isInvalid={message !== undefined}
        value={draft[name]}
        onChange={(value) =>
          form
            .bind(name, (v: string) => {
              setSaved(false);
              setDraft((d) => ({...d, [name]: v}));
            })
            .onChange(value)
        }
      >
        {/* The name starts with the visible label and ends with the row, so a field is told apart from the same field of another row (S2-r3-3). */}
        <Label>
          {labels[name]}
          <span className="sr-only">: {subject}</span>
        </Label>
        <Input dir="ltr" autoComplete="off" spellCheck={false} inputMode={ipv6 ? "text" : v4InputMode} placeholder={placeholder[name]} />
        <FieldError>{message}</FieldError>
      </TextField>
    );
  };

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <div className="grid gap-3 sm:grid-cols-2">
        {field("v4", false)}
        {field("v6", true)}
      </div>
      <FormError error={form.formError} form={form} onRetry={() => void submit()} />
      <InPlaceActions
        subject={subject}
        isPending={pending}
        isDisabled={readOnly}
        retryIn={form.retryIn}
        onCancel={onCancel}
        extra={
          // The status element is always there, so that the text arriving in it is announced.
          <span role="status" data-testid="custom-saved" className="text-muted text-xs">
            {saved ? t("options.saved") : ""}
          </span>
        }
      />
    </AuthForm>
  );
}
