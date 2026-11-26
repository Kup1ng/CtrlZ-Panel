"use client";

import {
  useGateways,
  useSaveProviderTemplate,
  useSaveTemplate,
  templatesQueryOptions,
  useTemplates,
  type SmsGatewayRow,
  type SmsTemplateRow,
} from "@ctrlz/api-client/admin/hooks/sms.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button, Card, Chip, Description, FieldError, Input, Label, Skeleton, TextArea, TextField, toast} from "@heroui/react";
import {Tech} from "../../data/Tech.tsx";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {ConflictNote} from "../shared/ConflictNote.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerDraft, useServerForm} from "../shared/useServerDraft.ts";
import {isTemplateId, providerLabel} from "./providers.ts";
import {countSms, isNoticeKey, OTP_EN_MAX_UNITS, OTP_FA_MAX_UNITS, otpBodyRefusal, placeholders} from "./smsParts.ts";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.3, the Templates tab. One card per template and language: the body editor with a live count of characters and
// billed parts (`{code}` filled by a code of full length), a warning for a Persian OTP body that may cost two parts, and
// per gateway the provider's own template id with its parameter names. The body is prose that the API checks (a wrong
// number of placeholders, or a link, is `validation_failed`) and needs no fresh code; the mapping to a gateway does.
// The API keeps a body on one line (control characters are refused), so a line break typed or pasted becomes a space.

const PARAM_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_PARAMS = 8;

/** Persian prose keeps the half-space (U+200C), which the language needs inside words (the `prosebody` pattern of the document). Every other control, format or private-use character is dropped. */
const cleanProse = (value: string) => value.replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cs}]/gu, (ch) => (ch === "‌" ? ch : "")).trim();

const nameList = (names: string) => names.split(/[\s,]+/).filter(Boolean);
type Mapping = {id: string; names: string};
const sameMapping = (a: Mapping, b: Mapping) => toAsciiDigits(a.id).trim() === toAsciiDigits(b.id).trim() && nameList(a.names).join(",") === nameList(b.names).join(",");
const sameBody = (a: string, b: string) => cleanProse(a) === cleanProse(b);
const mappingOf = (row: SmsTemplateRow | undefined, provider: string): Mapping => {
  const mapping = row?.mappings.find((m) => m.provider === provider);
  return {id: mapping?.provider_template_id ?? "", names: mapping?.param_names.join(", ") ?? ""};
};
const rowOf = (rows: SmsTemplateRow[], row: SmsTemplateRow) => rows.find((r) => r.key === row.key && r.locale === row.locale);

export function TemplatesTab() {
  const t = useTranslations("admin");
  const templates = useTemplates();
  const gateways = useGateways();
  if (templates.isPending || gateways.isPending) return <Skeleton className="h-48 w-full rounded-(--radius-box)" />;
  if (!templates.data) return <SectionError error={templates.error} onRetry={keepRetry(() => templates.refetch())} />;
  if (!gateways.data) return <SectionError error={gateways.error} onRetry={keepRetry(() => gateways.refetch())} />;
  if (templates.data.length === 0) return <SectionEmpty icon="sms" title={t("sms.templates.empty")} />;
  return (
    <>
      <RefreshFailed
        error={templates.error ?? gateways.error}
        // Both reads can be failing at once; one press asks again for each of them that is (wp10-r11-3).
        onRetry={() => Promise.all([templates.error ? templates.refetch() : null, gateways.error ? gateways.refetch() : null])}
      />
      <ul className="grid gap-4 xl:grid-cols-2" aria-label={t("sms.tabs.templates")}>
        {templates.data.map((row) => (
          <li key={`${row.key}:${row.locale}`}>
            <TemplateCard row={row} gateways={gateways.data} />
          </li>
        ))}
      </ul>
    </>
  );
}

function TemplateCard({row, gateways}: {row: SmsTemplateRow; gateways: SmsGatewayRow[]}) {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const save = useSaveTemplate();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  // Compared as the API will store it (cleaned), so a saved text leaves Save off whatever the server answers with.
  // The text another admin saved while this one was editing is a conflict: Save waits for an answer (wp10-r5-3).
  const {draft: body, setDraft: setBody, dirty, reset, saved, conflict, serverValue, keepMine} = useServerDraft(row.body, sameBody);
  const busy = useRef(false);

  const count = countSms(body);
  const expected = placeholders(body).length;
  // The API holds the three login-code templates to one billed part (422 body:too_long). The same rule is judged here on the text
  // as it will be sent, so the admin sees the reason before Save and not as a refusal after it (wp10-r17-1).
  const refusal = otpBodyRefusal(row.key, row.locale, cleanProse(body));
  // The two security notices (Question 19) are held to one part too, but they are not login codes, and they take no value:
  // a `{code}` in one is a refused body (the API counts zero markers for them), so it is said before Save as well.
  const notice = isNoticeKey(row.key);
  const refusalText =
    refusal === "not_gsm"
      ? t(notice ? "sms.templates.noticeNotGsm" : "sms.templates.otpNotGsm")
      : refusal === "too_long"
        ? row.locale === "en"
          ? t(notice ? "sms.templates.noticeTooLongEn" : "sms.templates.otpTooLongEn", {limit: format.number(OTP_EN_MAX_UNITS)})
          : t(notice ? "sms.templates.noticeTooLongFa" : "sms.templates.otpTooLongFa", {limit: format.number(OTP_FA_MAX_UNITS)})
        : notice && body.includes("{code}")
          ? t("sms.templates.noticeNoCode")
          : null;

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflict) return;
    const text = cleanProse(body);
    if (text === "") return form.setFieldError("body", t("sms.templates.bodyRequired"));
    if (refusalText !== null) return form.setFieldError("body", refusalText);
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the text this write replaces is read before it (wp10-r6-5).
      const written = await write({options: templatesQueryOptions(), pick: (rows) => rowOf(rows, row)?.body ?? "", seen: row.body, same: sameBody}, () =>
        save.mutateAsync({key: row.key, locale: row.locale as "fa" | "en", body: text}),
      );
      if (!written) return;
      saved(text);
      toast.success(t("sms.templates.saved"));
    } catch (error) {
      if (isHandledError(error)) return;
      // A wrong number of placeholders or a link is a `validation_failed` about this one field. Any other failure (a 500,
      // a busy server, a dropped connection) says nothing about the text, so it goes to FormError with Retry and its wait
      // (wp10-r1-1): telling the admin a correct text is invalid sends them to rewrite it.
      if (hasCode(error, "validation_failed")) form.fail(error, {field: "body", message: t("sms.templates.bodyInvalid")});
      else form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <Card className="h-full gap-4 p-5" data-testid={`template-${row.key}-${row.locale}`}>
      <Card.Header className="flex flex-row items-center justify-between gap-2">
        <Card.Title className="text-base">
          <Tech>{row.key}</Tech>
        </Card.Title>
        <Chip size="sm" variant="soft">
          <Chip.Label>{t(`sms.templates.locale.${row.locale === "en" ? "en" : "fa"}`)}</Chip.Label>
        </Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">
        <AuthForm form={form} onSubmit={() => void submit()}>
          <TextField
            name={`body-${row.key}-${row.locale}`}
            variant="secondary"
            fullWidth
            isDisabled={pending}
            isInvalid={form.fieldMessage("body") !== undefined}
            value={body}
            onChange={(value) => {
              setBody(value.replace(/[\r\n]+/g, " "));
              form.clearField("body");
            }}
          >
            <Label>{t("sms.templates.body")}</Label>
            <TextArea rows={3} dir="auto" maxLength={1024} className="[overflow-wrap:anywhere]" />
            <Description>{t(notice ? "sms.templates.noticeHint" : "sms.templates.bodyHint")}</Description>
            <FieldError>{form.fieldMessage("body")}</FieldError>
          </TextField>
          {conflict ? (
            <ConflictNote
              name={`body-${row.key}-${row.locale}`}
              value={<span dir="auto">{serverValue}</span>}
              onKeep={keepMine}
              onUseServer={() => (reset(), form.clear())}
            />
          ) : null}
          <p className="text-muted text-xs" aria-live="polite" data-testid="sms-count">
            {t("sms.templates.count", {
              characters: format.number(count.characters),
              parts: count.parts,
              encoding: t(`sms.templates.encoding.${count.encoding}`),
              single: format.number(count.single),
              multi: format.number(count.multi),
            })}
          </p>
          {refusalText !== null ? (
            <Alert status="danger" data-testid="otp-refused">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>{refusalText}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
          <OfflineNotice />
          <div className="flex justify-end gap-2">
            <Button variant="tertiary" isDisabled={!dirty || pending} onPress={() => (reset(), form.clear())}>
              {t("settings.cancel")}
            </Button>
            <Button type="submit" variant="primary" isPending={pending} isDisabled={!dirty || conflict || refusalText !== null || form.retryIn > 0}>
              {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("sms.templates.save")}
            </Button>
          </div>
        </AuthForm>

        <div className="flex flex-col gap-3">
          <h3 className="text-sm font-medium">{t("sms.templates.mappings")}</h3>
          <p className="text-muted text-xs">{t("sms.templates.mappingsHint", {count: expected})}</p>
          {gateways
            .filter((g) => g.provider !== "noop")
            .map((g) => (
              <MappingForm key={g.provider} row={row} gateway={g} />
            ))}
        </div>
      </Card.Content>
    </Card>
  );
}

function MappingForm({row, gateway}: {row: SmsTemplateRow; gateway: SmsGatewayRow}) {
  const t = useTranslations("admin");
  const save = useSaveProviderTemplate();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  // "code,brand" and "code, brand" are one list, and the id is compared as digits, so what was saved is not "changed".
  const {draft, edit, dirty, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm(mappingOf(row, gateway.provider), sameMapping);
  const {id, names} = draft;
  const conflicted = conflicts.length > 0;
  const note = (key: "id" | "names", field: string) =>
    conflicts.includes(key) ? (
      <ConflictNote
        name={`${key}-${row.key}-${row.locale}-${gateway.provider}`}
        value={<Tech>{serverValue[key]}</Tech>}
        onKeep={() => keepMine(key)}
        onUseServer={() => {
          takeServer(key);
          form.clearField(field);
        }}
      />
    ) : null;
  const setId = (value: string) => edit({id: value});
  const setNames = (value: string) => edit({names: value});
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const templateId = toAsciiDigits(id).trim();
    if (!isTemplateId(gateway.provider, templateId)) {
      return form.setFieldError("provider_template_id", t(gateway.provider === "sms_ir" ? "sms.templates.idInvalidSmsir" : "sms.templates.idInvalid"));
    }
    const list = nameList(names);
    if (list.length > MAX_PARAMS || !list.every((n) => PARAM_RE.test(n))) return form.setFieldError("param_names", t("sms.templates.namesInvalid", {max: MAX_PARAMS}));
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the mapping this write replaces is read before every try of it, the one
      // after the fresh-code dialog included (wp10-r6-5, wp10-r7-5).
      const written = await write(
        {options: templatesQueryOptions(), pick: (rows) => mappingOf(rowOf(rows, row), gateway.provider), seen: mappingOf(row, gateway.provider), same: sameMapping},
        () => save.mutateAsync({provider: gateway.provider, key: row.key, locale: row.locale as "fa" | "en", body: {provider_template_id: templateId, param_names: list}}),
      );
      if (!written) return;
      saved({id: templateId, names: list.join(", ")});
      toast.success(t("sms.templates.mappingSaved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  const inputId = `${row.key}-${row.locale}-${gateway.provider}`;
  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <div className="bg-surface-secondary flex flex-col gap-3 rounded-(--radius-box) p-3" data-testid={`mapping-${gateway.provider}`}>
        <span className="text-sm font-medium">
          <Tech mono={false}>{providerLabel(gateway.provider)}</Tech>
        </span>
        <TextField
          name={`provider_template_id-${inputId}`}
          variant="secondary"
          fullWidth
          autoComplete="off"
          inputMode="numeric"
          isDisabled={pending}
          isInvalid={form.fieldMessage("provider_template_id") !== undefined}
          value={id}
          onChange={form.bind("provider_template_id", setId).onChange}
        >
          <Label>{t("sms.templates.providerId")}</Label>
          <Input dir="ltr" className="text-start" />
          <FieldError>{form.fieldMessage("provider_template_id")}</FieldError>
        </TextField>
        {note("id", "provider_template_id")}
        <TextField
          name={`param_names-${inputId}`}
          variant="secondary"
          fullWidth
          autoComplete="off"
          isDisabled={pending}
          isInvalid={form.fieldMessage("param_names") !== undefined}
          value={names}
          onChange={form.bind("param_names", setNames).onChange}
        >
          <Label>{t("sms.templates.paramNames")}</Label>
          <Input dir="ltr" className="text-start" spellCheck={false} autoCapitalize="none" />
          <Description>{t("sms.templates.paramNamesHint")}</Description>
          <FieldError>{form.fieldMessage("param_names")}</FieldError>
        </TextField>
        {note("names", "param_names")}
        <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
        <div className="flex justify-end">
          <Button type="submit" size="sm" variant="secondary" isPending={pending} isDisabled={!dirty || conflicted || form.retryIn > 0}>
            {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("sms.templates.saveMapping")}
          </Button>
        </div>
      </div>
    </AuthForm>
  );
}
