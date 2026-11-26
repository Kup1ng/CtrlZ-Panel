"use client";

import {useSaveWebauthn, useWebauthn, useWebauthnImpact, webauthnQueryOptions, type WebauthnConfig} from "@ctrlz/api-client/admin/hooks/settings.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {Button, Card, Description, FieldError, Input, Label, Skeleton, Switch, TextField, toast} from "@heroui/react";
import {Tech} from "../../data/Tech.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {ImpactFailed} from "./ImpactFailed.tsx";
import {hasInvisible, stripInvisible} from "../../forms/invisible.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {ConflictNote} from "../shared/ConflictNote.tsx";
import {LiveStatus} from "../shared/LiveStatus.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.4, T-331. The Passkey configuration: `rp_id` and `enabled` are editable, `allowed_origins` is read-only (the
// server writes it, AUTH 7.2). Changing the RP ID makes passkeys made under the old one stale, so
// `GET /settings/webauthn/impact?rp_id=` says how many credentials, users and enforced users it touches before the Save
// is possible. `PUT /settings/webauthn {rp_id, enabled}` needs the fresh TOTP window. In production the server refuses
// `enabled = true` until the real domain is accepted (P4): that is `validation_failed`, shown plainly with a line that
// says why it may happen, and not hidden behind a general error.

const IMPACT_DELAY_MS = 500;

type Value = {rpId: string; enabled: boolean};
const valueOf = (config: WebauthnConfig): Value => ({rpId: config.rp_id ?? "", enabled: config.enabled});
// The server compares the RP ID trimmed and lowercased, so two spellings of it are one value (wp10-r2-5).
const sameValue = (a: Value, b: Value) => a.enabled === b.enabled && a.rpId.trim().toLowerCase() === b.rpId.trim().toLowerCase();

export function WebauthnCard() {
  const t = useTranslations("admin");
  const webauthn = useWebauthn();
  return (
    <Card className="gap-4 p-6" data-testid="settings-webauthn">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("settings.webauthn.title")}</Card.Title>
        <Card.Description>{t("settings.webauthn.text")}</Card.Description>
      </Card.Header>
      <Card.Content>
        {webauthn.isPending ? (
          <Skeleton className="h-32 w-full rounded-(--radius-box)" />
        ) : !webauthn.data ? (
          <SectionError error={webauthn.error} onRetry={keepRetry(() => webauthn.refetch())} />
        ) : (
          <>
            <RefreshFailed error={webauthn.error} onRetry={() => webauthn.refetch()} />
            <Editor current={webauthn.data} />
          </>
        )}
      </Card.Content>
    </Card>
  );
}

function Editor({current}: {current: WebauthnConfig}) {
  const t = useTranslations("admin");
  const save = useSaveWebauthn();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm({focus: undefined});
  const currentRp = current.rp_id ?? "";
  // The server compares the RP ID trimmed and lowercased, so two spellings of it are one value (wp10-r2-5). The draft follows
  // the server when the form is untouched and is clean at once after a save (wp10-r3-3).
  const {draft, edit, dirty: draftDirty, reset: resetDraft, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Value>(valueOf(current), sameValue);
  const {rpId, enabled} = draft;
  const [settled, setSettled] = useState(currentRp);
  const busy = useRef(false);

  // The server lowercases and trims the RP ID before it compares or stores it, so the card does the same: "Panel.Example.com"
  // is not a change of "panel.example.com", and asking for an impact count or warning about stale passkeys for it would be
  // wrong (wp10-r2-5). What is sent is the lowercase form.
  const name = rpId.trim().toLowerCase();
  const rpChanged = name !== currentRp.trim().toLowerCase();
  const dirty = draftDirty;
  // A field another admin changed after this one edited it: Save waits for an answer, since the write would undo their value,
  // for instance the switch turned off during an incident (wp10-r5-3).
  const conflicted = conflicts.length > 0;

  // The count is asked for the value the admin has stopped typing, not for each letter: `settled` follows `name` after a pause.
  useEffect(() => {
    const timer = setTimeout(() => setSettled(name), IMPACT_DELAY_MS);
    return () => clearTimeout(timer);
  }, [name]);
  // A name that is not the settled one has no numbers yet, so nothing is asked and the Save waits.
  const lookup = rpChanged && name !== "" && settled === name ? name : undefined;
  const impact = useWebauthnImpact(lookup);
  // After a refetch that failed TanStack keeps the old data and sets the error: those numbers are not the ones the page says
  // it could not read, so they do not count (wp10-r3-6).
  const impactReady = !rpChanged || (lookup !== undefined && impact.data !== undefined && !impact.error);
  // A malformed name is answered with 400 `validation_failed`: the value is wrong, not the count, and Retry would only
  // ask the same question again (wp10-r1-3).
  const rpRejected = rpChanged && hasCode(impact.error, "validation_failed");
  // An emptied RP ID is its own state (wp10-r4-1): nothing can be counted for it, so the panel must not say it is counting, and
  // the field says what is wrong at once. The stored value was not empty, or this would be a change nobody made.
  const rpEmpty = rpChanged && name === "";
  const rpMessage = form.fieldMessage("rp_id") ?? (rpEmpty ? t("settings.webauthn.rpRequired") : rpRejected ? t("settings.webauthn.rpMalformed") : undefined);

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    // Before the impact wait: an empty name has no impact to wait for, so Enter must say it is required (wp10-r4-1).
    if (name === "") return form.setFieldError("rp_id", t("settings.webauthn.rpRequired"));
    // The same wait as the Save button's. Retry of a failed save comes here without the button, and the RP ID may have been
    // edited since: a value whose impact was never shown must not be written, because it makes every passkey stale (wp10-r3-6).
    if (rpChanged && (!impactReady || rpRejected)) return;
    if (hasInvisible(name)) return form.setFieldError("rp_id", t("settings.webauthn.rpInvalid"));
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the switch and the RP ID this write replaces are read before every
      // try of it, the one after the fresh-code dialog included (wp10-r6-5, wp10-r7-5).
      const written = await write({options: webauthnQueryOptions(), pick: valueOf, seen: valueOf(current), same: sameValue}, () => save.mutateAsync({rp_id: name, enabled}));
      if (!written) return;
      saved({rpId: name, enabled});
      toast.success(t("settings.webauthn.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  function reset() {
    form.clear();
    resetDraft();
  }

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <TextField
        name="rp_id"
        variant="secondary"
        fullWidth
        autoComplete="off"
        isDisabled={pending}
        isInvalid={rpMessage !== undefined}
        value={rpId}
        onChange={(value) => {
          edit({rpId: stripInvisible(value)});
          // A failure that is still on show (and its Retry) belongs to the value that was sent, not to this one (wp10-r3-6).
          form.clear();
        }}
      >
        <Label>{t("settings.webauthn.rpId")}</Label>
        <Input dir="ltr" className="text-start font-mono" spellCheck={false} autoCapitalize="none" autoCorrect="off" />
        <Description>{t("settings.webauthn.rpIdHint")}</Description>
        <FieldError>{rpMessage}</FieldError>
      </TextField>
      {conflicts.includes("rpId") ? (
        <ConflictNote
          name="rp_id"
          value={serverValue.rpId === "" ? "" : <Tech>{serverValue.rpId}</Tech>}
          onKeep={() => keepMine("rpId")}
          onUseServer={() => {
            takeServer("rpId");
            form.clear();
          }}
        />
      ) : null}

      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 flex-col">
          <span className="text-sm font-medium">{t("settings.webauthn.enabled")}</span>
          <span className="text-muted text-xs">{t("settings.webauthn.enabledHint")}</span>
        </div>
        <Switch name="enabled" aria-label={t("settings.webauthn.enabled")} isSelected={enabled}
          onChange={(value) => {
            edit({enabled: value});
            form.clear();
          }} isDisabled={pending}>
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      </div>

      {conflicts.includes("enabled") ? (
        <ConflictNote
          name="enabled"
          value={serverValue.enabled ? t("conflict.on") : t("conflict.off")}
          onKeep={() => keepMine("enabled")}
          onUseServer={() => {
            takeServer("enabled");
            form.clear();
          }}
        />
      ) : null}

      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">{t("settings.webauthn.origins")}</span>
        {current.allowed_origins.length === 0 ? (
          <span className="text-muted text-sm">{t("settings.webauthn.originsNone")}</span>
        ) : (
          <ul className="flex flex-col gap-0.5 text-sm" data-testid="webauthn-origins">
            {current.allowed_origins.map((origin) => (
              <li key={origin}>
                <Tech className="[overflow-wrap:anywhere]">{origin}</Tech>
              </li>
            ))}
          </ul>
        )}
        <span className="text-muted text-xs">{t("settings.webauthn.originsHint")}</span>
      </div>

      {rpChanged && !rpEmpty ? (
        <LiveStatus className="bg-surface-secondary flex flex-col gap-1 rounded-(--radius-box) p-4 text-sm" testId="webauthn-impact">
          <span className="font-medium">{t("settings.webauthn.impact.title")}</span>
          {!impactReady && !impact.error ? (
            <span className="text-muted">{t("settings.impactLoading")}</span>
          ) : rpRejected ? (
            <span className="text-muted">{t("settings.webauthn.impact.rejected")}</span>
          ) : impact.error || !impact.data ? (
            <ImpactFailed onRetry={() => impact.refetch()} />
          ) : (
            <>
              <span data-testid="impact-credentials">{t("settings.webauthn.impact.credentials", {count: impact.data.credentials})}</span>
              <span data-testid="impact-users">{t("settings.webauthn.impact.users", {count: impact.data.users})}</span>
              <span data-testid="impact-enforced">{t("settings.webauthn.impact.enforced", {count: impact.data.enforced_users})}</span>
            </>
          )}
        </LiveStatus>
      ) : null}

      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      {hasCode(form.formError, "validation_failed") ? (
        <p role="note" className="text-muted text-sm" data-testid="webauthn-refused">
          {t("settings.webauthn.refused")}
        </p>
      ) : null}
      <OfflineNotice />
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="tertiary" isDisabled={!dirty || pending} onPress={reset}>
          {t("settings.cancel")}
        </Button>
        <Button type="submit" variant="primary" isPending={pending} isDisabled={!dirty || !impactReady || conflicted || form.retryIn > 0}>
          {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("settings.webauthn.submit")}
        </Button>
      </div>
    </AuthForm>
  );
}
