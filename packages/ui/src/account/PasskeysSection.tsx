"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {
  passkeyKeys,
  useAddPasskey,
  useDeletePasskey,
  usePasskeys,
  useRenamePasskey,
  useReviewPasskeys,
  useSetPasskeyEnforcement,
} from "@ctrlz/api-client/hooks/passkeys.ts";
import type {Me} from "@ctrlz/api-client/session.ts";
import {isWebAuthnCancel, isWebAuthnSupported} from "@ctrlz/api-client/webauthn.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, AlertDialog, Button, Chip, FieldError, Input, Label, Skeleton, Switch, TextField, toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {ReauthPanel} from "../auth/ReauthPanel.tsx";
import {useAuthConfig} from "../auth/useAuthConfig.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {isHandledError} from "../feedback/handleApiError.ts";
import {FormError} from "../forms/FormError.tsx";
import {InlineEditRow} from "../forms/InlineEditRow.tsx";
import {cleanName, nameLength} from "../forms/invisible.ts";
import {AccountSection, SettingRow} from "./AccountSection.tsx";

// Spec 12.5 (T-103, T-106): the passkeys of the account. The whole section is hidden when the
// operator has passkeys off (`passkey_enabled`, AUTH 7.2). Adding one takes a reauth, then the browser's
// prompt, then a name; deleting and Enforce take the reauth the server asks for (the 403 opens the dialog
// and repeats the call once); after a recovery, the list is reviewed and confirmed (AUTH 7.7).

type Passkey = NonNullable<ReturnType<typeof usePasskeys>["data"]>[number];

const NAME_MAX = 64;

export function PasskeysSection({me}: {me: Me}) {
  const t = useTranslations("account");
  const config = useAuthConfig();

  if (config.status === "loading") {
    return (
      <AccountSection id="passkeys" title={t("sections.passkeys")}>
        <Skeleton aria-hidden className="h-16 w-full rounded-(--radius-box)" />
      </AccountSection>
    );
  }
  // Off, or the answer is missing: the safe reading is that the section is not there, and the list is not asked for.
  if (!config.passkeyEnabled) return null;
  return <PasskeysList me={me} />;
}

function PasskeysList({me}: {me: Me}) {
  const t = useTranslations("account");
  const passkeys = usePasskeys();
  // The passkey whose Delete was confirmed. Its row, with the Delete button and the dialog that was to give the focus
  // back, leaves the page, and the next Tab would start from the top of the document: when the row is gone the
  // focus goes to the section title instead (wp9-r1-5).
  const removed = useRef<string | null>(null);
  const list = passkeys.data;
  useEffect(() => {
    const id = removed.current;
    if (id === null || !list || list.some((row) => row.id === id)) return;
    removed.current = null;
    // After the dialog's own focus restore, which finds nothing to restore to.
    const frame = requestAnimationFrame(() => document.getElementById("passkeys-title")?.focus());
    return () => cancelAnimationFrame(frame);
  }, [list]);
  // The same for "I checked the list": the alert, with the button that has the focus, leaves the page when /me says the
  // review is done (wp9-r2-2).
  const reviewing = useRef(false);
  const reviewPending = me.security.passkey_review_required;
  useEffect(() => {
    if (reviewPending || !reviewing.current) return;
    reviewing.current = false;
    const frame = requestAnimationFrame(() => document.getElementById("passkeys-title")?.focus());
    return () => cancelAnimationFrame(frame);
  }, [reviewPending]);
  if (hasCode(passkeys.error, "passkey_unavailable")) return null;

  return (
    <AccountSection id="passkeys" title={t("sections.passkeys")}>
      {reviewPending ? <ReviewAlert onReviewing={(on) => (reviewing.current = on)} /> : null}
      {me.security.enforce_lift_at ? <LiftAlert at={me.security.enforce_lift_at} /> : null}
      {passkeys.isPending ? (
        <div role="status" aria-busy="true">
          <span className="sr-only">{t("passkeys.loading")}</span>
          <Skeleton aria-hidden className="h-16 w-full rounded-(--radius-box)" />
        </div>
      ) : passkeys.isError ? (
        <SectionError error={passkeys.error} onRetry={() => void passkeys.refetch()} />
      ) : (
        <>
          {passkeys.data.map((passkey) => (
            <PasskeyRow key={passkey.id} passkey={passkey} all={passkeys.data} me={me} onRemoved={(id) => (removed.current = id)} />
          ))}
          <AddRow me={me} />
        </>
      )}
      <EnforceRow me={me} />
    </AccountSection>
  );
}

// ---- alerts -----------------------------------------------------------------------------------------------

function ReviewAlert({onReviewing}: {onReviewing: (on: boolean) => void}) {
  const t = useTranslations("account");
  const review = useReviewPasskeys();
  const recover = useRecoverable();
  const [error, setError] = useState<unknown>(null);

  async function confirm() {
    setError(null);
    // Set before the call: /me may answer and remove this alert before the call resolves here.
    onReviewing(true);
    try {
      // Reauth here cannot be a passkey: the panel hides that button while the review is pending.
      await recover(() => review.mutateAsync());
      toast.success(t("passkeys.reviewDone"));
    } catch (failure) {
      onReviewing(false);
      if (!isHandledError(failure)) setError(failure);
    }
  }

  return (
    <Alert status="warning" data-testid="passkey-review">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{t("passkeys.reviewTitle")}</Alert.Title>
        <Alert.Description>{t("passkeys.reviewText")}</Alert.Description>
        {error ? <FormError className="mt-2" error={error} /> : null}
        <div className="mt-2">
          <Button size="sm" variant="primary" isPending={review.isPending} onPress={() => void confirm()}>
            {t("passkeys.reviewed")}
          </Button>
        </div>
      </Alert.Content>
    </Alert>
  );
}

function LiftAlert({at}: {at: string}) {
  const t = useTranslations("account");
  const f = useAppFormat();
  return (
    <Alert status="warning" data-testid="enforce-lift">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Description>{t("passkeys.liftText", {date: f.dateTime(at)})}</Alert.Description>
      </Alert.Content>
    </Alert>
  );
}

// ---- one passkey ------------------------------------------------------------------------------------------

function PasskeyRow({passkey, all, me, onRemoved}: {passkey: Passkey; all: Passkey[]; me: Me; onRemoved: (id: string | null) => void}) {
  const t = useTranslations("account");
  const f = useAppFormat();
  const rename = useRenamePasskey();
  const recover = useRecoverable();
  const [name, setName] = useState(passkey.name);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const e = useTranslations("errors");

  async function save(): Promise<boolean> {
    const next = cleanName(name);
    if (next.length === 0) {
      setError(t("passkeys.nameRequired"));
      return false;
    }
    if (nameLength(next) > NAME_MAX) {
      setError(t("passkeys.nameTooLong", {max: NAME_MAX}));
      return false;
    }
    try {
      await recover(() => rename.mutateAsync({id: passkey.id, name: next}));
      return true;
    } catch (failure) {
      if (!isHandledError(failure)) setError(hasCode(failure, "validation_failed") ? t("passkeys.nameTooLong", {max: NAME_MAX}) : e("unknown"));
      return false;
    }
  }

  return (
    <>
      <InlineEditRow
        id={`passkey-${passkey.id}`}
        label={t("passkeys.passkeyLabel")}
        value={
          <span className="flex flex-wrap items-center gap-2">
            <span>{passkey.name}</span>
            {passkey.backup_eligible ? (
              <Chip size="sm" variant="soft">
                {t("passkeys.synced")}
              </Chip>
            ) : null}
            {passkey.stale ? (
              <Chip size="sm" color="warning" variant="soft">
                {t("passkeys.stale")}
              </Chip>
            ) : null}
          </span>
        }
        description={
          <>
            {t("passkeys.created", {date: f.date(passkey.created_at)})}
            {" · "}
            {passkey.last_used_at ? t("passkeys.lastUsed", {date: f.relative(passkey.last_used_at)}) : t("passkeys.neverUsed")}
            {passkey.stale ? <span className="mt-1 block text-(--warning-text)">{t("passkeys.staleText")}</span> : null}
          </>
        }
        editLabel={t("passkeys.rename")}
        editAriaLabel={t("passkeys.renameAria", {name: passkey.name})}
        onOpenChange={(open) => {
          if (open) {
            setName(passkey.name);
            setError(null);
          }
        }}
        editor={
          <NameField
            value={name}
            error={error}
            onChange={(value) => {
              setName(value);
              setError(null);
            }}
          />
        }
        onContinue={save}
        continueLabel={t("passkeys.saveName")}
        trailing={
          <Button
            size="sm"
            variant="danger-soft"
            aria-label={t("passkeys.deleteAria", {name: passkey.name})}
            onPress={() => setDeleting(true)}
          >
            {t("passkeys.delete")}
          </Button>
        }
      />
      {deleting ? <DeleteDialog passkey={passkey} all={all} me={me} onRemoved={onRemoved} onClose={() => setDeleting(false)} /> : null}
    </>
  );
}

function DeleteDialog({
  passkey,
  all,
  me,
  onRemoved,
  onClose,
}: {
  passkey: Passkey;
  all: Passkey[];
  me: Me;
  onRemoved: (id: string | null) => void;
  onClose: () => void;
}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const remove = useDeletePasskey();
  const recover = useRecoverable();
  const [error, setError] = useState<unknown>(null);
  // Deleting the last live passkey turns Enforce off (the API's rule, AUTH 7.5).
  const lastLive = !passkey.stale && all.filter((row) => !row.stale).length === 1;
  const lifts = lastLive && me.security.enforce_passkey;

  async function confirm() {
    setError(null);
    try {
      // Before the call settles: the list refetch inside it removes this row before the line after the await runs.
      onRemoved(passkey.id);
      await recover(() => remove.mutateAsync(passkey.id));
      toast.success(t("passkeys.deleted"));
      onClose();
    } catch (failure) {
      // It stays, so there is nothing to take the focus back from.
      onRemoved(null);
      if (!isHandledError(failure)) setError(failure);
    }
  }

  return (
    <AlertDialog.Backdrop isOpen onOpenChange={(open) => !open && !remove.isPending && onClose()}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[400px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="danger">
              <Icon name="trash" className="size-5" />
            </AlertDialog.Icon>
            <AlertDialog.Heading>{t("passkeys.deleteTitle", {name: passkey.name})}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>
            <div className="flex flex-col gap-3">
              <p>{t("passkeys.deleteText")}</p>
              {lifts ? <p className="text-(--warning-text)">{t("passkeys.deleteEnforce")}</p> : null}
              <FormError error={error} onRetry={() => void confirm()} />
            </div>
          </AlertDialog.Body>
          <AlertDialog.Footer>
            <Button slot="close" variant="tertiary" isDisabled={remove.isPending}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={remove.isPending} onPress={() => void confirm()}>
              {t("passkeys.deleteConfirm")}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}

/** The name of a passkey. It takes the focus when it appears, because the person has just asked for it (Rename, or the passkey was added). */
function NameField({value, error, onChange}: {value: string; error: string | null; onChange: (value: string) => void}) {
  const t = useTranslations("account");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => input.current?.focus(), []);
  return (
    <TextField name="passkey_name" variant="secondary" fullWidth value={value} onChange={onChange} isInvalid={error !== null}>
      <Label>{t("passkeys.nameLabel")}</Label>
      <Input ref={input} autoComplete="off" />
      <FieldError>{error}</FieldError>
    </TextField>
  );
}

// ---- add -------------------------------------------------------------------------------------------------

function AddRow({me}: {me: Me}) {
  const t = useTranslations("account");
  // A browser without WebAuthn can still list and delete: only the add is off, and the row says why.
  const supported = isWebAuthnSupported();
  return (
    <InlineEditRow
      id="passkey-add"
      label={t("passkeys.addLabel")}
      value={supported ? t("passkeys.addValue") : t("passkeys.unsupported")}
      editLabel={t("passkeys.add")}
      editAriaLabel={t("passkeys.addAria")}
      editor={supported ? ({close}) => <AddEditor me={me} close={close} /> : undefined}
    />
  );
}

function AddEditor({me, close}: {me: Me; close: () => void}) {
  const [stage, setStage] = useState<"reauth" | "create" | "name">("reauth");
  const [added, setAdded] = useState<Passkey | null>(null);
  if (stage === "reauth") return <ReauthPanel me={me} onDone={() => setStage("create")} onCancel={close} />;
  if (stage === "create" || !added) {
    return (
      <CreateStep
        onCancel={close}
        onAdded={(passkey) => {
          setAdded(passkey);
          setStage("name");
        }}
      />
    );
  }
  return <NameStep passkey={added} onDone={close} />;
}

function CreateStep({onAdded, onCancel}: {onAdded: (passkey: Passkey) => void; onCancel: () => void}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const add = useAddPasskey();
  const recover = useRecoverable();
  const [error, setError] = useState<unknown>(null);
  const ceremony = useRef<AbortController | null>(null);
  const createButton = useRef<HTMLButtonElement>(null);

  // The reauth form that led here has just left the page with the focus in it (wp9-r3-2).
  useEffect(() => createButton.current?.focus(), []);

  // A prompt that is still open when the row goes away must not finish into a closed row.
  useEffect(() => () => ceremony.current?.abort(), []);

  async function create() {
    setError(null);
    const controller = new AbortController();
    ceremony.current = controller;
    try {
      const result = await recover(() => add.mutateAsync(controller.signal));
      // The passkey was added and other sessions ended even if the row closed while finish was on the wire (gate-r16-9): that is said whatever
      // the row does, and the caches are dropped by the mutation itself. Only the next step of the row is skipped, since the row is gone.
      if (result.ended_sessions > 0) toast.info(t("passkeys.ended", {count: result.ended_sessions}));
      if (controller.signal.aborted) return;
      onAdded(result.passkey);
    } catch (failure) {
      // Closing the browser's prompt is an answer, not a failure.
      if (isWebAuthnCancel(failure) || controller.signal.aborted) return;
      if (!isHandledError(failure)) setError(failure);
    }
  }

  const duplicate = error instanceof DOMException && error.name === "InvalidStateError";
  const message = duplicate
    ? t("passkeys.duplicate")
    : hasCode(error, "passkey_invalid", "ticket_invalid")
      ? t("passkeys.addFailed")
      : hasCode(error, "validation_failed")
        ? t("passkeys.tooMany")
        : undefined;

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted text-sm">{t("passkeys.createText")}</p>
      <FormError error={error} message={message} onRetry={() => void create()} />
      <div className="flex justify-end gap-2">
        <Button variant="tertiary" isDisabled={add.isPending} onPress={onCancel}>
          {c("cancel")}
        </Button>
        <Button ref={createButton} variant="primary" isPending={add.isPending} onPress={() => void create()}>
          {t("passkeys.create")}
        </Button>
      </div>
    </div>
  );
}

function NameStep({passkey, onDone}: {passkey: Passkey; onDone: () => void}) {
  const t = useTranslations("account");
  const e = useTranslations("errors");
  const rename = useRenamePasskey();
  const recover = useRecoverable();
  const [name, setName] = useState(passkey.name);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    const next = cleanName(name);
    if (next.length === 0) return setError(t("passkeys.nameRequired"));
    if (nameLength(next) > NAME_MAX) return setError(t("passkeys.nameTooLong", {max: NAME_MAX}));
    // Unchanged: the server already holds this name.
    if (next === passkey.name) return onDone();
    try {
      await recover(() => rename.mutateAsync({id: passkey.id, name: next}));
      toast.success(t("passkeys.added"));
      onDone();
    } catch (failure) {
      if (!isHandledError(failure)) setError(e("unknown"));
    }
  }

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
    >
      <p className="text-muted text-sm">{t("passkeys.nameText")}</p>
      <NameField
        value={name}
        error={error}
        onChange={(value) => {
          setName(value);
          setError(null);
        }}
      />
      <div className="flex justify-end gap-2">
        <Button variant="tertiary" isDisabled={rename.isPending} onPress={onDone}>
          {t("passkeys.keepName")}
        </Button>
        <Button type="submit" variant="primary" isPending={rename.isPending}>
          {t("passkeys.saveName")}
        </Button>
      </div>
    </form>
  );
}

// ---- enforce ---------------------------------------------------------------------------------------------

function EnforceRow({me}: {me: Me}) {
  const t = useTranslations("account");
  const enforce = useSetPasskeyEnforcement();
  const recover = useRecoverable();
  const queryClient = useQueryClient();
  const [error, setError] = useState<unknown>(null);
  const on = me.security.enforce_passkey;

  async function toggle(next: boolean) {
    setError(null);
    try {
      const result = await recover(() => enforce.mutateAsync(next));
      toast.success(
        result.ended_sessions > 0
          ? t("passkeys.enforce.endedSessions", {count: result.ended_sessions})
          : next
            ? t("passkeys.enforce.onDone")
            : t("passkeys.enforce.offDone"),
      );
    } catch (failure) {
      if (isHandledError(failure)) return;
      setError(failure);
      // The switch is controlled by `/me`, so it already shows the real state; a refetch settles a race with another tab.
      void queryClient.invalidateQueries({queryKey: passkeyKeys.list});
    }
  }

  const precondition = hasCode(error, "enforce_precondition_failed");
  return (
    <SettingRow
      id="enforce"
      label={t("passkeys.enforce.label")}
      description={t("passkeys.enforce.description")}
      control={
        <Switch
          isSelected={on}
          // Read-only, not disabled: the switch has the focus when it is pressed, and a disabled control gives it up for good
          // (wp9-r3-2). A press while the call runs changes nothing.
          isReadOnly={enforce.isPending}
          onChange={(next) => void toggle(next)}
          aria-label={t("passkeys.enforce.label")}
        >
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      }
    >
      {precondition ? (
        <p role="alert" className="text-sm text-(--danger-text)">
          {me.security.passkey_review_required ? t("passkeys.enforce.needsReview") : t("passkeys.enforce.needs")}
        </p>
      ) : error ? (
        <FormError error={error} />
      ) : null}
    </SettingRow>
  );
}
