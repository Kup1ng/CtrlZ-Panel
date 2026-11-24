"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useEndSession, useLogoutAll, useSessions} from "@ctrlz/api-client/hooks/sessions.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {AlertDialog, Button, Chip, Skeleton} from "@heroui/react";
import {useLocale, useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {useRecoverable} from "../auth/ReauthDialog.tsx";
import {Tech} from "../data/Tech.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {isHandledError} from "../feedback/handleApiError.ts";
import {FormError} from "../forms/FormError.tsx";
import {InlineEditRow} from "../forms/InlineEditRow.tsx";

// Spec 12.4 (T-108): where the account is signed in. The list is read when the row is opened, and each
// other session has an End button. A session newer than this one needs a live reauth (AUTH 12.1): the
// 403 opens the reauth dialog and the call is repeated once. "Log out all" asks first, then the server
// ends every session, this one included, and the page leaves through `logoutLocal`, so there is no second
// logout call that the server would answer with 401.

const AGENT_MAX = 80;

/** A user agent can be a kilobyte of text. The row shows the start of it, which is the part people recognise. */
export function trimAgent(agent: string): string {
  return agent.length > AGENT_MAX ? `${agent.slice(0, AGENT_MAX).trimEnd()}…` : agent;
}

export function SessionsRow() {
  const t = useTranslations("account");
  return (
    <InlineEditRow
      id="sessions"
      label={t("sessions.label")}
      value={t("sessions.value")}
      editLabel={t("sessions.manage")}
      editAriaLabel={t("sessions.manageAria")}
      editor={({close}) => <SessionsPanel close={close} />}
    />
  );
}

function SessionsPanel({close}: {close: () => void}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const f = useAppFormat();
  const sessions = useSessions();
  const end = useEndSession();
  const recover = useRecoverable();
  const [error, setError] = useState<unknown>(null);
  const [ending, setEnding] = useState<string | null>(null);
  const [logoutOpen, setLogoutOpen] = useState(false);
  // The session just ended, and which End button of the list it was. Its row, with the button that had the focus,
  // leaves the page; the focus goes to the End button that took its place (or the one before it), or to the list
  // when no other session is left, so the keyboard path is not sent back to the top of the document (wp9-r1-5).
  const gone = useRef<{id: string; at: number} | null>(null);
  const list = useRef<HTMLUListElement>(null);
  const data = sessions.data;
  useEffect(() => {
    const target = gone.current;
    // The buttons are all off while a call runs: wait for it to end as well as for the row to leave.
    if (target === null || ending !== null || !data || data.some((row) => row.id === target.id)) return;
    gone.current = null;
    const buttons = list.current?.querySelectorAll<HTMLButtonElement>("button[data-end]") ?? [];
    (buttons[Math.min(target.at, buttons.length - 1)] ?? list.current)?.focus();
  }, [data, ending]);

  async function endOne(id: string) {
    setEnding(id);
    setError(null);
    const at = list.current ? Array.from(list.current.querySelectorAll("button[data-end]")).findIndex((b) => b.closest("li")?.getAttribute("data-session") === id) : 0;
    try {
      await recover(() => end.mutateAsync(id));
      gone.current = {id, at: Math.max(at, 0)};
    } catch (failure) {
      if (!isHandledError(failure)) setError(failure);
    } finally {
      setEnding(null);
    }
  }

  if (sessions.isPending) {
    return (
      <div role="status" aria-busy="true" className="flex flex-col gap-3">
        <span className="sr-only">{c("loading")}</span>
        {[0, 1].map((index) => (
          <Skeleton key={index} aria-hidden className="h-14 w-full rounded-(--radius-box)" />
        ))}
      </div>
    );
  }
  if (sessions.isError) return <SectionError error={sessions.error} onRetry={() => void sessions.refetch()} />;

  const rows = sessions.data;
  const others = rows.filter((row) => !row.current).length;

  return (
    <div className="flex flex-col gap-4">
      <ul ref={list} tabIndex={-1} aria-label={t("sessions.listLabel")} className="divide-separator flex flex-col divide-y outline-none">
        {rows.map((row) => (
          <li key={row.id} data-session={row.id} data-current={row.current || undefined} className="flex flex-wrap items-start gap-x-3 gap-y-2 py-3 first:pt-0">
            <div className="flex min-w-0 flex-1 basis-56 flex-col gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">{t(`sessions.method.${row.auth_method}`)}</span>
                {row.current ? (
                  <Chip size="sm" color="accent" variant="soft">
                    {t("sessions.current")}
                  </Chip>
                ) : null}
              </div>
              <p className="text-muted text-xs">
                {t("sessions.created", {date: f.dateTime(row.created_at)})}
                {" · "}
                {t("sessions.lastSeen", {date: f.relative(row.last_seen_at)})}
              </p>
              <p className="text-muted text-xs">
                <Tech>{row.ip}</Tech>
              </p>
              <p className="text-muted text-xs break-all">
                <Tech mono={false}>{trimAgent(row.user_agent)}</Tech>
              </p>
            </div>
            {row.current ? null : (
              <Button
                size="sm"
                variant="tertiary"
                isPending={ending === row.id}
                // The button that was pressed stays focusable (isPending), so a failed call leaves the focus where it was;
                // the others are off while the call runs (wp9-r3-2).
                isDisabled={ending !== null && ending !== row.id}
                data-end=""
                aria-label={t("sessions.endAria", {when: f.dateTime(row.created_at)})}
                onPress={() => void endOne(row.id)}
              >
                {t("sessions.end")}
              </Button>
            )}
          </li>
        ))}
      </ul>
      {error ? <FormError error={error} /> : null}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button size="sm" variant="tertiary" onPress={close}>
          {c("close")}
        </Button>
        <Button size="sm" variant="danger-soft" onPress={() => setLogoutOpen(true)}>
          {others > 0 ? t("sessions.logoutAll") : t("sessions.logoutAllOnly")}
        </Button>
      </div>
      {logoutOpen ? <LogoutAllDialog onClose={() => setLogoutOpen(false)} /> : null}
    </div>
  );
}

function LogoutAllDialog({onClose}: {onClose: () => void}) {
  const t = useTranslations("account");
  const c = useTranslations("common");
  const locale = useLocale();
  const logoutAll = useLogoutAll(locale);
  const [error, setError] = useState<unknown>(null);

  async function confirm() {
    setError(null);
    try {
      // The server has ended this session too and `logoutLocal` has left the page: nothing else is called.
      await logoutAll.mutateAsync();
    } catch (failure) {
      setError(failure);
    }
  }

  return (
    <AlertDialog.Backdrop isOpen onOpenChange={(open) => !open && !logoutAll.isPending && onClose()}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:max-w-[400px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status="warning">
              <Icon name="logout" className="size-5" />
            </AlertDialog.Icon>
            <AlertDialog.Heading>{t("sessions.logoutAllTitle")}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>
            <div className="flex flex-col gap-3">
              <p>{t("sessions.logoutAllText")}</p>
              <FormError error={error} onRetry={hasCode(error, "logout_all_incomplete") ? undefined : () => void confirm()} />
            </div>
          </AlertDialog.Body>
          <AlertDialog.Footer>
            <Button slot="close" variant="tertiary" isDisabled={logoutAll.isPending}>
              {c("cancel")}
            </Button>
            <Button variant="danger" isPending={logoutAll.isPending} onPress={() => void confirm()}>
              {t("sessions.logoutAllConfirm")}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
