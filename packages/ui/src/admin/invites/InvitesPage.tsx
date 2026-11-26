"use client";

import {useInvites, useRevokeInvite, type InviteRow} from "@ctrlz/api-client/admin/hooks/invites.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Button, Chip} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Tech} from "../../data/Tech.tsx";
import {ConfirmFrame} from "../../dialog/ConfirmFrame.tsx";
import {useUrlDialog} from "../../dialog/useUrlDialog.ts";
import {useErrorText} from "../../feedback/errorText.ts";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {useTranslations} from "next-intl";
import {useMemo, useState} from "react";

import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {gridOf, restoreFocusLater} from "../shared/restoreFocus.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {CreateInviteDialog} from "./CreateInviteDialog.tsx";

// Spec 13.2, T-327, T-330. The invites, newest first, never with a link (the API does not keep one in a list). Create is
// the `+` of the header (`?dialog=createInvite`); Revoke is an AlertDialog and `DELETE /invites/{id}`. Only a pending
// invite can be revoked: the other states are history.

const STATE_COLOR = {pending: "accent", used: "success", revoked: "default", expired: "default"} as const;

export function InvitesPage() {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const dialog = useUrlDialog("dialog");
  const invites = useInvites();
  const grid = gridState(invites);
  const [revoking, setRevoking] = useState<InviteRow | null>(null);

  const columns = useMemo<DataGridColumn<InviteRow>[]>(
    () => [
      {id: "phone", isRowHeader: true, header: t("invites.columns.phone"), minWidth: 170, cell: (i) => <Tech className="text-sm">{i.phone_e164}</Tech>},
      {
        id: "state",
        header: t("invites.columns.state"),
        minWidth: 120,
        cell: (i) => (
          <Chip size="sm" variant="soft" color={STATE_COLOR[i.state]}>
            <Chip.Label>{t(`invites.state.${i.state}`)}</Chip.Label>
          </Chip>
        ),
      },
      {id: "locale", header: t("invites.columns.locale"), minWidth: 90, cell: (i) => <Tech className="text-sm">{i.locale}</Tech>},
      {id: "expires", header: t("invites.columns.expires"), minWidth: 160, cell: (i) => <span className="text-muted text-sm">{format.dateTime(i.expires_at)}</span>},
      {id: "created", header: t("invites.columns.created"), minWidth: 160, cell: (i) => <span className="text-muted text-sm">{format.dateTime(i.created_at)}</span>},
      {
        id: "actions",
        header: <span className="sr-only">{t("invites.columns.actions")}</span>,
        width: 110,
        minWidth: 110,
        align: "end",
        cell: (i) =>
          i.state === "pending" ? (
            <Button size="sm" variant="danger-soft" aria-label={t("invites.revoke.row", {phone: i.phone_e164})} onPress={() => setRevoking(i)}>
              <Icon name="trash" className="size-4" />
              {t("invites.revoke.action")}
            </Button>
          ) : null,
      },
    ],
    [t, format],
  );

  return (
    <>
      <PageHeader
        icon="invite"
        title={t("pages.invites.title")}
        subtitle={t("pages.invites.subtitle")}
        onCreate={() => dialog.open("createInvite")}
        createLabel={t("invites.create.open")}
      />
      <PagedGrid
        {...grid}
        label={t("invites.gridLabel")}
        columns={columns}
        getRowId={(i) => i.id}
        minWidth="min-w-[46rem]"
        empty={{icon: "invite", title: t("invites.empty.title"), description: t("invites.empty.text")}}
      />
      <CreateInviteDialog dialog={dialog} />
      <RevokeDialog invite={revoking} onClose={() => setRevoking(null)} />
    </>
  );
}

function RevokeDialog({invite, onClose}: {invite: InviteRow | null; onClose: () => void}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  const errorText = useErrorText();
  const revoke = useRevokeInvite();
  // The revoke needs the fresh TOTP window: the dialog opens and the call is repeated once (admin-fresh, gate-r32-3).
  const {send} = useCheckedWrite();
  const [error, setError] = useState<unknown>(null);

  function close() {
    setError(null);
    revoke.reset();
    onClose();
    // The Revoke button this dialog came from leaves with the pending state, so React Aria has nothing to give the focus back to (wp10-r7-1).
    restoreFocusLater(() => gridOf(t("invites.gridLabel")));
  }

  return (
    <ConfirmFrame
      isOpen={invite !== null}
      onOpenChange={(open) => !open && close()}
      status="danger"
      icon={<Icon name="trash" className="size-5" />}
      title={t("invites.revoke.title")}
      footer={
        <>
          <Button slot="close" variant="tertiary">
            {c("cancel")}
          </Button>
          <Button
            variant="danger"
            isPending={revoke.isPending}
            onPress={async () => {
              if (!invite) return;
              setError(null);
              try {
                await send(() => revoke.mutateAsync(invite.id));
                close();
              } catch (failure) {
                // A revoked or used invite answers not_found or conflict: the list is asked again either way, so the row is right.
                setError(failure);
              }
            }}
          >
            {t("invites.revoke.confirm")}
          </Button>
        </>
      }
    >
      <p>{t.rich("invites.revoke.text", {phone: invite?.phone_e164 ?? "", tech: (chunks) => <Tech>{chunks}</Tech>})}</p>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-(--danger-text)">
          {errorText(error)}
        </p>
      ) : null}
    </ConfirmFrame>
  );
}
