"use client";

import {useEnrollments, useRejectEnrollment, type NodeEnrollmentRow, type NodeEnrollmentState} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, buttonVariants, Chip, toast} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {pushDialogParams, useUrlDialog, wasPushed} from "../../dialog/useUrlDialog.ts";
import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {stripDialogParam} from "../shared/dialogUrl.ts";
import {gridOf, restoreFocusLater} from "../shared/restoreFocus.ts";
import {ActionDialog} from "./ActionDialog.tsx";
import {ConfirmNodeDialog} from "./ConfirmNodeDialog.tsx";
import {enrollmentOpen} from "./nodeParts.ts";

// T-340. The enrolments, newest first. A host that has called in waits for its fingerprint to be compared; one that has not is still an
// install command that works until its time. Compare and confirm opens `?dialog=confirmNode&enrollmentId=<id>` (one history entry for the
// two parameters, so Back closes it); Reject spends the token. A confirmed enrolment links to its node, which waits for approval.

const STATE_LOOK: Record<NodeEnrollmentState, {color: "default" | "accent" | "success" | "warning" | "danger"; icon: "info" | "warning" | "check" | "close"}> = {
  issued: {color: "default", icon: "info"},
  pending_approval: {color: "accent", icon: "warning"},
  approved: {color: "success", icon: "check"},
  rejected: {color: "default", icon: "close"},
  expired: {color: "default", icon: "close"},
};

export function EnrolList() {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const list = useEnrollments();
  const grid = gridState(list);
  const dialog = useUrlDialog("dialog");
  const idParam = useUrlDialog("enrollmentId");
  const [rejecting, setRejecting] = useState<NodeEnrollmentRow | null>(null);
  const reject = useRejectEnrollment();

  function closeConfirm() {
    const pushed = wasPushed("dialog");
    dialog.close();
    // A tab that arrived on the link has no entry to go back to: both parameters are taken out of the address.
    if (!pushed) stripDialogParam("enrollmentId");
    restoreFocusLater(() => gridOf(t("enrol.list.gridLabel")));
  }

  const columns = useMemo<DataGridColumn<NodeEnrollmentRow>[]>(
    () => [
      {
        id: "host",
        isRowHeader: true,
        header: t("enrol.list.columns.host"),
        minWidth: 170,
        cell: (e) => (
          <div className="flex flex-col gap-0.5">
            <span className="text-sm font-medium">{e.hostname ? <Tech mono={false}>{e.hostname}</Tech> : e.state === "issued" ? t("enrol.list.noHost") : t("enrol.list.unnamed")}</span>
            {e.os_release || e.node_version ? (
              <span className="text-muted text-xs">
                {e.os_release ? <Tech mono={false}>{e.os_release}</Tech> : null} {e.node_version ? <Tech>{e.node_version}</Tech> : null}
              </span>
            ) : null}
          </div>
        ),
      },
      {
        id: "state",
        header: t("enrol.list.columns.state"),
        minWidth: 220,
        cell: (e) => {
          // A command that was never used and has passed its time reads as expired whether or not the server has marked it yet.
          const state: NodeEnrollmentState = e.state === "issued" && !enrollmentOpen(e.state, e.expires_at) ? "expired" : e.state;
          const look = STATE_LOOK[state];
          return (
            <div className="flex flex-col items-start gap-1.5">
              <Chip size="sm" variant="soft" color={look.color} data-enrol-state={state}>
                <Icon name={look.icon} className="size-3.5" />
                <Chip.Label>{t(`enrol.list.state.${state}`)}</Chip.Label>
              </Chip>
              <div className="flex flex-col gap-0.5 text-xs">
                {e.enrolled_at ? <span>{t("enrol.list.called", {when: format.dateTime(e.enrolled_at)})}</span> : null}
                {e.enrolled_from ? <span>{t.rich("enrol.list.from", {ip: e.enrolled_from, tech: (chunks) => <Tech>{chunks}</Tech>})}</span> : null}
                {enrollmentOpen(e.state, e.expires_at) ? <span className="text-muted">{t("enrol.list.expires", {when: format.dateTime(e.expires_at)})}</span> : null}
              </div>
            </div>
          );
        },
      },
      {
        id: "addresses",
        header: t("enrol.list.columns.addresses"),
        minWidth: 170,
        cell: (e) => (
          <div className="flex flex-col gap-0.5 text-xs">
            <span>
              {t("enrol.list.dns")} <Tech>{e.dns_advertised_ip ?? "-"}</Tech>
            </span>
            <span>
              {t("enrol.list.proxy")} <Tech>{e.proxy_advertised_ip ?? "-"}</Tech>
            </span>
          </div>
        ),
      },
      {
        id: "actions",
        header: <span className="sr-only">{t("enrol.list.columns.actions")}</span>,
        minWidth: 190,
        align: "end",
        cell: (e) => {
          const host = e.hostname ?? t("enrol.list.unnamed");
          return (
            <div className="flex flex-col items-end gap-2">
              {e.state === "pending_approval" ? (
                <PrimaryButton size="sm" aria-label={t("enrol.list.compareRow", {host})} onPress={() => pushDialogParams({dialog: "confirmNode", enrollmentId: e.id})} data-testid={`compare-${e.id}`}>
                  <Icon name="check" className="size-4" />
                  {t("enrol.list.compare")}
                </PrimaryButton>
              ) : null}
              {e.state === "pending_approval" || (e.state === "issued" && enrollmentOpen(e.state, e.expires_at)) ? (
                <Button size="sm" variant="danger-soft" aria-label={t("enrol.list.rejectRow", {host})} onPress={() => setRejecting(e)} data-testid={`reject-${e.id}`}>
                  <Icon name="close" className="size-4" />
                  {t("enrol.list.reject")}
                </Button>
              ) : null}
              {e.state === "approved" && e.node_id ? (
                <Link href={`/nodes/${e.node_id}`} aria-label={t("enrol.list.openRow", {host})} className={buttonVariants({variant: "secondary", size: "sm"})}>
                  <Icon name="nodes" className="size-4" />
                  {t("enrol.list.open")}
                </Link>
              ) : null}
            </div>
          );
        },
      },
    ],
    [t, format],
  );

  return (
    <section aria-labelledby="enrol-list" className="flex flex-col gap-3" data-testid="enrol-list">
      <div className="flex max-w-2xl flex-col gap-1">
        <h2 id="enrol-list" className="text-base font-medium">
          {t("enrol.list.title")}
        </h2>
        <p className="text-muted text-sm">{t("enrol.list.text")}</p>
      </div>
      <PagedGrid
        {...grid}
        label={t("enrol.list.gridLabel")}
        columns={columns}
        getRowId={(e) => e.id}
        minWidth="min-w-[44rem]"
        empty={{icon: "nodes", title: t("enrol.list.empty.title"), description: t("enrol.list.empty.text")}}
      />
      <ConfirmNodeDialog dialog={dialog} enrollmentId={idParam.value} onClose={closeConfirm} />
      <ActionDialog
        open={rejecting !== null}
        onClose={() => {
          setRejecting(null);
          restoreFocusLater(() => gridOf(t("enrol.list.gridLabel")));
        }}
        icon={<Icon name="close" className="size-5" />}
        title={t("enrol.reject.title")}
        confirmLabel={t("enrol.reject.confirm")}
        run={() => (rejecting ? reject.mutateAsync(rejecting.id) : Promise.resolve())}
        onDone={() => toast.success(t("enrol.reject.done"))}
        testId="confirm-reject"
      >
        <p>{t("enrol.reject.text")}</p>
      </ActionDialog>
    </section>
  );
}
