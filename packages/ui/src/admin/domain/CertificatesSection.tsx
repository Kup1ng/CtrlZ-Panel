"use client";

import {useCertificates, useRetireCertificate, type CertificateView} from "@ctrlz/api-client/admin/hooks/domain.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Chip, toast} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo, useRef, useState} from "react";

import {Tech} from "../../data/Tech.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {ActionDialog} from "../nodes/ActionDialog.tsx";
import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {restoreFocusLater} from "../shared/restoreFocus.ts";
import {CertUploadDialog} from "./CertUploadDialog.tsx";
import {canRetire, daysLeft, EXPIRY_WARN_DAYS} from "./domainParts.ts";

// T-344, p4-nodes 4.3. The certificates the panel holds: the ones an admin uploaded (the wildcard of the zone, the panel host, the admin
// host) and the private CAs' own rows beside them, which can be read and not changed. An uploaded active one can be retired; the choice
// rule then picks another active certificate that covers the host, or the private CA when none does, at the next apply on the server.
// Upload opens a state-only dialog, because it holds a private key.

const STATE_LOOK: Record<CertificateView["state"], {color: "default" | "accent" | "success" | "warning" | "danger"; icon: "check" | "info" | "close" | "warning"}> = {
  active: {color: "success", icon: "check"},
  pending: {color: "default", icon: "info"},
  retired: {color: "default", icon: "close"},
  revoked: {color: "danger", icon: "warning"},
};

export function CertificatesSection() {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const list = useCertificates();
  const grid = gridState(list);
  const [uploading, setUploading] = useState(false);
  const [retiring, setRetiring] = useState<CertificateView | null>(null);
  const retire = useRetireCertificate();
  const opener = useRef<HTMLElement | null>(null);
  // Kept while the dialog closes, so its text does not empty during the fade.
  const [last, setLast] = useState<CertificateView | null>(null);
  if (retiring && retiring !== last) setLast(retiring);
  const shown = retiring ?? last;

  const columns = useMemo<DataGridColumn<CertificateView>[]>(
    () => [
      {
        id: "kind",
        isRowHeader: true,
        header: t("domain.certs.columns.kind"),
        minWidth: 170,
        cell: (c) => (
          <div className="flex flex-col gap-0.5">
            <span className="text-sm font-medium">{t(`domain.certs.kinds.${c.kind}`)}</span>
            <span className="text-muted text-xs">{t(`domain.certs.source.${c.source}`)}</span>
          </div>
        ),
      },
      {
        id: "state",
        header: t("domain.certs.columns.state"),
        minWidth: 150,
        cell: (c) => {
          const look = STATE_LOOK[c.state];
          return (
            <Chip size="sm" variant="soft" color={look.color} data-cert-state={c.state}>
              <Icon name={look.icon} className="size-3.5" />
              <Chip.Label>{t(`domain.certs.state.${c.state}`)}</Chip.Label>
            </Chip>
          );
        },
      },
      {
        id: "names",
        header: t("domain.certs.columns.names"),
        minWidth: 220,
        cell: (c) => (
          <ul className="flex flex-col gap-0.5">
            {c.names.map((name) => (
              <li key={name}>
                <Tech className="text-sm [overflow-wrap:anywhere]">{name}</Tech>
              </li>
            ))}
          </ul>
        ),
      },
      {
        id: "until",
        header: t("domain.certs.columns.until"),
        minWidth: 170,
        cell: (c) => {
          const left = daysLeft(c.not_after);
          const soon = c.state === "active" && left <= EXPIRY_WARN_DAYS;
          return (
            <div className="flex flex-col gap-0.5">
              <time dateTime={c.not_after} className="text-sm">
                {format.date(c.not_after)}
              </time>
              {soon ? (
                <span className="flex items-center gap-1 text-xs" data-testid={`cert-expiring-${c.id}`}>
                  <Icon name="warning" className="size-3.5" />
                  {left < 0 ? t("domain.certs.expired") : t("domain.certs.expiresIn", {days: format.number(left)})}
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        id: "actions",
        header: <span className="sr-only">{t("domain.certs.columns.actions")}</span>,
        minWidth: 130,
        align: "end",
        cell: (c) =>
          canRetire(c) ? (
            <Button
              size="sm"
              variant="tertiary"
              aria-label={t("domain.certs.retireRow", {kind: t(`domain.certs.kinds.${c.kind}`), names: c.names.join(", ")})}
              onPress={() => setRetiring(c)}
              data-testid={`cert-retire-${c.id}`}
            >
              <Icon name="trash" className="size-4" />
              {t("domain.certs.retire")}
            </Button>
          ) : null,
      },
    ],
    [t, format],
  );

  return (
    <section aria-labelledby="certs-title" className="flex flex-col gap-3" data-testid="certificates">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 id="certs-title" className="text-base font-medium">
            {t("domain.certs.title")}
          </h2>
          <p className="text-muted max-w-2xl text-sm">{t("domain.certs.text")}</p>
        </div>
        <PrimaryButton
          onPress={() => {
            opener.current = document.activeElement as HTMLElement | null;
            setUploading(true);
          }}
          data-testid="cert-upload-open"
        >
          <Icon name="plus" className="size-4" />
          {t("domain.certs.upload.open")}
        </PrimaryButton>
      </div>
      <PagedGrid
        {...grid}
        label={t("domain.certs.gridLabel")}
        columns={columns}
        getRowId={(c) => c.id}
        minWidth="min-w-[48rem]"
        empty={{icon: "shield", title: t("domain.certs.empty.title"), description: t("domain.certs.empty.text")}}
      />
      <CertUploadDialog
        open={uploading}
        onClose={() => {
          setUploading(false);
          restoreFocusLater(() => opener.current);
        }}
      />
      <ActionDialog
        open={retiring !== null}
        onClose={() => setRetiring(null)}
        status="danger"
        icon={<Icon name="trash" className="size-5" />}
        title={t("domain.certs.retireTitle", {kind: shown ? t(`domain.certs.kinds.${shown.kind}`) : ""})}
        confirmLabel={t("domain.certs.retireConfirm")}
        run={() => retire.mutateAsync(retiring!.id)}
        onDone={() => toast.success(t("domain.certs.retired"))}
        testId="cert-retire-confirm"
      >
        <p className="text-sm">{t("domain.certs.retireText")}</p>
        {shown ? (
          <p className="text-muted text-xs">
            <Tech>{shown.names.join(", ")}</Tech>
          </p>
        ) : null}
      </ActionDialog>
    </section>
  );
}
