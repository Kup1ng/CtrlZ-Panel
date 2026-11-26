"use client";

import {useAddressesGivenUp, type AddressGivenUp} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {buttonVariants, Skeleton} from "@heroui/react";
import {DataGrid, type DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useMemo} from "react";

import {Tech} from "../../data/Tech.tsx";
import {SectionEmpty} from "../../feedback/SectionEmpty.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {keepRetry} from "../shared/restoreFocus.ts";
import {isSafeNow} from "./nodeParts.ts";

// T-546. What happens to an address after a node gives it up is outside the panel (the provider, the parent zone's NS and glue), so
// this is a warning and a date, never a column, a trigger or a countdown of the product: the list says when giving it back is safe,
// the fixed note says what the panel does not see, and the runbook has the steps. Free DNS users get no notice either (T-556).

export function GivenUpSection() {
  const t = useTranslations("nodes");
  const given = useAddressesGivenUp();
  return (
    <section aria-labelledby="given-up" className="flex flex-col gap-3" data-testid="given-up">
      <div className="flex max-w-3xl flex-col gap-1">
        <h2 id="given-up" className="text-base font-medium">
          {t("givenUp.title")}
        </h2>
        <p className="text-muted text-sm">{t("givenUp.text")}</p>
        <p className="text-muted text-sm" data-testid="given-up-free-warning">
          {t("givenUp.freeWarning")}
        </p>
      </div>
      {given.isPending ? (
        <div role="status" aria-busy="true">
          <Skeleton className="h-24 w-full rounded-(--radius-box)" />
        </div>
      ) : !given.data ? (
        <SectionError error={given.error} onRetry={keepRetry(() => given.refetch())} />
      ) : (
        <>
          <RefreshFailed error={given.error} onRetry={() => given.refetch()} />
          <GivenUpList rows={given.data} />
        </>
      )}
      <div role="note" className="bg-surface-secondary flex max-w-3xl flex-col items-start gap-3 rounded-(--radius-box) p-4 text-sm" data-testid="given-up-note">
        <div className="flex items-start gap-3">
          <Icon name="info" className="mt-0.5 size-4 shrink-0" />
          <span>{t("givenUp.fixedNote")}</span>
        </div>
        <Link href="/runbook" className={buttonVariants({variant: "secondary", size: "sm"})}>
          <Icon name="runbook" className="size-4" />
          {t("givenUp.runbook")}
        </Link>
      </div>
    </section>
  );
}

function GivenUpList({rows}: {rows: AddressGivenUp[]}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();

  const columns = useMemo<DataGridColumn<AddressGivenUp>[]>(
    () => [
      {id: "address", isRowHeader: true, header: t("givenUp.columns.address"), minWidth: 150, cell: (r) => <Tech className="text-sm">{r.address}</Tech>},
      {id: "kind", header: t("givenUp.columns.kind"), minWidth: 90, cell: (r) => <span className="text-sm">{t(`givenUp.kind.${r.kind}`)}</span>},
      {id: "node", header: t("givenUp.columns.node"), minWidth: 140, cell: (r) => <span className="text-sm">{r.node_name ?? t("givenUp.removedNode")}</span>},
      {
        id: "gaveUp",
        header: t("givenUp.columns.gaveUp"),
        minWidth: 160,
        cell: (r) => (
          <time dateTime={r.given_up_at} className="text-muted text-sm">
            {format.date(r.given_up_at)}
          </time>
        ),
      },
      {
        id: "safeFrom",
        header: t("givenUp.columns.safeFrom"),
        minWidth: 200,
        cell: (r) => (
          <div className="flex flex-col">
            <time dateTime={r.safe_from} className="text-sm font-medium">
              {format.date(r.safe_from)}
            </time>
            <span className="text-muted text-xs">{isSafeNow(r.safe_from) ? t("givenUp.safeNow") : t("givenUp.safeIn", {when: format.relative(r.safe_from)})}</span>
          </div>
        ),
      },
    ],
    [t, format],
  );

  if (rows.length === 0) {
    return (
      <div className="bg-surface rounded-(--radius-box) shadow-surface" data-testid="grid-empty">
        <SectionEmpty icon="check" title={t("givenUp.empty.title")} description={t("givenUp.empty.text")} size="md" className="py-8" />
      </div>
    );
  }
  return (
    <>
      <DataGrid
        aria-label={t("givenUp.gridLabel")}
        columns={columns}
        data={rows}
        getRowId={(r) => `${r.kind}|${r.address}|${r.given_up_at}`}
        contentClassName="min-w-[40rem]"
        scrollContainerClassName="max-h-[24rem] overflow-auto"
      />
      <p className="text-muted text-xs">{t("givenUp.wait")}</p>
    </>
  );
}
