"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Button, Chip, Description, Label, ListBox, ListLayout, Virtualizer} from "@heroui/react";
import {DataGrid, type DataGridColumn} from "@heroui-pro/react";
import {useTranslations} from "next-intl";
import {useSearchParams} from "next/navigation";
import {useMemo, useState} from "react";

import {PageHeader} from "../shell/PageHeader.tsx";
import {bigActivity, type ActivityDecision, type BigRow} from "./fixtures.ts";
import {Tech} from "./LabTech.tsx";
import {SectionTitle} from "./SectionTitle.tsx";
import {TokenStrip} from "./TokenStrip.tsx";

// Spec 8.10 (T-487): P1 proves both with 5,000 fixture rows, in fa. The theme lab that the spec first
// named is gone (D17), and this page took over. The two
// ways to virtualise a long list are shown side by side: ListBox inside a Virtualizer with a
// ListLayout, and DataGrid with `virtualized`, which needs both heights. Budget: the DOM holds
// under 100 rows, and a 2,000px scroll settles within 100ms of its last wheel event, measured by
// the test in apps/panel/e2e/lab.spec.ts.
//
// What the proof found (spec 8.10): the ListBox is up in about 2.6s at 5,000 rows, server render
// included. The virtualised DataGrid of HeroUI Pro 1.0.0-beta.14 is not, when it is part of the
// server-rendered page: the time to its first cells grows with the square of the row count, about
// 3s at 500 rows, 5s at 1,000, 13s at 2,000 and close to a minute at 5,000, with the tab frozen.
// Built in the browser after a button press, the same 5,000 rows take about 1s, and scrolling
// is smooth either way. So the grid renders only when asked, which keeps it out of the server
// render. A real screen should load rows by page (the API is cursor-based anyway) and keep a
// grid to a few hundred rows, or mount it on the client only.
//
// `?rows=N` (100 to 20,000) changes the count, to measure how each one scales.

const DEFAULT_ROWS = 5000;
const LIST_ROW = 56;
const GRID_ROW = 48;
const GRID_HEADING = 40;

const DECISION_COLOR = {blocked: "danger", allowed: "success", redirected: "accent"} as const satisfies Record<
  ActivityDecision,
  string
>;

export function VirtualLab() {
  const t = useTranslations("lab.virtual");
  const a = useTranslations("lab.activity");
  const fmt = useAppFormat();
  const params = useSearchParams();
  const count = Math.min(20_000, Math.max(100, Number(params.get("rows")) || DEFAULT_ROWS));
  const rows = useMemo(() => bigActivity(count), [count]);
  const [showGrid, setShowGrid] = useState(false);

  const columns = useMemo<DataGridColumn<BigRow>[]>(
    () => [
      {id: "time", header: a("time"), cell: (r) => <span className="text-muted">{fmt.time(r.at)}</span>, width: 96, minWidth: 96},
      {id: "domain", isRowHeader: true, header: a("domain"), cell: (r) => <Tech className="text-sm">{r.domain}</Tech>, minWidth: 200},
      {
        id: "decision",
        header: a("action"),
        cell: (r) => (
          <Chip size="sm" color={DECISION_COLOR[r.decision]} variant="soft">
            <Chip.Label>{a(r.decision)}</Chip.Label>
          </Chip>
        ),
        width: 110,
        minWidth: 110,
      },
      {id: "client", header: a("client"), cell: (r) => <Tech className="text-sm text-muted">{r.client}</Tech>, minWidth: 130},
    ],
    [a, fmt],
  );

  return (
    <>
      <PageHeader icon="activityLog" title={t("title")} subtitle={t("subtitle")} />
      <div className="@container flex flex-col gap-8">
        <section aria-labelledby="virtual-list" className="flex flex-col gap-3">
          <SectionTitle id="virtual-list" title={t("listTitle")}>
            <span className="text-sm text-muted">{t("count", {count})}</span>
          </SectionTitle>
          <div className="overflow-clip rounded-(--radius-box) bg-surface shadow-surface">
            <Virtualizer layout={ListLayout} layoutOptions={{rowHeight: LIST_ROW, padding: 8}}>
              <ListBox aria-label={t("listLabel")} className="h-[420px] overflow-y-auto" items={rows} selectionMode="none">
                {(r) => (
                  <ListBox.Item id={r.id} textValue={r.domain}>
                    <div className="flex min-w-0 flex-1 flex-col">
                      <Label>
                        <Tech>{r.domain}</Tech>
                      </Label>
                      <Description>
                        {a(r.decision)} · <Tech>{r.client}</Tech>
                      </Description>
                    </div>
                  </ListBox.Item>
                )}
              </ListBox>
            </Virtualizer>
          </div>
        </section>

        <section aria-labelledby="virtual-grid" className="flex flex-col gap-3">
          <SectionTitle id="virtual-grid" title={t("gridTitle")}>
            <span className="text-sm text-muted">{t("count", {count})}</span>
          </SectionTitle>
          {showGrid ? (
            <DataGrid
              virtualized
              aria-label={t("gridLabel")}
              columns={columns}
              data={rows}
              getRowId={(r) => r.id}
              contentClassName="h-[420px] min-w-[34rem] overflow-auto"
              rowHeight={GRID_ROW}
              headingHeight={GRID_HEADING}
            />
          ) : (
            <div className="flex flex-wrap items-center gap-3 rounded-(--radius-box) bg-surface p-4 shadow-surface">
              <p className="min-w-0 flex-1 text-sm text-muted">{t("gridWarning")}</p>
              <Button variant="secondary" onPress={() => setShowGrid(true)}>
                {t("gridShow")}
              </Button>
            </div>
          )}
        </section>
        <TokenStrip />
      </div>
    </>
  );
}
