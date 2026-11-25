"use client";

import {AUDIT_ACTION_RE, useAudit, type AuditRow} from "@ctrlz/api-client/admin/hooks/audit.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Description, FieldError, Input, Label, TextField} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {Tech} from "../../data/Tech.tsx";
import {stripInvisible} from "../../forms/invisible.ts";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useMemo, useState} from "react";

import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";

// Spec 13.5, T-352. The admin audit log, newest first, read only, loaded by `next_cursor`, with a filter by an exact
// action name. Dates go through `useAppFormat` (Jalali in Persian). Params are shown as a compact `<Tech>` block of
// `name=value` text: React escapes it, nothing here is ever HTML, and a value is cut at a bound so one long row cannot
// push the grid wide.

const FILTER_DELAY_MS = 400;
const PARAMS_MAX_CHARS = 300;

/** `a=1 b=x,y`: scalars and short lists, as `RowParams` bounds them. */
export function paramsText(params: AuditRow["params"]): string {
  const text = Object.entries(params as Record<string, unknown>)
    .map(([name, value]) => `${name}=${Array.isArray(value) ? value.join(",") : String(value)}`)
    .join(" ");
  return text.length > PARAMS_MAX_CHARS ? `${text.slice(0, PARAMS_MAX_CHARS)}…` : text;
}

export function AuditPage() {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const [typed, setTyped] = useState("");
  const [action, setAction] = useState("");

  // The filter is an exact name. Anything that is not one is not sent (the API would answer 400), and the field says so.
  const trimmed = typed.trim();
  const valid = trimmed === "" || AUDIT_ACTION_RE.test(trimmed);
  useEffect(() => {
    if (!valid) return;
    const timer = setTimeout(() => setAction(trimmed), FILTER_DELAY_MS);
    return () => clearTimeout(timer);
  }, [trimmed, valid]);

  const audit = useAudit(action);
  // While the typed text is not a name, `action` still holds the last valid one, and its rows must not stand for what the box holds: the
  // grid shows the empty state that says why, as Users does for "not a number" (wp10-r7-4).
  const grid = valid ? gridState(audit) : {...gridState(audit), rows: [], isPending: false, error: null, hasNextPage: false, isNextPageError: false};

  const columns = useMemo<DataGridColumn<AuditRow>[]>(
    () => [
      {id: "at", header: t("audit.columns.at"), minWidth: 170, cell: (r) => <span className="text-muted text-sm">{format.dateTime(r.at)}</span>},
      {id: "action", isRowHeader: true, header: t("audit.columns.action"), minWidth: 190, cell: (r) => <Tech className="text-sm">{r.action}</Tech>},
      {id: "target", header: t("audit.columns.target"), minWidth: 150, cell: (r) => (r.target ? <Tech className="text-sm [overflow-wrap:anywhere]">{r.target}</Tech> : <span className="text-muted">—</span>)},
      {
        id: "params",
        header: t("audit.columns.params"),
        minWidth: 280,
        cell: (r) => <Tech className="text-muted block max-w-md text-xs leading-5 [overflow-wrap:anywhere]">{paramsText(r.params) || "—"}</Tech>,
      },
      {id: "ip", header: t("audit.columns.ip"), minWidth: 130, cell: (r) => (r.ip ? <Tech className="text-sm">{r.ip}</Tech> : <span className="text-muted">—</span>)},
    ],
    [t, format],
  );

  return (
    <>
      <PageHeader icon="audit" title={t("pages.audit.title")} subtitle={t("pages.audit.subtitle")} />
      <div className="mb-4 max-w-sm">
        <TextField
          name="action"
          variant="secondary"
          fullWidth
          autoComplete="off"
          isInvalid={!valid}
          value={typed}
          onChange={(value) => setTyped(stripInvisible(value).slice(0, 64))}
        >
          <Label>{t("audit.filter.label")}</Label>
          <Input dir="ltr" className="text-start" spellCheck={false} autoCapitalize="none" />
          <Description>{t("audit.filter.hint")}</Description>
          <FieldError>{t("audit.filter.invalid")}</FieldError>
        </TextField>
      </div>
      <PagedGrid
        {...grid}
        label={t("audit.gridLabel")}
        columns={columns}
        getRowId={(r) => String(r.id)}
        minWidth="min-w-[52rem]"
        empty={
          !valid
            ? {icon: "search", title: t("audit.empty.filterTitle"), description: t("audit.filter.invalid")}
            : action === ""
              ? {icon: "audit", title: t("audit.empty.title"), description: t("audit.empty.text")}
              : {icon: "search", title: t("audit.empty.filterTitle"), description: t("audit.empty.filterText")}
        }
      />
    </>
  );
}
