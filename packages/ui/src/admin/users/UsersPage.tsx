"use client";

import {useUsers, type AdminUserRow} from "@ctrlz/api-client/admin/hooks/users.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Chip} from "@heroui/react";
import type {DataGridColumn} from "@heroui-pro/react";
import {Tech} from "../../data/Tech.tsx";
import {useUrlDialog} from "../../dialog/useUrlDialog.ts";
import {stripInvisible} from "../../forms/invisible.ts";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useMemo, useState} from "react";

import {gridState, PagedGrid} from "../shared/PagedGrid.tsx";
import {CreateUserDialog} from "./CreateUserDialog.tsx";
import {isPhonePrefix} from "./phonePrefix.ts";

// Spec 13.1, T-327. Users, newest first, found by a phone prefix. No log data (D19): the list says who exists, when they
// came and whether a one-time password is still waiting, and nothing about what they do. Create is the `+` of the header,
// bound to `?dialog=createUser`; the one-time password of the new user is state-only and never in the address.

const SEARCH_DELAY_MS = 300;
/** The API's bound for the prefix (`maxLength: 32`). */
const MAX_PREFIX = 32;

const STATUS_COLOR = {active: "success", suspended: "danger"} as const;

export function UsersPage() {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const dialog = useUrlDialog("dialog");
  const [typed, setTyped] = useState("");
  const [query, setQuery] = useState("");

  // A request per key press would be a request per letter of a number; the field waits for a pause.
  useEffect(() => {
    const timer = setTimeout(() => setQuery(typed), SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [typed]);

  // Text that cannot start a mobile number is not sent (the API would answer 400). If it is sent anyway, because this copy
  // of the rule drifted from the server one, that 400 is the same answer: "not a number", not a failure to retry (wp10-r2-1).
  const sendable = isPhonePrefix(query);
  const users = useUsers(query, sendable);
  const notNumber = query !== "" && (!sendable || hasCode(users.error, "validation_failed"));
  const grid = notNumber ? {...gridState(users), rows: [], isPending: false, error: null, hasNextPage: false, isNextPageError: false} : gridState(users);

  const columns = useMemo<DataGridColumn<AdminUserRow>[]>(
    () => [
      {id: "phone", isRowHeader: true, header: t("users.columns.phone"), minWidth: 170, cell: (u) => <Tech className="text-sm">{u.phone_e164}</Tech>},
      {
        id: "status",
        header: t("users.columns.status"),
        minWidth: 190,
        cell: (u) => (
          <span className="flex flex-wrap items-center gap-1.5">
            <Chip size="sm" variant="soft" color={(STATUS_COLOR as Record<string, "success" | "danger">)[u.tenant_status] ?? "default"}>
              <Chip.Label>{t.has(`users.status.${u.tenant_status}` as never) ? t(`users.status.${u.tenant_status}` as never) : u.tenant_status}</Chip.Label>
            </Chip>
            {u.one_time_password_expires_at ? (
              <Chip size="sm" variant="soft" color="warning">
                <Chip.Label>{t("users.oneTime")}</Chip.Label>
              </Chip>
            ) : null}
          </span>
        ),
      },
      {id: "created", header: t("users.columns.created"), minWidth: 160, cell: (u) => <span className="text-muted text-sm">{format.dateTime(u.created_at)}</span>},
      {
        id: "lastLogin",
        header: t("users.columns.lastLogin"),
        minWidth: 160,
        cell: (u) => <span className="text-muted text-sm">{u.last_login_at ? format.dateTime(u.last_login_at) : t("users.never")}</span>,
      },
    ],
    [t, format],
  );

  return (
    <>
      <PageHeader
        icon="users"
        title={t("pages.users.title")}
        subtitle={t("pages.users.subtitle")}
        onSearch={(value) => setTyped(stripInvisible(value).slice(0, MAX_PREFIX))}
        onCreate={() => dialog.open("createUser")}
        createLabel={t("users.create.open")}
      />
      <PagedGrid
        {...grid}
        label={t("users.gridLabel")}
        columns={columns}
        getRowId={(u) => `${u.tenant_id}:${u.user_id}`}
        empty={
          query === ""
            ? {icon: "users", title: t("users.empty.title"), description: t("users.empty.text")}
            : {icon: "search", title: t("users.empty.searchTitle"), description: t(notNumber ? "users.empty.notNumberText" : "users.empty.searchText")}
        }
      />
      <CreateUserDialog dialog={dialog} />
    </>
  );
}
