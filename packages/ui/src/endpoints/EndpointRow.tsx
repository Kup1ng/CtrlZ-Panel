"use client";

import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, buttonVariants, Checkbox, Chip} from "@heroui/react";
import {useTranslations} from "next-intl";

import {ListRow} from "../data/ListRow.tsx";
import {RowCounters, type RowCounter} from "../data/RowCounters.tsx";
import {profileHref} from "../profiles/profileRoutes.ts";
import {endpointHref} from "./endpointRoutes.ts";
import {EndpointTypeIcon} from "./EndpointTypeIcon.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// WF "Endpoints", spec p3 10 (T-217, T-218, T-232): one row of the list.
//
//   [type mark]  Name                                 Clients  IPs     [statistics] [Edit] [Resolvers | Configure]
//                type, profile link, last query       status chips
//
// The whole row opens the Clients page; the counters, the profile links and the buttons are separate controls above that action. In
// selection mode the row toggles instead, a box stands before it, and the buttons are not drawn. Status is words and a mark, never a
// colour alone: Not Configured, Soft and Hard Disabled, Held and "has a schedule" are chips with text.

export type EndpointRowProps = {
  endpoint: Endpoint;
  typeName: string;
  typeIcon: string | undefined;
  profileName: (id: string) => string;
  selecting: boolean;
  selected: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onResolvers: () => void;
  onConfigure: () => void;
};

export function EndpointRow({endpoint: e, typeName, typeIcon, profileName, selecting, selected, onToggle, onEdit, onResolvers, onConfigure}: EndpointRowProps) {
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const pending = e.status === "pending";

  const counters: RowCounter[] = [
    {id: "clients", label: t("list.row.clients"), value: e.counts.clients, ...(selecting ? {} : {href: endpointHref(e.id, "clients"), ariaLabel: t("list.row.countAria", {label: t("list.row.clients"), name: e.name, count: e.counts.clients})})},
    {id: "ips", label: t("list.row.ips"), value: e.counts.authorized_ips, ...(selecting ? {} : {href: endpointHref(e.id, "ips"), ariaLabel: t("list.row.countAria", {label: t("list.row.ips"), name: e.name, count: e.counts.authorized_ips})})},
  ];

  const subtitle = (
    <>
      <span>{typeName}</span>
      <span aria-hidden="true"> · </span>
      <Link href={profileHref(e.profile_id)} className="relative z-10 inline-block py-1 underline-offset-2 hover:underline">
        {profileName(e.profile_id)}
      </Link>
      {e.profile2_id ? (
        <>
          <span aria-hidden="true">{t("dialogs.delete.separator")}</span>
          <Link href={profileHref(e.profile2_id)} className="relative z-10 inline-block py-1 underline-offset-2 hover:underline">
            {profileName(e.profile2_id)}
          </Link>
        </>
      ) : null}
      <span aria-hidden="true"> · </span>
      <span>{e.last_query_at ? t("lastQuery", {when: format.relative(e.last_query_at)}) : t("noQuery")}</span>
    </>
  );

  const chips = (
    <>
      {pending ? (
        <Chip size="sm" variant="soft" color="warning">
          <Chip.Label>{t("status.pending")}</Chip.Label>
        </Chip>
      ) : null}
      {e.admin_state !== "enabled" ? (
        <Chip size="sm" variant="soft">
          <Chip.Label>{t(`state.${e.admin_state}`)}</Chip.Label>
        </Chip>
      ) : null}
      {e.admin_hold ? (
        <Chip size="sm" variant="soft" color="warning">
          <Chip.Label>{t("list.row.heldChip")}</Chip.Label>
        </Chip>
      ) : null}
      {e.has_schedule ? (
        <Chip size="sm" variant="soft">
          <Icon name="calendar" className="size-3.5" />
          <Chip.Label>{t("list.row.schedule")}</Chip.Label>
        </Chip>
      ) : null}
    </>
  );

  const row = (
    <ListRow
      icon={<EndpointTypeIcon icon={typeIcon} />}
      // A name is the person's own text: it runs in its own direction and is cut at its end, not at its beginning.
      title={
        <span dir="auto" className="block truncate py-0.5" style={{textAlign: "match-parent"}}>
          {e.name}
        </span>
      }
      subtitle={subtitle}
      isHighlighted={selected}
      roomy
      stacked
      leading={
        selecting ? (
          <Checkbox aria-label={t("list.row.selectAria", {name: e.name})} isSelected={selected} onChange={onToggle}>
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
            </Checkbox.Content>
          </Checkbox>
        ) : undefined
      }
      {...(selecting ? {onPress: onToggle} : {href: endpointHref(e.id, "clients")})}
      counters={
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {chips}
          <RowCounters items={counters} />
        </div>
      }
      trailing={
        selecting ? undefined : (
          <div className="flex items-center gap-1">
            {/* The statistics page is a stub (P5): on a phone its place goes to the name. */}
            <span className="hidden sm:contents">
              <Link href="/analytics/statistics" aria-label={t("list.row.statistics", {name: e.name})} className={`${buttonVariants({variant: "ghost", size: "sm", isIconOnly: true})}`}>
                <Icon name="statistics" className="size-4" />
              </Link>
            </span>
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("list.row.editAria", {name: e.name})} onPress={onEdit}>
              <Icon name="edit" className="size-4" />
            </Button>
            {pending ? (
              <PrimaryButton size="sm" aria-label={t("frame.configureAria", {name: e.name})} onPress={onConfigure}>
                {t("frame.configure")}
              </PrimaryButton>
            ) : (
              <Button size="sm" variant="outline" aria-label={t("frame.resolversAria", {name: e.name})} onPress={onResolvers}>
                <Icon name="globe" className="size-4" />
                <span className="hidden sm:inline">{t("frame.resolvers")}</span>
              </Button>
            )}
          </div>
        )
      }
    />
  );

  return row;
}
