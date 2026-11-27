"use client";

import type {Client} from "@ctrlz/api-client/hooks/clients.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Checkbox, Chip} from "@heroui/react";
import {useTranslations} from "next-intl";
import {memo} from "react";

import {Tech} from "../../data/Tech.tsx";
import {ListRow} from "../../data/ListRow.tsx";
import {ANALYTICS_KEY, clientName, DEFAULT_LABEL} from "./clientsModel.ts";

// One client of an Endpoint (spec p3 10, T-257): its name (alias, else label), the label and what the hub learned (Hostname, MAC, IP), the
// profile it has of its own, its Analytics level, and when it last asked. The whole row opens its edit; in selection mode it toggles. A name
// is the person's own text and a label, a host, a MAC and an address are Tech: they keep their direction inside a Persian line.

export type ClientRowProps = {
  client: Client;
  /** The name of the client's own profile (or Profile 2), when it has one. */
  profileName: (id: string) => string;
  selecting: boolean;
  selected: boolean;
  onToggle: (id: string) => void;
  onEdit: (client: Client) => void;
  onDelete: (client: Client) => void;
  /** The wrapper sets the height; the row fills it. */
  className?: string;
};

export const ClientRow = memo(function ClientRow({client: c, profileName, selecting, selected, onToggle, onEdit, onDelete, className}: ClientRowProps) {
  const t = useTranslations("endpoints");
  const format = useAppFormat();
  const name = clientName(c);
  const known = [c.hostname, c.ip, c.mac].filter((x): x is string => !!x);

  const subtitle = (
    <>
      {c.alias ? (
        <>
          <Tech>{c.label}</Tech>
          {known.length > 0 ? <span aria-hidden="true"> · </span> : null}
        </>
      ) : null}
      {known.map((value, i) => (
        <span key={value}>
          {i > 0 ? <span aria-hidden="true"> · </span> : null}
          <Tech>{value}</Tech>
        </span>
      ))}
      {!c.alias && known.length === 0 ? <span>{t("clients.row.nothingKnown")}</span> : null}
    </>
  );

  const chips = (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      {c.label === DEFAULT_LABEL ? (
        <Chip size="sm" variant="soft">
          <Chip.Label>{t("clients.row.default")}</Chip.Label>
        </Chip>
      ) : null}
      {c.is_custom ? (
        <Chip size="sm" variant="soft">
          <Chip.Label>{t("clients.row.custom")}</Chip.Label>
        </Chip>
      ) : null}
      {c.profile_id ? (
        <Chip size="sm" variant="soft" color="accent">
          <Chip.Label>{c.profile2_id ? t("clients.row.profiles", {first: profileName(c.profile_id), second: profileName(c.profile2_id)}) : t("clients.row.profile", {name: profileName(c.profile_id)})}</Chip.Label>
        </Chip>
      ) : null}
      {c.analytics_level ? (
        <Chip size="sm" variant="soft">
          <Chip.Label>{t("clients.row.analytics", {level: t(`dialogs.fields.${ANALYTICS_KEY[c.analytics_level]}`)})}</Chip.Label>
        </Chip>
      ) : null}
      <span className="text-muted text-xs">{t("clients.row.lastSeen", {when: format.relative(c.last_seen_at)})}</span>
    </div>
  );

  return (
    <ListRow
      className={className}
      icon={<Icon name="phone" className="size-5" />}
      title={
        <span className="block truncate py-0.5">
          <bdi dir="auto">{name}</bdi>
        </span>
      }
      subtitle={subtitle}
      isHighlighted={selected}
      roomy
      leading={
        selecting ? (
          <Checkbox aria-label={t("clients.row.selectAria", {name})} isSelected={selected} onChange={() => onToggle(c.id)}>
            <Checkbox.Content>
              <Checkbox.Control>
                <Checkbox.Indicator />
              </Checkbox.Control>
            </Checkbox.Content>
          </Checkbox>
        ) : undefined
      }
      onPress={selecting ? () => onToggle(c.id) : () => onEdit(c)}
      counters={chips}
      trailing={
        selecting ? undefined : (
          <div className="flex items-center gap-1">
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("clients.row.editAria", {name})} onPress={() => onEdit(c)}>
              <Icon name="edit" className="size-4" />
            </Button>
            <Button isIconOnly size="sm" variant="ghost" aria-label={t("clients.row.deleteAria", {name})} onPress={() => onDelete(c)}>
              <Icon name="trash" className="size-4" />
            </Button>
          </div>
        )
      }
    />
  );
});
