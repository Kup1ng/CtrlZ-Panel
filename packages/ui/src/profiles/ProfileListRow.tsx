"use client";

import {Button, Chip, Dropdown, Label, buttonVariants} from "@heroui/react";
import type {Profile} from "@ctrlz/api-client/hooks/profiles.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Flag} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {ListRow} from "../data/ListRow.tsx";
import {RowCounters, type RowCounter} from "../data/RowCounters.tsx";
import {endpointHref} from "../endpoints/endpointRoutes.ts";
import {profileHref, type ProfileTab} from "./profileRoutes.ts";

// Spec p2 9.1, WF "Profiles" (T-127, T-135, T-136), P3 10 row "Profiles" (T-137). One row of the list:
//
//   [icon + flag] name                          [Filters | Services | Rules | Options]  [status] >
//                 Endpoint line
//
// The icon wears the flag of the Default Rule's destination when it redirects. The icon box is decoration (ListRow hides it from readers), so
// the same fact is also said in words after the name, for screen readers, and the row never relies on the flag alone.
// A click on the row opens Options, and a click on a counter opens that tab (T-135): the counter is its own link above the row's action.
// A profile with no Endpoint offers Add Endpoint and one with some has the menu of them (T-137). Locked and disabled profiles say so with a
// word and an icon, and the profile that was just made carries the word "New" besides the highlight (T-136).

const COUNTER_TABS = ["filters", "services", "rules", "options"] as const satisfies readonly ProfileTab[];

export function ProfileListRow({profile, isNew}: {profile: Profile; isNew: boolean}) {
  const t = useTranslations("profiles");
  const format = useAppFormat();

  const counters: RowCounter[] = COUNTER_TABS.map((tab) => ({
    id: tab,
    label: t(`counters.${tab}`),
    value: profile.counts[tab],
    href: profileHref(profile.id, tab),
    ariaLabel: t("counters.aria", {label: t(`counters.${tab}`), name: profile.name, count: format.number(profile.counts[tab])}),
  }));

  const redirect = profile.default_redirect ? redirectText(profile.default_redirect, t, format.regionName) : null;

  return (
    <ListRow
      isHighlighted={isNew}
      icon={<ProfileIcon redirect={profile.default_redirect} />}
      title={
        <>
          {profile.name}
          {redirect ? <span className="sr-only">{` (${redirect})`}</span> : null}
        </>
      }
      subtitle={<EndpointLine profile={profile} />}
      href={profileHref(profile.id, "options")}
      counters={<RowCounters items={counters} />}
      trailing={
        <span className="flex items-center gap-1.5">
          {isNew ? (
            <Chip size="sm" variant="soft" color="accent">
              <Chip.Label>{t("list.new")}</Chip.Label>
            </Chip>
          ) : null}
          {profile.locked ? (
            <Chip size="sm" variant="soft">
              <Icon name="lock" className="size-3" />
              <Chip.Label>{t("list.locked")}</Chip.Label>
            </Chip>
          ) : null}
          {profile.disabled_until ? (
            <Chip size="sm" variant="soft">
              <Chip.Label>{t("list.disabled")}</Chip.Label>
            </Chip>
          ) : null}
        </span>
      }
    />
  );
}

function redirectText(redirect: NonNullable<Profile["default_redirect"]>, t: ReturnType<typeof useTranslations<"profiles">>, region: (code: string) => string): string {
  if (redirect.kind === "location") {
    const where = redirect.country ? region(redirect.country) : (redirect.label ?? "");
    return where ? t("list.redirect.location", {where}) : t("list.redirect.unknown");
  }
  return t(`list.redirect.${redirect.kind}`);
}

/** The profile's icon, with the Default Rule's destination at the lower inline-end corner when that rule redirects (tile-6 of the radius table). */
function ProfileIcon({redirect}: {redirect: Profile["default_redirect"]}) {
  return (
    <span className="relative inline-grid place-items-center">
      <Icon name="profiles" />
      {redirect ? (
        <span className="tile-6 bg-surface border-border absolute -end-4 -bottom-4 grid size-6 place-items-center overflow-hidden border">
          {redirect.kind === "location" && redirect.country ? <Flag code={redirect.country} className="border-0" /> : <Icon name={redirect.kind === "ip" || redirect.kind === "host" ? "link" : "globe"} className="size-3.5" />}
        </span>
      ) : null}
    </span>
  );
}

/** The line under the name: the Endpoints that use the profile, as a menu, or a way to add one (T-137). */
// The line may wrap (a phone has no room for the words and the button on one line), and sits 6px under the name: the name's link is 20px tall and the next control must not come within 24px of its centre (WCAG target size).
function EndpointLine({profile}: {profile: Profile}) {
  const t = useTranslations("profiles");
  if (profile.endpoints.length === 0) {
    return (
      <span className="mt-1.5 flex flex-wrap items-center gap-x-1.5 whitespace-normal">
        <span>{t("list.noEndpoint")}</span>
        {/* The frame of the profile mounts the Endpoint dialogs and starts the add step on this profile (ProfileFrame, T-137). */}
        <Link
          href={`${profileHref(profile.id, "options")}?deviceDialog=add`}
          aria-label={t("frame.addEndpointAria", {name: profile.name})}
          className={`${buttonVariants({variant: "ghost", size: "sm"})} relative z-10`}
        >
          <Icon name="plus" className="size-3.5" />
          {t("frame.addEndpoint")}
        </Link>
      </span>
    );
  }
  return (
    <span className="mt-1.5 flex">
      <Dropdown>
        <Button size="sm" variant="ghost" className="relative z-10" aria-label={t("list.endpointsAria", {name: profile.name, count: profile.endpoints.length})}>
          <Icon name="endpoints" className="size-3.5" />
          {t("list.endpointCount", {count: profile.endpoints.length})}
          <Icon name="chevron" className="size-3 rotate-90" />
        </Button>
        <Dropdown.Popover placement="bottom start">
          <Dropdown.Menu aria-label={t("frame.endpointsAria", {name: profile.name})}>
            {profile.endpoints.map((e) => (
              <Dropdown.Item key={e.id} id={e.id} textValue={e.name} href={endpointHref(e.id, "clients")}>
                <Label>{e.name}</Label>
              </Dropdown.Item>
            ))}
          </Dropdown.Menu>
        </Dropdown.Popover>
      </Dropdown>
    </span>
  );
}
