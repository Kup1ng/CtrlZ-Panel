"use client";

import {hasSubIcon, SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import type {IconName} from "@ctrlz/icons/generated/registry.ts";
import type {EndpointType} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useLocale} from "next-intl";
import {useCallback} from "react";

// The mark of an Endpoint's type (spec p3 2.3, open question 6): a generic device drawn by us (`packages/icons/svg/devices`), never a
// vendor's logo. The API sends an icon slug of that set; a slug the set has no drawing for shows the plain device, so a type added by a
// migration later still has a mark.

export function EndpointTypeIcon({icon, className}: {icon: string | undefined; className?: string}) {
  const slug = icon !== undefined && hasSubIcon("devices", icon) ? icon : "device";
  return <SubIcon group="devices" name={slug as IconName<"devices">} className={className ?? "size-6"} />;
}

/** The name of a type in the language in use (the API sends both), or its key for a type the list does not hold. */
export function useTypeName(types: readonly EndpointType[] | undefined): (key: string) => string {
  const locale = useLocale();
  return useCallback(
    (key: string) => {
      const type = types?.find((x) => x.key === key);
      return type ? (locale === "fa" ? type.name_fa : type.name_en) : key;
    },
    [types, locale],
  );
}
