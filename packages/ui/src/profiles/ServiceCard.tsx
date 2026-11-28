"use client";

import {Button, Chip, Switch} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {ServiceLogo} from "@ctrlz/icons/ServiceLogo.tsx";
import {useTranslations} from "next-intl";
import {memo} from "react";

import {ItemTile} from "../data/CardGrid.tsx";
import {ThreeStateControl} from "../controls/ThreeStateControl.tsx";
import type {Action} from "../controls/threeState.ts";
import {useTargetName} from "../destinations/DestinationsDialog.tsx";
import {TargetMark} from "./TargetMark.tsx";
import type {ServiceItem} from "./servicesModel.ts";

// The card of one service of the profile (spec p2 9.4, WF "Services", T-162): its logo, name and status in words, remove, the switch, and the
// three-state control whose Redirect shows the flag of the destination and opens Destinations.
//
// A switched-off service keeps its action ("a service that is off is not Bypass", Plan, Services), so the status says Off and not the action.
// A service the catalogue marks deprecated stays usable and removable, with a note. One that is never proxied (D42) has no Redirect button,
// and one that acts as Bypass says so: both are in the control.

export type ServiceCardProps = {
  item: ServiceItem;
  readOnly: boolean;
  /** The profile has a location to redirect to (T-166). */
  hasDestination: boolean;
  // The handlers take the item, so the page can give every card the same four functions: a card then re-renders only when its own row changes.
  onToggle: (item: ServiceItem, enabled: boolean) => void;
  onAction: (item: ServiceItem, action: Action) => void;
  onOpenDestination: (item: ServiceItem) => void;
  onRemove: (item: ServiceItem) => void;
};

function ServiceCardView({item, readOnly, hasDestination, onToggle, onAction, onOpenDestination, onRemove}: ServiceCardProps) {
  const t = useTranslations("services");
  const rules = useTranslations("rules");
  const targetName = useTargetName();
  const {row, service, name} = item;
  const deprecated = service?.state === "deprecated";
  const status = row.enabled ? rules(`action.${row.action}`) : t("card.statusOff");
  const where = row.action === "redirect" ? targetName(row.target) : undefined;

  return (
    <ItemTile
      state={readOnly ? "disabled" : row.enabled ? "on" : "off"}
      icon={<ServiceLogo slug={row.slug} name={name} className="size-full bg-transparent" />}
      toggle={
        <Switch isSelected={row.enabled} isDisabled={readOnly} onChange={(enabled) => onToggle(item, enabled)} aria-label={t("card.switch", {name})} data-service={row.slug}>
          <Switch.Content>
            <Switch.Control>
              <Switch.Thumb />
            </Switch.Control>
          </Switch.Content>
        </Switch>
      }
      title={name}
      status={status}
      footer={
        <>
          <Button isIconOnly size="sm" variant="ghost" isDisabled={readOnly} aria-label={t("card.remove", {name})} onPress={() => onRemove(item)}>
            <Icon name="trash" className="size-4" />
          </Button>
          {deprecated ? (
            <Chip size="sm" variant="soft">
              <Chip.Label>{t("card.deprecated")}</Chip.Label>
            </Chip>
          ) : null}
        </>
      }
    >
      <ThreeStateControl
        value={row.action}
        onChange={(action) => onAction(item, action)}
        subject={name}
        choices={["block", "bypass", "redirect"]}
        redirectAllowed={service?.redirect_allowed ?? true}
        hasDestination={hasDestination}
        iranianBypass={row.iranian_bypass}
        locationUnavailable={row.location_unavailable}
        destination={row.action === "redirect" ? <TargetMark target={row.target} /> : undefined}
        destinationName={where}
        onOpenDestination={() => onOpenDestination(item)}
        isDisabled={readOnly}
      />
      {deprecated ? (
        <p className="text-muted flex items-start gap-1 text-xs">
          <Icon name="info" className="mt-0.5 size-3.5 shrink-0" />
          <span>{t("card.deprecatedNote")}</span>
        </p>
      ) : null}
    </ItemTile>
  );
}

// Every optimistic write replaces the rows of the page and the page rebuilds its items, so `item` is a new object each time while the row, the
// catalogue entry and the name of an untouched card are the same ones. Comparing those keeps a switch press from re-rendering every card drawn (S3-r3-1).
const same = (a: ServiceCardProps, b: ServiceCardProps) =>
  a.item.row === b.item.row &&
  a.item.service === b.item.service &&
  a.item.name === b.item.name &&
  a.readOnly === b.readOnly &&
  a.hasDestination === b.hasDestination &&
  a.onToggle === b.onToggle &&
  a.onAction === b.onAction &&
  a.onOpenDestination === b.onOpenDestination &&
  a.onRemove === b.onRemove;

export const ServiceCard = memo(ServiceCardView, same);
