"use client";

import {Button, ToggleButton, ToggleButtonGroup} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import {useId, type ReactNode} from "react";

import {controlNote, effectiveAction, isChoiceDisabled, offeredChoices, type Action} from "./threeState.ts";

// Spec p2 9.4 and 9.9, WF "Services" and "Rules". The control of a service card, a rule row, a Folder Rule and the Default Rule: Block,
// Bypass, Redirect, and Inherit where a rule may follow its folder.
//
// It is a LABELLED GROUP of toggle buttons (one is always pressed), and every name has its subject in it ("Block for Telegram"), so
// a screen reader that lists the controls of a page of 40 cards can tell them apart (9.9). What the state means is in WORDS and an
// icon beside it, never in colour alone:
//
//   - a service that is never proxied (`redirect_allowed` false, D42, T-521) has no Redirect button, and a line says why;
//   - a Redirect that acts as Bypass (`iranian_bypass`, or a destination that left the set) says so, and the effective action is on
//     the Redirect button's own accessible name;
//   - with no shared destination (T-166) Redirect is shown, disabled, with its reason.
//
// The third button holds the flag and place of the destination, and a second press of it, or the small destination button beside it,
// opens Destinations (WF: "its click opens Destinations"): the caller's `onOpenDestination` opens that dialog.

export type ThreeStateControlProps = {
  value: Action;
  onChange: (value: Action) => void;
  /** The service, folder or domain the control is for. It is in every accessible name. */
  subject: string;
  /** The choices to offer, in order. Default Block, Bypass, Redirect. */
  choices?: readonly Action[];
  /** `redirect_allowed` of the catalogue entry (D42). Default true. */
  redirectAllowed?: boolean;
  /** The location set holds something to redirect to (T-166). Default true. */
  hasDestination?: boolean;
  /** `iranian_bypass` of the row. */
  iranianBypass?: boolean;
  /** `location_unavailable` of the row. */
  locationUnavailable?: boolean;
  /** The flag and name of the destination, shown in the Redirect button when it is the pressed one. */
  destination?: ReactNode;
  /** The words of the destination, for its accessible name: "Germany, Frankfurt". */
  destinationName?: string;
  /** The sentence for "no shared destination" when the screen knows more than the generic one (Choose Service says "for this selection"). */
  noSharedText?: string;
  /** Opens the Destinations dialog. Without it the destination is not clickable. */
  onOpenDestination?: () => void;
  isDisabled?: boolean;
  size?: "sm" | "md";
  className?: string;
};

const DEFAULT_CHOICES: readonly Action[] = ["block", "bypass", "redirect"];

function ActionIcon({action}: {action: Action}) {
  if (action === "inherit") return <Icon name="rules" className="size-4" />;
  return <SubIcon group="rules" name={`action-${action}`} className="size-4" />;
}

export function ThreeStateControl({
  value,
  onChange,
  subject,
  choices = DEFAULT_CHOICES,
  redirectAllowed = true,
  hasDestination = true,
  iranianBypass = false,
  locationUnavailable = false,
  destination,
  destinationName,
  onOpenDestination,
  noSharedText,
  isDisabled = false,
  size = "sm",
  className,
}: ThreeStateControlProps) {
  const t = useTranslations("rules");
  const noteId = useId();
  const state = {value, redirectAllowed, hasDestination, iranianBypass, locationUnavailable};
  const shown = offeredChoices(choices, state);
  const note = controlNote(state);
  const acting = effectiveAction(state);
  const actsDifferently = acting !== value;

  const nameOf = (action: Action) => {
    const base = t("three.set", {action: t(`action.${action}`), subject});
    return action === "redirect" && actsDifferently ? `${base}. ${t("three.actsAs", {action: t(`action.${acting}`)})}` : base;
  };

  return (
    <div className={["flex min-w-0 flex-col gap-1", className ?? ""].filter(Boolean).join(" ")}>
      <div className="flex min-w-0 items-center gap-1">
        <ToggleButtonGroup
          aria-label={t("three.group", {subject})}
          aria-describedby={note ? noteId : undefined}
          selectionMode="single"
          disallowEmptySelection
          size={size}
          // Four choices (Inherit) are wider than a phone dialog: the group scrolls inside its own width and never pushes the page sideways.
          className="max-w-full min-w-0 overflow-x-auto"
          isDisabled={isDisabled}
          selectedKeys={[value]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (typeof next === "string" && next !== value) onChange(next as Action);
          }}
        >
          {shown.map((action, index) => {
            const redirectPressed = action === "redirect" && value === "redirect";
            return (
              <ToggleButton
                key={action}
                id={action}
                aria-label={nameOf(action)}
                isDisabled={isChoiceDisabled(action, state)}
                className="shrink-0 gap-1.5"
              >
                {index > 0 ? <ToggleButtonGroup.Separator /> : null}
                {redirectPressed && destination ? destination : <ActionIcon action={action} />}
                <span className="truncate">{t(`action.${action}`)}</span>
              </ToggleButton>
            );
          })}
        </ToggleButtonGroup>
        {value === "redirect" && onOpenDestination ? (
          <Button
            isIconOnly
            size={size}
            variant="outline"
            isDisabled={isDisabled}
            aria-label={destinationName ? `${t("three.openDestination", {subject})}. ${t("three.destinationNow", {where: destinationName})}` : t("three.openDestination", {subject})}
            onPress={onOpenDestination}
          >
            <Icon name="globe" className="size-4" />
          </Button>
        ) : null}
      </div>
      {note ? (
        <p id={noteId} className="text-muted flex items-start gap-1 text-xs">
          <Icon name={note === "iranianBypass" || note === "unavailable" ? "warning" : "info"} className="mt-0.5 size-3.5 shrink-0" />
          <span>{note === "noShared" && noSharedText ? noSharedText : t(`three.${note}`, {subject, action: t("action.bypass")})}</span>
        </p>
      ) : null}
    </div>
  );
}
