import {HugeiconsIcon} from "@hugeicons/react";
import {general} from "./hugeicons.ts";
import type {GeneralIconName} from "./hugeicons.ts";

export type IconProps = {
  name: GeneralIconName;
  /** Gives the icon an accessible name. Without it the icon is decorative and hidden from readers. */
  label?: string;
  /** Mirrors a direction-bearing icon (chevron, arrows) in RTL. Not for asymmetric shapes. */
  flip?: boolean;
  className?: string;
};

/**
 * A general-purpose icon from the allowlist. It is 1em square, so size comes from
 * the parent's font size or from `className="size-4"`. Colour is currentColor.
 */
export function Icon({name, label, flip, className}: IconProps) {
  const classes = [flip ? "rtl:rotate-180" : "", className ?? ""].filter(Boolean).join(" ") || undefined;
  return (
    <HugeiconsIcon
      icon={general[name]}
      size="1em"
      color="currentColor"
      strokeWidth={1.5}
      className={classes}
      focusable="false"
      {...(label ? {role: "img", "aria-label": label} : {"aria-hidden": true})}
    />
  );
}
