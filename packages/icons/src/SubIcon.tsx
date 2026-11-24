import type {SVGProps} from "react";
import {registry} from "./generated/registry.ts";
import type {IconComponent, IconGroup, IconName} from "./generated/registry.ts";

export type SubIconProps<G extends IconGroup> = Omit<SVGProps<SVGSVGElement>, "ref" | "name"> & {
  group: G;
  name: IconName<G>;
  /** Gives the icon an accessible name. Without it the icon is decorative. */
  label?: string;
};

/** True when the group has an icon for this slug. Use it on a slug that came from the API. */
export function hasSubIcon(group: IconGroup, name: string): boolean {
  return Object.hasOwn(registry[group], name);
}

/**
 * One of our own icons, by group and slug: `<SubIcon group="filters" name="malware" />`.
 * Renders nothing for a slug that has no icon, so a catalogue entry added later
 * shows up without one instead of breaking the page.
 */
export function SubIcon<G extends IconGroup>({group, name, label, ...rest}: SubIconProps<G>) {
  const map: Record<string, IconComponent | undefined> = registry[group];
  const Component = map[name as string];
  if (!Component) return null;
  return <Component aria-label={label} {...rest} />;
}
