"use client";

import {useState} from "react";
import {logoSrc, monogramLetter} from "./monogram.ts";

export type ServiceLogoProps = {
  slug: string;
  name: string;
  className?: string;
};

// The radius comes from the .service-logo row of radius.table.ts (D16: a size-9 tile is a
// control, so 0.4 of its height). The number lives there and nowhere else.
const TILE = "service-logo inline-flex size-9 shrink-0 items-center justify-center overflow-hidden bg-default text-foreground";

/**
 * A service's logo from our own static files, or a monogram tile when there is
 * none or the file fails to load. The tile is neutral on purpose: no colour is
 * derived from the name, since hue is not decoration here (DESIGN.md).
 */
export function ServiceLogo({slug, name, className}: ServiceLogoProps) {
  const [failed, setFailed] = useState(false);
  const src = logoSrc(slug);
  const classes = className ? `${TILE} ${className}` : TILE;
  if (src && !failed) {
    return (
      <span className={classes}>
        {/* The name is next to the logo in every use, so the image is decorative. */}
        <img src={src} alt="" className="size-full object-contain p-1.5" onError={() => setFailed(true)} />
      </span>
    );
  }
  return (
    <span className={`${classes} text-sm font-medium`} aria-hidden="true">
      {monogramLetter(name)}
    </span>
  );
}
