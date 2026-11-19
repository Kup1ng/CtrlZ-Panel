import localFont from "next/font/local";

// Dana is a variable font with two axes: `wght` 10 to 990 and `KASH` (kashida)
// 0 to 100 (read from the file, docs/licences/dana.md). The weight range is
// declared so the browser maps CSS font-weight onto the axis instead of
// synthesising bold from a single instance.
//
// The file loads from our own origin: next/font copies it into .next/static and
// preloads it, so no request leaves (spec 7.1).
export const dana = localFont({
  src: "../../fonts/DanaVF.woff2",
  variable: "--font-dana",
  display: "swap",
  weight: "10 990",
  style: "normal",
});
