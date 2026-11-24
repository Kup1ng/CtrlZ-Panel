import {themeNames} from "./html.ts";

// A fixed string with no imports, built from constants at module load. It runs
// before <body> is parsed and only when the server rendered no theme class (mode
// `system`, or no cookie yet). It adds classes and never replaces className, so
// the Dana font class survives (spec 5.1).
const light = themeNames("light");
const dark = themeNames("dark");

const SCRIPT = `(function(){var d=document.documentElement;if(d.classList.contains("light")||d.classList.contains("dark"))return;var n=matchMedia("(prefers-color-scheme: dark)").matches?${JSON.stringify(dark)}:${JSON.stringify(light)};d.classList.add.apply(d.classList,n.classes);d.setAttribute("data-theme",n.dataTheme)})()`;

/**
 * Server Component. `nonce` comes from the request's CSP header (spec 15), so the
 * script needs no 'unsafe-inline'.
 */
export function ThemeScript({nonce}: {nonce?: string}) {
  return <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{__html: SCRIPT}} />;
}
