import {existsSync, readdirSync} from "node:fs";
import {join} from "node:path";

const PAGE_FILES = ["page.tsx", "page.ts", "page.jsx", "page.js"];

/**
 * Whether an app has a login page under `src/app/[locale]/`, directly or inside a route group such as `(auth)`.
 * A route group does not change the URL, and the panel's login lives in one, so a check for the plain path alone would
 * keep the admin's skipped cases off for ever once WP10 puts its login the same way (wp5-r16-2). Specs that wait for
 * that page use this one function, so there is no second spelling of the rule to fall out of step.
 */
export function hasLoginPage(appDir: string): boolean {
  const root = join(appDir, "src/app/[locale]");
  const holds = (dir: string) => PAGE_FILES.some((f) => existsSync(join(dir, "login", f)));
  if (holds(root)) return true;
  try {
    return readdirSync(root, {withFileTypes: true}).some((e) => e.isDirectory() && /^\(.+\)$/.test(e.name) && holds(join(root, e.name)));
  } catch {
    return false;
  }
}
