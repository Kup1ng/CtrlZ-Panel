// The augmentation file is never imported, so each entry point pulls it into the program.
// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="./types.d.ts" />
import {hasLocale} from "next-intl";
import {notFound} from "next/navigation";
import {getRequestConfig} from "next-intl/server";

import {TIME_ZONE} from "./locale.ts";
import {loadMessages} from "./messages.ts";
import type {AppId} from "./namespaces.ts";
import {routing} from "./routing.ts";

/**
 * The request config of one app (spec 4.1). `readLocale` is the `locale`
 * getter of `next/root-params`: that module is replaced by the Next compiler
 * and cannot be imported from here, so each app passes its own in.
 *
 * `setRequestLocale` is the legacy route and is not used. An invalid locale
 * is a 404: the proxy already redirects unprefixed paths, so only a path such
 * as `/fa/x` with a bad first segment can reach this.
 */
export function createRequest(app: AppId, readLocale: () => Promise<string | undefined>) {
  return getRequestConfig(async () => {
    const candidate = await readLocale();
    if (!hasLocale(routing.locales, candidate)) notFound();
    return {
      locale: candidate,
      timeZone: TIME_ZONE,
      messages: await loadMessages(candidate, app),
    };
  });
}
