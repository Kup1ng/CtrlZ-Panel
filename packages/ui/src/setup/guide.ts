import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {useEffect, useState} from "react";

import {GUIDE_LOADERS} from "./content/index.ts";

// The step data of Help Me Configure (spec p3 8.3). A step has a title and a text, and names which values of the Resolver view it shows
// with Copy buttons: it never holds an address, a host or a URL itself, so a value is always the one the Resolver view gives now
// (T-544: the primary first, a strict mode, no plaintext fallback). The files are content/<language>/<platform>.json, one lazy chunk each.

/** The values a step may show. `resolved_conf` is the text of a systemd-resolved drop-in, built here from the view. */
export const VALUE_KEYS = ["host", "doh_url", "dns1", "dns2", "resolved_conf"] as const;
export type ValueKey = (typeof VALUE_KEYS)[number];

export type GuideStep = {
  title: string;
  text: string;
  /** Values to show under the text, each with its Copy button. */
  show?: ValueKey[];
  /** A button to the Addresses page of the Endpoint (the claim of a network). Not shown on the share page, which has no such page. */
  link?: "ips";
  /** The last step: the verification of spec p3 8.4 sits under it. */
  verify?: boolean;
};
export type GuideVersion = {id: string; name: string; steps: GuideStep[]};
export type Guide = {versions: GuideVersion[]};

/** The text of a value, or `undefined` when the view does not have it (not ready). */
export function valueOf(view: ResolverView, key: ValueKey): string | undefined {
  const dns1 = view.legacy?.dns1;
  const dns2 = view.legacy?.dns2;
  switch (key) {
    case "host":
      return view.host;
    case "doh_url":
      return view.doh_url;
    case "dns1":
      return dns1;
    case "dns2":
      return dns2;
    case "resolved_conf":
      // The primary first (SC 8a.8), each with the host name for the certificate check, and DNSOverTLS=yes: never "opportunistic". `Domains=~.` is
      // what makes these servers the ones for every name: without it systemd-resolved asks them in parallel with the servers a link (DHCP) gives,
      // and a network resolver that speaks DoT would still answer.
      if (!dns1 || !dns2 || !view.host) return undefined;
      return `[Resolve]\nDNS=${dns1}#${view.host} ${dns2}#${view.host}\nDomains=~.\nDNSOverTLS=yes\n`;
  }
}

/** Keys whose value carries the DoH token: copied as a one-time secret. */
export const SECRET_VALUES: readonly ValueKey[] = ["doh_url"];

export type GuideState = {status: "loading"} | {status: "error"} | {status: "ready"; guide: Guide};

/** Loads the steps of one platform in one language. A platform with no file is an error, not an empty wizard. */
export function useGuide(language: string, platform: string): GuideState & {retry: () => void} {
  const [state, setState] = useState<{key: string; value: GuideState} | null>(null);
  const [attempt, setAttempt] = useState(0);
  const key = `${language}/${platform}/${attempt}`;
  useEffect(() => {
    let live = true;
    const loader = (GUIDE_LOADERS[language === "fa" ? "fa" : "en"] as Record<string, (typeof GUIDE_LOADERS)["fa"][string]>)[platform];
    if (!loader) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- the platform has no file: the answer is known at once
      setState({key, value: {status: "error"}});
      return;
    }
    loader().then(
      (module) => live && setState({key, value: {status: "ready", guide: module.default}}),
      () => live && setState({key, value: {status: "error"}}),
    );
    return () => {
      live = false;
    };
  }, [key, language, platform]);
  const value: GuideState = state && state.key === key ? state.value : {status: "loading"};
  return {...value, retry: () => setAttempt((n) => n + 1)};
}
