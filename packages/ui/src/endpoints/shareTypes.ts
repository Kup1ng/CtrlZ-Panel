import type {IconName} from "@ctrlz/icons/generated/registry.ts";

// The share page has no session, so it cannot ask `GET /endpoint-types` for the names of the 30 types, and `ShareView.endpoint.type` is
// the type's key only (spec p3 7.2). The keys are the seed of migration 0076 (position order), each with the picture of its group. A key
// the table does not know (a type added by a later migration) is shown with the generic picture and its key, so the page never breaks on it.

type Group = "computer" | "phone" | "browser" | "tv" | "router" | "server" | "network";

const GROUP_OF = {
  windows: "computer",
  mac: "computer",
  linux: "computer",
  ios: "phone",
  android: "phone",
  chrome: "browser",
  firefox: "browser",
  edge: "browser",
  brave: "browser",
  other_browser: "browser",
  apple_tv: "tv",
  android_tv: "tv",
  fire_tv: "tv",
  samsung_tv: "tv",
  other_tv: "tv",
  asus_merlin: "router",
  dd_wrt: "router",
  firewalla: "router",
  fresh_tomato: "router",
  gl_inet: "router",
  openwrt: "router",
  opnsense: "router",
  pfsense: "router",
  synology: "server",
  ubiquiti: "router",
  windows_server: "server",
  generic_linux: "server",
  tailscale: "network",
  other_router: "router",
  other_endpoint: "network",
} as const satisfies Record<string, Group>;

export type ShareTypeKey = keyof typeof GROUP_OF;

const ICON_OF: Record<Group, IconName<"setup">> = {
  computer: "desktop",
  phone: "phone",
  browser: "browser",
  tv: "tv",
  router: "router",
  server: "terminal",
  network: "router",
};

/** The keys the table knows, for the message check: every one has a name in both languages in `setup.share.types`. */
export const SHARE_TYPE_KEYS = Object.keys(GROUP_OF);

export const isKnownShareType = (key: string): key is ShareTypeKey => Object.hasOwn(GROUP_OF, key);

/** The picture of a type in the `setup` group of our own icons. */
export function shareTypeIcon(key: string): IconName<"setup"> {
  const group: Group = isKnownShareType(key) ? GROUP_OF[key] : "network";
  return ICON_OF[group];
}
