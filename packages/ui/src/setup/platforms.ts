import type {GeneratorId} from "@ctrlz/api-client/hooks/setup.ts";

// The platforms of Help Me Configure (Plan T-243, spec p3 8.3), in the order the list shows them, and what each can do. The text of a
// platform's steps lives in content/<language>/<id>.json (guide.ts); this file is the one list of ids, versions and automatic setups, so
// the list, the URL parser, the steps and the test of T-243 all read the same thing.

export const PLATFORM_GROUPS = ["computer", "mobile", "browser", "tv", "router"] as const;
export type PlatformGroup = (typeof PLATFORM_GROUPS)[number];

/** What Automatic Setup does for a platform: a generator's text to copy, or the Apple profile builder. Absent when the platform has none. */
export type Automatic = {kind: "generator"; generator: GeneratorId} | {kind: "apple"};

export const PLATFORM_ID_LIST = ["windows", "mac", "linux", "ios", "android", "chrome", "firefox", "edge", "brave", "apple-tv", "android-tv", "fire-tv", "samsung-tv", "router"] as const;
export type PlatformId = (typeof PLATFORM_ID_LIST)[number];

export type Platform = {
  /** `setupOs` in the address. */
  id: PlatformId;
  group: PlatformGroup;
  /** An icon of our own set (`svg/setup`). By form, not by brand: no vendor logo is drawn. */
  icon: "desktop" | "laptop" | "terminal" | "phone" | "browser" | "tv" | "tv-box" | "router";
  /** The versions the picker offers, in order. One version means no picker. Every id has steps in the content files. */
  versions: readonly string[];
  /** Automatic Setup per version. A version missing here has none. */
  automatic: Readonly<Record<string, Automatic>>;
};

const generator = (id: GeneratorId): Automatic => ({kind: "generator", generator: id});
const apple: Automatic = {kind: "apple"};

/** The fourteen platforms of T-243, in the order of the Plan. */
export const PLATFORMS: readonly Platform[] = [
  {id: "windows", group: "computer", icon: "desktop", versions: ["11", "10"], automatic: {"11": generator("windows-doh"), "10": generator("address-list")}},
  {id: "mac", group: "computer", icon: "laptop", versions: ["13", "12"], automatic: {"13": apple, "12": apple}},
  {id: "linux", group: "computer", icon: "terminal", versions: ["resolved"], automatic: {}},
  {id: "ios", group: "mobile", icon: "phone", versions: ["14"], automatic: {"14": apple}},
  {id: "android", group: "mobile", icon: "phone", versions: ["9"], automatic: {"9": generator("android-private-dns")}},
  {id: "chrome", group: "browser", icon: "browser", versions: ["browser"], automatic: {browser: generator("chromium-policy")}},
  {id: "firefox", group: "browser", icon: "browser", versions: ["browser"], automatic: {browser: generator("firefox-policy")}},
  {id: "edge", group: "browser", icon: "browser", versions: ["browser"], automatic: {browser: generator("chromium-policy")}},
  {id: "brave", group: "browser", icon: "browser", versions: ["browser"], automatic: {browser: generator("chromium-policy")}},
  {id: "apple-tv", group: "tv", icon: "tv-box", versions: ["14", "13"], automatic: {"14": apple, "13": generator("address-list")}},
  {id: "android-tv", group: "tv", icon: "tv-box", versions: ["tv"], automatic: {tv: generator("address-list")}},
  {id: "fire-tv", group: "tv", icon: "tv-box", versions: ["tv"], automatic: {tv: generator("address-list")}},
  {id: "samsung-tv", group: "tv", icon: "tv", versions: ["tv"], automatic: {tv: generator("address-list")}},
  {id: "router", group: "router", icon: "router", versions: ["router"], automatic: {router: generator("address-list")}},
];

export const PLATFORM_IDS = PLATFORMS.map((p) => p.id);

export const platformOf = (id: string | null | undefined): Platform | undefined => PLATFORMS.find((p) => p.id === id);

/** The version a platform opens on, and the one a stored or typed value falls back to. */
export const defaultVersion = (platform: Platform): string => platform.versions[0]!;
export const versionOf = (platform: Platform, wanted: string | null | undefined): string =>
  wanted && platform.versions.includes(wanted) ? wanted : defaultVersion(platform);

export const automaticOf = (platform: Platform, version: string): Automatic | undefined => platform.automatic[version];

/** Platforms that have an Automatic Setup in at least one version. */
export const automaticPlatforms = (): Platform[] => PLATFORMS.filter((p) => Object.keys(p.automatic).length > 0);

/** Platforms set by address: they need a claim of the network (spec p3 8.3). Derived from the guide, which says so in its first step. */
export const NETWORK_ADDRESS_PLATFORMS = ["windows", "mac", "apple-tv", "android-tv", "fire-tv", "samsung-tv", "router"] as const;

/**
 * The version rides in `setupOs` (`windows-10`, `mac-12`, `apple-tv-13`), because the address has no other parameter for it (spec p3 10, FE 9) and
 * a reload or a link would otherwise open another version's steps. The default version is left out, so `windows` is still Windows 11.
 */
export function parseSetupNav(value: string | null | undefined): {platform: Platform; version: string | null} | null {
  if (!value) return null;
  for (const platform of PLATFORMS) {
    if (value === platform.id) return {platform, version: null};
    if (value.startsWith(`${platform.id}-`)) {
      const version = value.slice(platform.id.length + 1);
      if (platform.versions.includes(version) && version !== defaultVersion(platform)) return {platform, version};
    }
  }
  return null;
}

/** The `setupOs` value of a platform and the version in use, with the default version left out. */
export function setupOsValue(os: string | null, version: string | null | undefined): string | null {
  const platform = platformOf(os);
  if (!platform) return os;
  return version && version !== defaultVersion(platform) && platform.versions.includes(version) ? `${platform.id}-${version}` : platform.id;
}
