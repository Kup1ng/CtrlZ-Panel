import type {Options, OptionsPatch, OptionName} from "@ctrlz/api-client/hooks/options.ts";
import type {LocationRef} from "@ctrlz/api-client/hooks/profiles.ts";
import type {Target} from "@ctrlz/api-client/hooks/services.ts";
import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";

import {isIPv4, isIPv6} from "../../destinations/destinations.ts";

// The rules of the Profile Options screen, kept out of the components so they are tested without a DOM (spec p2 9.7, 3.7, SC 6).
// The API decides last, with the same bounds; these checks only spare a round trip and word the problem next to the field.

/** The rows of the screen in the order of Plan "Profile Options" (without AI Malware, D5, and Compatibility Mode, D9). */
export const OPTION_ROWS = [
  "default_rule",
  "block_exfiltration",
  "rebind_protection",
  "disable_dnssec",
  "block_ttl",
  "redirect_ttl",
  "bypass_ttl",
  "block_response",
  "ecs",
  "dns64",
  "cname_flattening",
  "safe_search",
  "restricted_youtube",
  "disable",
  "lock",
] as const;
export type OptionRow = (typeof OPTION_ROWS)[number];

/** The options that are one switch. Off is not stored: the option is cleared (open question 3). */
export const SWITCH_OPTIONS = ["block_exfiltration", "rebind_protection", "disable_dnssec", "dns64", "cname_flattening", "safe_search", "restricted_youtube"] as const satisfies readonly OptionName[];
export type SwitchOption = (typeof SWITCH_OPTIONS)[number];

export const TTL_OPTIONS = ["block_ttl", "redirect_ttl", "bypass_ttl"] as const satisfies readonly OptionName[];
export type TtlOption = (typeof TTL_OPTIONS)[number];

export const TTL_MIN = 1;
export const TTL_MAX = 86_400;
/** SC 6: Block and Redirect answer with 60 s unless set. Bypass keeps the answer's own TTL, so it has no number. */
export const TTL_DEFAULT: Record<TtlOption, number | null> = {block_ttl: 60, redirect_ttl: 60, bypass_ttl: null};

/**
 * The seconds a reader typed. Persian and Arabic-Indic digits count as the digits they are, since a keyboard in Iran is as likely to type
 * the one as the other, and a value grouped in threes as the hint prints it ("86,400", "۸۶٬۴۰۰", "86 400") is read too (S2-r3-2); anything
 * else (a sign, a point, a letter, nothing) is `NaN`, which `ttlProblem` calls "required".
 */
export function parseTtl(text: string): number {
  const ascii = toAsciiDigits(text).trim();
  // The comma, the Arabic thousands separator and comma, and the spaces a locale prints between groups.
  const grouped = /^[0-9]{1,3}(?:[,٬،    ][0-9]{3})+$/.test(ascii) ? ascii.replace(/[,٬،    ]/g, "") : ascii;
  return /^[0-9]{1,9}$/.test(grouped) ? Number(grouped) : Number.NaN;
}

export type TtlProblem = "required" | "out_of_range";
export function ttlProblem(value: number | null | undefined): TtlProblem | null {
  if (value === null || value === undefined || Number.isNaN(value)) return "required";
  if (!Number.isInteger(value) || value < TTL_MIN || value > TTL_MAX) return "out_of_range";
  return null;
}

/** The slug of the icon in `@ctrlz/icons` group `options` for a row, or `lock` (a general icon) for Lock Profile. */
export const ROW_ICON: Record<OptionRow, string> = {
  default_rule: "default-rule",
  block_exfiltration: "exfiltration",
  rebind_protection: "rebind",
  disable_dnssec: "dnssec",
  block_ttl: "ttl",
  redirect_ttl: "ttl",
  bypass_ttl: "ttl",
  block_response: "block-response",
  ecs: "ecs",
  dns64: "dns64",
  cname_flattening: "cname",
  safe_search: "safe-search",
  restricted_youtube: "restricted-youtube",
  disable: "disable",
  lock: "lock",
};

// ---- Default Rule ----

export type DefaultAction = "block" | "bypass" | "redirect";
/** The stored action, or Bypass, which is what an unset Default Rule does (SC 6). */
export const defaultActionOf = (options: Options): DefaultAction => options.default_rule?.action ?? "bypass";

/**
 * The target with the place it names, read from the set the profile may use. A response carries `location` beside `location_id`, but the
 * value a save shows before the server's answer (the optimistic one) carries only the id, and a row must not read "unknown" in between.
 */
export function withLocation(target: Target | undefined, locations: readonly LocationRef[] | undefined): Target | undefined {
  if (!target || target.kind !== "location" || target.location || !target.location_id) return target;
  const found = locations?.find((l) => l.id === target.location_id);
  if (!found) return target;
  return {...target, location: {...(found.country ? {country: found.country} : {}), ...(found.city ? {city: found.city} : {}), ...(found.label ? {label: found.label} : {})}};
}

/** Whether two targets send names to the same place. A saved target and the dialog's draft name a location by id and may differ in what else they carry. */
export function sameTarget(a: Target | null | undefined, b: Target | null | undefined): boolean {
  if (!a || !b) return a === b || (!a && !b);
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "location":
      return (a.location_id ?? "") === (b.location_id ?? "");
    case "ip":
      return (a.ipv4 ?? "") === (b.ipv4 ?? "") && (a.ipv6 ?? "") === (b.ipv6 ?? "");
    case "host":
      return (a.host ?? "").toLowerCase() === (b.host ?? "").toLowerCase();
    default:
      return true;
  }
}

// ---- Addresses and subnets ----

export type AddressProblem = "invalid";
export type SubnetProblem = "invalid" | "host_bits";

const WIDE_PREFIX = /^(0|[1-9]\d{0,2})$/;

/** The address as 16 bytes, for the prefix arithmetic of an IPv6 subnet. Only called for a string `isIPv6` accepted. */
function v6Bytes(value: string): number[] {
  let text = value;
  const tail = text.slice(text.lastIndexOf(":") + 1);
  if (tail.includes(".")) {
    const [a, b, c, d] = tail.split(".").map(Number) as [number, number, number, number];
    text = `${text.slice(0, text.lastIndexOf(":") + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", rest] = text.split("::");
  const side = (s: string) => (s === "" ? [] : s.split(":"));
  const left = side(head);
  const right = rest === undefined ? [] : side(rest);
  const groups = rest === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  return groups.flatMap((g) => {
    const n = parseInt(g, 16);
    return [n >> 8, n & 255];
  });
}

/** True when any bit after the first `prefix` bits is set. */
function hasHostBits(bytes: readonly number[], prefix: number): boolean {
  return bytes.some((byte, i) => {
    const keep = Math.max(0, Math.min(8, prefix - i * 8));
    const mask = keep === 8 ? 0xff : (0xff << (8 - keep)) & 0xff;
    return (byte & ~mask & 0xff) !== 0;
  });
}

/** One address of the family, as Custom Block Response takes it. An empty field is "not given" (null), not a problem by itself. */
export function addressProblem(value: string, family: 4 | 6): AddressProblem | null {
  if (value === "") return null;
  return (family === 4 ? isIPv4(value) : isIPv6(value)) ? null : "invalid";
}

/** A subnet "address/prefix" of the family. An ECS prefix with host bits set is refused, as the API does (spec p2 3.7). */
export function subnetProblem(value: string, family: 4 | 6): SubnetProblem | null {
  if (value === "") return null;
  const slash = value.indexOf("/");
  if (slash < 0) return "invalid";
  const address = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  const max = family === 4 ? 32 : 128;
  if (!WIDE_PREFIX.test(prefixText) || Number(prefixText) > max || Number(prefixText) < 1) return "invalid";
  if (family === 4 ? !isIPv4(address) : !isIPv6(address)) return "invalid";
  const bytes = family === 4 ? address.split(".").map(Number) : v6Bytes(address);
  return hasHostBits(bytes, Number(prefixText)) ? "host_bits" : null;
}

// ---- Block Response ----

export const BLOCK_MODES = ["zero", "nxdomain", "refused", "custom", "branded"] as const;
export type BlockMode = (typeof BLOCK_MODES)[number];
/** Branded is shown as coming later and refused by the API until P4b (open question 9). */
export const BLOCK_MODES_AVAILABLE = ["zero", "nxdomain", "refused", "custom"] as const satisfies readonly BlockMode[];

export type CustomDraft = {v4: string; v6: string};
export type CustomProblems = {v4?: AddressProblem; v6?: AddressProblem; needOne?: true};

export function blockCustomProblems(draft: CustomDraft): CustomProblems {
  const out: CustomProblems = {};
  const v4 = addressProblem(draft.v4, 4);
  const v6 = addressProblem(draft.v6, 6);
  if (v4) out.v4 = v4;
  if (v6) out.v6 = v6;
  if (!out.v4 && !out.v6 && draft.v4 === "" && draft.v6 === "") out.needOne = true;
  return out;
}

export type EcsProblems = {v4?: SubnetProblem; v6?: SubnetProblem; needOne?: true};
export function ecsCustomProblems(draft: CustomDraft): EcsProblems {
  const out: EcsProblems = {};
  const v4 = subnetProblem(draft.v4, 4);
  const v6 = subnetProblem(draft.v6, 6);
  if (v4) out.v4 = v4;
  if (v6) out.v6 = v6;
  if (!out.v4 && !out.v6 && draft.v4 === "" && draft.v6 === "") out.needOne = true;
  return out;
}

export const hasProblems = (problems: object) => Object.keys(problems).length > 0;

/** The body of a Custom unit: only the fields that are filled. */
export function customBody(draft: CustomDraft): {v4?: string; v6?: string} {
  return {...(draft.v4 ? {v4: draft.v4} : {}), ...(draft.v6 ? {v6: draft.v6} : {})};
}

// ---- ECS ----

export const ECS_MODES = ["none", "auto", "custom"] as const;
export type EcsMode = (typeof ECS_MODES)[number];

// ---- Disable ----

export const DISABLE_CHOICES = ["5m", "1h", "1d", "custom"] as const;
export type DisableChoice = (typeof DISABLE_CHOICES)[number];

/** A profile is disabled while `disabled_until` is still ahead. A stale value that the list has not dropped yet does not count. */
export function isDisabledNow(disabledUntil: string | undefined, now: number): boolean {
  if (!disabledUntil) return false;
  const at = Date.parse(disabledUntil);
  return Number.isFinite(at) && at > now;
}

/** A date picked earlier counts only while it is still ahead; one that has passed is treated as not picked, so the API never gets `in_past` (S2-r1-4). */
export function freshUntil(date: Date | null, now: number): Date | null {
  return date && date.getTime() > now ? date : null;
}

/** The body of `PUT /disabled`, or null while a Custom choice has no date yet. */
export function disableBody(choice: DisableChoice, customUntil: Date | null): {for: "5m" | "1h" | "1d"} | {until: string} | null {
  if (choice !== "custom") return {for: choice};
  return customUntil ? {until: customUntil.toISOString()} : null;
}

// ---- A patch ----

/** Turning a switch on sets it; off clears it, since every option's default is off (open question 3). */
export function switchPatch(name: SwitchOption, on: boolean): OptionsPatch {
  return on ? {[name]: true} : {clear: [name]};
}

/** True when the Options already hold what the patch would do, so the screen sends nothing. */
export function isNoop(options: Options, patch: OptionsPatch): boolean {
  const {clear, ...set} = patch;
  for (const [name, value] of Object.entries(set)) {
    if (JSON.stringify((options as Record<string, unknown>)[name]) !== JSON.stringify(value)) return false;
  }
  return (clear ?? []).every((name) => (options as Record<string, unknown>)[name] === undefined);
}
