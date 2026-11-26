// The rules of the three-state control (Block, Bypass, Redirect), kept out of the component so that they are tested without a DOM.
// Spec p2 9.4 and 3.6, SC 10.5 (D42), T-166, T-521.

export const ACTIONS = ["block", "bypass", "redirect", "inherit"] as const;
export type Action = (typeof ACTIONS)[number];

/** Why Redirect is not offered. */
export type RedirectOff = "never_proxied" | "no_shared";

export type ThreeStateState = {
  /** The stored state of the row. */
  value: Action;
  /** The service or name is never proxied (`redirect_allowed` false, D42): the control offers Block and Bypass only. */
  redirectAllowed: boolean;
  /** The location set has no shared destination (`auto_random` false and no location, T-166). */
  hasDestination: boolean;
  /** The row says it acts as Bypass: its name is Iranian (`iranian_bypass`). */
  iranianBypass?: boolean;
  /** The row's destination left the set (`location_unavailable`): it acts as Bypass until it returns. */
  locationUnavailable?: boolean;
};

/**
 * Which choices the control SHOWS. Redirect is not shown at all for a name that is never proxied (D42, T-521: "the control has only
 * Block and Bypass"), except on a row that already says Redirect (an existing row that a later list covered, P2 3.6), which keeps its
 * button so the state it is in is never hidden. `inherit` is shown only where the caller asks for it.
 */
export function offeredChoices(wanted: readonly Action[], state: Pick<ThreeStateState, "redirectAllowed" | "value">): Action[] {
  return wanted.filter((a) => a !== "redirect" || state.redirectAllowed || state.value === "redirect");
}

/** The reason Redirect cannot be chosen, or `null` when it can (or when nobody asked for it). The never-proxied reason wins. */
export function redirectOffReason(state: Pick<ThreeStateState, "redirectAllowed" | "hasDestination">): RedirectOff | null {
  if (!state.redirectAllowed) return "never_proxied";
  if (!state.hasDestination) return "no_shared";
  return null;
}

/**
 * Whether a shown choice is disabled. Redirect with no shared destination is shown and disabled (T-166), with its reason beside it.
 * A row already set to Redirect can still be moved away from it, and its own button stays pressable.
 */
export function isChoiceDisabled(action: Action, state: Pick<ThreeStateState, "redirectAllowed" | "hasDestination" | "value">): boolean {
  if (action !== "redirect" || state.value === "redirect") return false;
  return state.redirectAllowed && !state.hasDestination;
}

/**
 * What the node does with the row. A Redirect of a never-proxied name acts as Bypass (D42), and so does one whose destination is
 * not available now (P2 4.2). Block stays Block. The control shows this beside the state, as words and an icon, so the screen never
 * claims a redirect that does not happen.
 */
export function effectiveAction(state: Pick<ThreeStateState, "value" | "iranianBypass" | "locationUnavailable">): Action {
  if (state.value === "redirect" && (state.iranianBypass || state.locationUnavailable)) return "bypass";
  return state.value;
}

/** The note a control shows under itself, as a key of `rules.three.*`, or `null`. At most one: the reason that matters most. */
export function controlNote(state: ThreeStateState): "neverProxied" | "noShared" | "iranianBypass" | "unavailable" | null {
  if (state.value === "redirect" && state.iranianBypass) return "iranianBypass";
  if (state.value === "redirect" && state.locationUnavailable) return "unavailable";
  if (state.value !== "redirect") {
    const off = redirectOffReason(state);
    if (off === "never_proxied") return "neverProxied";
    if (off === "no_shared") return "noShared";
  }
  return null;
}
