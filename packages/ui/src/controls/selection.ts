// The selection of a list in selection mode (WF "Rules": a click on a row opens it, a check box on each row, SELECT ALL, and a bar in the
// header). Spec p2 9.6 and p3 10 (Endpoints, Clients).
//
// A list of 10,000 rules is loaded by pages, so the rows in memory are never "all". Select All therefore does not collect the ids of
// the loaded rows: it records that EVERY row of the current filter is selected (`all`), and the write is sent as a `selector` over that
// filter, which the server resolves under its own lock. The moment a person unticks one row after Select All, the selection becomes the
// ids of the rows that are loaded, minus that one, because a selector cannot say "all but". That is a smaller promise and it is shown as
// one (the count drops to the loaded rows).
//
// A pure reducer, so every rule is tested without a DOM. The hook of `useListSelection.ts` is a thin wrapper.

export type Selection =
  | {readonly mode: "off"}
  | {readonly mode: "ids"; readonly ids: ReadonlySet<string>}
  | {readonly mode: "all"};

export const OFF: Selection = {mode: "off"};

export type SelectionAction =
  | {type: "enter"; id?: string}
  | {type: "toggle"; id: string; loaded: readonly string[]}
  | {type: "selectAll"}
  | {type: "clear"}
  | {type: "exit"}
  /** The list changed under the selection (another filter, a row deleted): ids that are gone leave it. `all` ends, since it was for the old filter. */
  | {type: "reconcile"; loaded: readonly string[]; filterChanged: boolean};

export function reduce(state: Selection, action: SelectionAction): Selection {
  switch (action.type) {
    case "enter":
      return state.mode === "off" ? {mode: "ids", ids: new Set(action.id ? [action.id] : [])} : state;
    case "exit":
      return OFF;
    case "clear":
      return state.mode === "off" ? state : {mode: "ids", ids: new Set()};
    case "selectAll":
      return state.mode === "off" ? state : {mode: "all"};
    case "toggle": {
      if (state.mode === "off") return state;
      const ids = state.mode === "all" ? new Set(action.loaded) : new Set(state.ids);
      if (ids.has(action.id)) ids.delete(action.id);
      else ids.add(action.id);
      return {mode: "ids", ids};
    }
    case "reconcile": {
      if (state.mode === "off") return state;
      if (action.filterChanged) return {mode: "ids", ids: new Set()};
      if (state.mode === "all") return state;
      const loaded = new Set(action.loaded);
      const ids = new Set([...state.ids].filter((id) => loaded.has(id)));
      return ids.size === state.ids.size ? state : {mode: "ids", ids};
    }
  }
}

export const isSelecting = (s: Selection): boolean => s.mode !== "off";
export const isSelected = (s: Selection, id: string): boolean => s.mode === "all" || (s.mode === "ids" && s.ids.has(id));

/** How many rows are selected. `total` is the count the server gave for the filter, for Select All; without it the loaded rows are what is known. */
export function selectedCount(s: Selection, loadedCount: number, total?: number): number {
  if (s.mode === "off") return 0;
  if (s.mode === "all") return total ?? loadedCount;
  return s.ids.size;
}

/**
 * What a batch route is sent: ids, or the selector of the current filter. A list of ids is cut at `max` (the route's limit), and the cut
 * is silent here, so a screen whose route is smaller than the default asks `selectionOverflow(s, max)` first and says so, or stops. The
 * default 10,000 is the rules and profiles routes'; the Endpoint and client routes take 500 ids and have NO selector, so there the screen
 * passes `max = 500`, checks the overflow, and answers Select All (mode "all") by listing the ids itself, never by sending `selector`.
 */
export type BatchTarget = {kind: "ids"; ids: string[]} | {kind: "selector"};
export function batchTarget(s: Selection, max = 10_000): BatchTarget | null {
  if (s.mode === "off") return null;
  if (s.mode === "all") return {kind: "selector"};
  if (s.ids.size === 0) return null;
  return {kind: "ids", ids: [...s.ids].slice(0, max)};
}

/** How many selected ids a route that takes `max` would leave out: 0 for a selector (the server counts it) and for an empty selection. */
export function selectionOverflow(s: Selection, max = 10_000): number {
  return s.mode === "ids" ? Math.max(0, s.ids.size - max) : 0;
}
