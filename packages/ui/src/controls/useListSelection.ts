"use client";

import {useCallback, useMemo, useReducer} from "react";

import {batchTarget, isSelected, isSelecting, OFF, reduce, selectedCount, selectionOverflow, type BatchTarget, type Selection} from "./selection.ts";

// The state of a list's selection mode (controls/selection.ts holds the rules). A screen keeps one per list:
//
//   const sel = useListSelection();
//   row: onPress={() => (sel.selecting ? sel.toggle(id, loadedIds) : open(row))}  checked={sel.isSelected(id)}
//   header: <SelectionBar count={sel.count(loadedIds.length, total)} ...>
//   write:  const target = sel.target()   // {kind: "ids", ids} or {kind: "selector"}

export function useListSelection() {
  const [state, dispatch] = useReducer(reduce, OFF as Selection);
  const enter = useCallback((id?: string) => dispatch({type: "enter", id}), []);
  const exit = useCallback(() => dispatch({type: "exit"}), []);
  const clear = useCallback(() => dispatch({type: "clear"}), []);
  const selectAll = useCallback(() => dispatch({type: "selectAll"}), []);
  const toggle = useCallback((id: string, loaded: readonly string[]) => dispatch({type: "toggle", id, loaded}), []);
  const reconcile = useCallback((loaded: readonly string[], filterChanged: boolean) => dispatch({type: "reconcile", loaded, filterChanged}), []);
  return useMemo(
    () => ({
      state,
      selecting: isSelecting(state),
      allMatching: state.mode === "all",
      isSelected: (id: string) => isSelected(state, id),
      count: (loadedCount: number, total?: number) => selectedCount(state, loadedCount, total),
      target: (max?: number): BatchTarget | null => batchTarget(state, max),
      /** Ids that `target(max)` would leave out. A route with a limit under 10,000 shows this before it sends. */
      overflow: (max?: number) => selectionOverflow(state, max),
      enter,
      exit,
      clear,
      selectAll,
      toggle,
      reconcile,
    }),
    [state, enter, exit, clear, selectAll, toggle, reconcile],
  );
}

export type ListSelection = ReturnType<typeof useListSelection>;
