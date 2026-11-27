import {useLocale} from "react-aria-components";

// The only file that may write the literal arrow key names (lint rule
// no-physical-arrow). React Aria widgets already flip their arrows by locale;
// this is for handlers of our own, so "next" means "toward the inline end".

export type DirectionalKeys = {
  /** True for the key that moves toward the end of the line: right in LTR, left in RTL. */
  isNext(event: {key: string}): boolean;
  /** The key that moves toward the start of the line. */
  isPrev(event: {key: string}): boolean;
};

export function useDirectionalKeys(): DirectionalKeys {
  const {direction} = useLocale();
  const next = direction === "rtl" ? "ArrowLeft" : "ArrowRight";
  const prev = direction === "rtl" ? "ArrowRight" : "ArrowLeft";
  return {isNext: (e) => e.key === next, isPrev: (e) => e.key === prev};
}
