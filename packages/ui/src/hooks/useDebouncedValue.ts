"use client";

import {useEffect, useState} from "react";

/**
 * The value after it has stopped changing for `delay` ms. The first value is returned at once. A value that `instant` accepts (a cleared search)
 * goes through on the next tick instead of waiting, so a clear is not slower than a keystroke.
 */
export function useDebouncedValue<T>(value: T, delay: number, instant?: (value: T) => boolean): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), instant?.(value) ? 0 : delay);
    return () => clearTimeout(timer);
  }, [value, delay, instant]);
  return settled;
}
