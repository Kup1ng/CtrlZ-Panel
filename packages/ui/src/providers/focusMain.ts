// After the idle cover's Continue (wp4-r9-1). The button that had focus is unmounted with the cover and the
// page comes back as a fresh mount: the gate skeleton first, the shell (and #main-content, which takes
// focus on purpose, tabIndex -1) a request later. Nothing moves focus in between, so it stays on <body> and
// a keyboard or screen-reader user starts again from the top, told nothing about the page that returned
// (spec 17.5). So focus goes to the page region once it exists, and only while focus is still nowhere: a
// person or a page that has put it somewhere else keeps it.

/** How long to wait for the page to come back before giving up. */
export const FOCUS_MAIN_WAIT_MS = 15_000;

type Doc = Pick<Document, "activeElement" | "body" | "getElementById">;

/** Returns what stops the wait. `observe` is MutationObserver, a parameter so a test needs no DOM. */
export function focusMainWhenBack(
  doc: Doc,
  observe: (onChange: () => void) => {disconnect: () => void},
  setTimer: (fn: () => void, ms: number) => unknown = setTimeout as never,
  clearTimer: (id: unknown) => void = clearTimeout as never,
): () => void {
  let done = false;
  const observer: {current?: {disconnect: () => void}} = {};
  const timer: {current?: unknown} = {};
  const stop = () => {
    done = true;
    observer.current?.disconnect();
    clearTimer(timer.current);
  };
  const attempt = () => {
    if (done) return;
    const active = doc.activeElement;
    if (active && active !== doc.body) return stop();
    const main = doc.getElementById("main-content");
    if (!main) return;
    main.focus();
    stop();
  };
  observer.current = observe(attempt);
  timer.current = setTimer(stop, FOCUS_MAIN_WAIT_MS);
  attempt();
  return stop;
}

export const observeDocument = (onChange: () => void) => {
  const observer = new MutationObserver(onChange);
  observer.observe(document.body, {childList: true, subtree: true});
  return observer;
};
