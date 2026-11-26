// A full page load that this page has started itself (the language switch, spec 4.2). React unmounts nothing for
// it, so the page keeps running, with its calls in flight, until the new document commits. A sign-in whose
// answer arrives in that window must not finish: it has opened a session that the new page does not show, and
// the `here` and `mounted` checks of the sign-in code cannot tell (wp8-r9-6). Whoever starts such a load marks it
// first; the sign-in code asks.
//
// A load can also end without a new document: the visitor presses Escape or Stop, or a script calls
// window.stop(). The old document then lives on, and a mark that nothing clears would end every later sign-in on
// it and leave its form spinning (wp8-r10-3). Neither `pagehide` nor `unload` fires for that, so the mark is tied
// to the navigation itself where the browser has the Navigation API: the `navigate` event of the load carries a
// signal that aborts when the load is cancelled, and the mark is cleared then. A browser without the API gets
// the next input event instead: a document that takes the visitor's next key or click after the mark was not
// replaced in time, and it is the less harmful guess (a retry then works; a sign-in that answers to a visitor who
// submits during a load that does finish leaves, at worst, a session behind the new page, which is the old
// round 9 outcome and rare).

let leaving = false;
let watching = false;

type NavigateEventLike = Event & {signal?: AbortSignal; destination?: {sameDocument?: boolean}};
type NavigationLike = EventTarget;

const clear = () => {
  leaving = false;
};

// An abort is not always a cancel. Chrome aborts the signal of a pending load whenever a later navigation starts,
// and the load still commits: a second language pick (a second location.replace) and the same-document
// history.replaceState of the tab list (useMirroredStep) both do it, and a mark cleared by them lets a sign-in
// that answers during the load leave a live session behind the new login page (wp8-r11-4, measured in Chrome).
// So an abort clears the mark only when no navigate event comes with it: the abort and the event of the
// navigation that caused it are dispatched in one task, in either order, so the decision waits one task and asks.
// A Stop, Escape or window.stop() aborts alone.
//
// `watched` is the signal of the load the mark belongs to, and the latest cross-document navigation takes it over.
// A same-document navigation leaves the mark as it is: the load it aborted goes on, and nothing in the page can
// say whether it is cancelled later (the one case this leaves open: Stop after a same-document navigation keeps
// the mark, and a sign-in then ends its own session and resets its form, see useCompleteSignIn).
let watched: AbortSignal | null = null;
let navigateSeq = 0;
let navigateThisTask = false;

function noteNavigate() {
  navigateSeq += 1;
  if (navigateThisTask) return;
  navigateThisTask = true;
  setTimeout(() => {
    navigateThisTask = false;
  }, 0);
}

function watchLoad(signal: AbortSignal) {
  watched = signal;
  signal.addEventListener(
    "abort",
    () => {
      // The event came first (flag) or comes later in this task (counter): another navigation took over.
      const supersededAlready = navigateThisTask;
      const seen = navigateSeq;
      setTimeout(() => {
        if (!supersededAlready && seen === navigateSeq && watched === signal) {
          watched = null;
          clear();
        }
      }, 0);
    },
    {once: true},
  );
}

function onNavigate(event: Event) {
  noteNavigate();
  if (!leaving) return;
  const {signal, destination} = event as NavigateEventLike;
  if (destination?.sameDocument) return;
  if (signal) watchLoad(signal);
}

function watchInput() {
  const onInput = () => {
    window.removeEventListener("pointerdown", onInput, true);
    window.removeEventListener("keydown", onInput, true);
    clear();
  };
  window.addEventListener("pointerdown", onInput, true);
  window.addEventListener("keydown", onInput, true);
}

let navigationWatched: NavigationLike | null = null;

export function markPageLeaving() {
  leaving = true;
  if (typeof window === "undefined") return;
  if (!watching) {
    watching = true;
    // A page restored from the back/forward cache is a live page again.
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) {
        watched = null;
        clear();
      }
    });
  }
  const navigation = (window as unknown as {navigation?: NavigationLike}).navigation;
  if (navigation && typeof navigation.addEventListener === "function") {
    // One listener for the life of the page; it acts only while a mark is set.
    if (navigationWatched !== navigation) {
      navigationWatched = navigation;
      navigation.addEventListener("navigate", onNavigate);
    }
  } else if (typeof window.addEventListener === "function") watchInput();
}

export const isPageLeaving = () => leaving;

/** Test hook: a unit test starts each case on a page that is not leaving. */
export function resetPageLeaving() {
  leaving = false;
  watched = null;
}
