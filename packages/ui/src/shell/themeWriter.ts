import type {ThemeMode} from "../theme/config.ts";

// Spec 5.1. The theme write of the gate. Two quick switches must end on the last choice, in the
// page, the cookie and the server alike (wp4-r6-2). Two things went wrong when each switch sent
// its own PATCH and every answer was adopted as "the server's theme":
//  - the answer to the first PATCH carries the first choice, which is no longer the current mode,
//    so adopting it flips the page back for a moment, and
//  - two PATCHes in flight can be answered, or applied by the server, in either order.
// So at most one PATCH is in flight, a choice made meanwhile replaces the one waiting (only the
// last matters), and the server's theme is adopted only while nothing is in flight or waiting.
//
// A write that fails (T-308). The page had already taken the choice and the cookie with it, and the server still held the
// old theme, so the next load would adopt the server's and flip the page back without a word. The rule is that THE SERVER
// WINS: the account is the one source across devices and the cookie is only a cache of it. So when the last choice could not
// be saved, the page goes back at once to the theme the server holds, and `onWriteFailed` says so, with the reason. A choice
// that a later choice replaced, or that failed before a later one succeeded, says nothing: the later one decided.

export type ThemeWriter = {
  /** The user chose `mode`. Sends it now, or after the PATCH in flight, unless a later choice replaces it. */
  request: (mode: ThemeMode) => void;
  /** Applies the theme `/me` carries to the page, unless a write of ours is in flight or waiting: our own choice wins. */
  adopt: (serverMode: ThemeMode) => void;
  /** A write is in flight or waiting. */
  readonly busy: boolean;
};

export function createThemeWriter({
  write,
  adoptServerMode,
  onWriteFailed,
}: {
  /** Sends one `PATCH /account/preferences {theme}`. A rejection of the last choice puts the server's theme back and is reported. */
  write: (mode: ThemeMode) => Promise<unknown>;
  adoptServerMode: (mode: ThemeMode) => void;
  /** The last choice was not saved: `error` is the rejection, `restored` the theme the page went back to (the server's). */
  onWriteFailed?: (error: unknown, restored: ThemeMode | undefined) => void;
}): ThemeWriter {
  let waiting: ThemeMode | undefined;
  let running = false;
  // The theme the server holds, as far as this tab knows: what it last adopted or what its last successful write saved.
  let known: ThemeMode | undefined;

  async function drain() {
    running = true;
    let failure: {error: unknown} | undefined;
    try {
      while (waiting !== undefined) {
        const mode = waiting;
        waiting = undefined;
        try {
          await write(mode);
          known = mode;
          failure = undefined;
        } catch (error) {
          // A failed write is not retried and does not stop the choice that came after it.
          failure = {error};
        }
      }
    } finally {
      running = false;
    }
    if (failure) {
      if (known !== undefined) adoptServerMode(known);
      onWriteFailed?.(failure.error, known);
    }
  }

  return {
    request(mode) {
      waiting = mode;
      if (!running) void drain();
    },
    adopt(serverMode) {
      if (running || waiting !== undefined) return;
      known = serverMode;
      adoptServerMode(serverMode);
    },
    get busy() {
      return running || waiting !== undefined;
    },
  };
}
