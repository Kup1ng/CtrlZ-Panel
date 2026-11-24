import type {ThemeMode} from "../theme/config.ts";

// Spec 5.1. The theme write of the gate. Two quick switches must end on the last choice, in the
// page, the cookie and the server alike (wp4-r6-2). Two things went wrong when each switch sent
// its own PATCH and every answer was adopted as "the server's theme":
//  - the answer to the first PATCH carries the first choice, which is no longer the current mode,
//    so adopting it flips the page back for a moment, and
//  - two PATCHes in flight can be answered, or applied by the server, in either order.
// So at most one PATCH is in flight, a choice made meanwhile replaces the one waiting (only the
// last matters), and the server's theme is adopted only while nothing is in flight or waiting.

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
}: {
  /** Sends one `PATCH /account/preferences {theme}`. A rejection is dropped: the page keeps the choice. */
  write: (mode: ThemeMode) => Promise<unknown>;
  adoptServerMode: (mode: ThemeMode) => void;
}): ThemeWriter {
  let waiting: ThemeMode | undefined;
  let running = false;

  async function drain() {
    running = true;
    try {
      while (waiting !== undefined) {
        const mode = waiting;
        waiting = undefined;
        try {
          await write(mode);
        } catch {
          // A failed write is not retried and does not stop the choice that came after it.
        }
      }
    } finally {
      running = false;
    }
  }

  return {
    request(mode) {
      waiting = mode;
      if (!running) void drain();
    },
    adopt(serverMode) {
      if (!running && waiting === undefined) adoptServerMode(serverMode);
    },
    get busy() {
      return running || waiting !== undefined;
    },
  };
}
