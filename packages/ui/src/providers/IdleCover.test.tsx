import {ADMIN_IDLE_PAUSE_MS, ADMIN_SESSION_IDLE_MS, getIdleState, holdSignedInSurface, watchActivity, type SharedPresence} from "@ctrlz/api-client/activity.ts";
import {QueryClient} from "@tanstack/react-query";
import {NextIntlClientProvider} from "next-intl";
import {renderToString} from "react-dom/server";
import {afterEach, describe, expect, it, vi} from "vitest";

// renderToString runs no effect and attaches no ref, so both are stood in for. Only IdleCover's own
// useEffect and useRef are replaced: HeroUI is an external dependency and keeps the real ones.
const hooks = vi.hoisted(() => ({
  effects: [] as Array<{effect: () => unknown; deps: unknown[] | undefined}>,
  refs: [] as Array<{current: {focus: () => void}}>,
}));

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useEffect: (effect: () => unknown, deps?: unknown[]) => void hooks.effects.push({effect, deps}),
  useRef: () => {
    const ref = {current: {focus: vi.fn()}};
    hooks.refs.push(ref);
    return ref;
  },
}));

import {AppContextProvider} from "./appContext.tsx";
import {IdleCover} from "./IdleCover.tsx";

const messages = {errors: {idle: {title: "Hidden", text: "Press Continue.", continue: "Continue", adminText: "The session ended."}}};
const MIN = 60_000;

afterEach(() => {
  hooks.effects.length = 0;
  hooks.refs.length = 0;
  vi.useRealTimers();
});

/** One render of the cover as an admin tab, the effects run by hand. Returns what got focus: the button is the first ref, the main element the second. */
function renderAdmin() {
  hooks.effects.length = 0;
  hooks.refs.length = 0;
  const html = renderToString(
    <NextIntlClientProvider locale="en" messages={messages}>
      <AppContextProvider value="admin">
        <IdleCover />
      </AppContextProvider>
    </NextIntlClientProvider>,
  );
  const mine = hooks.effects.filter((e) => e.deps?.length === 1);
  for (const {effect} of mine) effect();
  const [button, main] = hooks.refs;
  return {
    html,
    deps: mine.map((e) => e.deps),
    buttonFocused: vi.mocked(button?.current.focus as () => void).mock.calls.length > 0,
    mainFocused: vi.mocked(main?.current.focus as () => void).mock.calls.length > 0,
  };
}

// wp4-r11-2: a covered admin tab that showed Continue while another tab was in use. When that tab's recheck
// ends the session, the focused button unmounts and the keyboard focus would fall to <body>.
describe("IdleCover keeps the keyboard focus when the session ends under it (wp4-r11-2)", () => {
  it("Continue has focus while the session is live, and the status line's container gets it once the session ends", () => {
    vi.useFakeTimers();
    let stored: number | undefined;
    const shared: SharedPresence = {read: () => stored, write: (ms) => void (stored = ms)};
    const release = holdSignedInSurface();
    const stop = watchActivity(new QueryClient(), {addEventListener: () => undefined, removeEventListener: () => undefined}, {idleMs: ADMIN_IDLE_PAUSE_MS, coverMs: ADMIN_SESSION_IDLE_MS, shared});
    vi.advanceTimersByTime(10 * MIN);
    stored = Date.now(); // another tab, which is then closed
    vi.advanceTimersByTime(5 * MIN + 1_000);
    expect(getIdleState()).toMatchObject({covered: true, ending: false});

    const live = renderAdmin();
    expect(live.html).toContain("Continue");
    expect(live.buttonFocused).toBe(true);
    expect(live.mainFocused).toBe(false);

    vi.advanceTimersByTime(10 * MIN);
    expect(getIdleState()).toMatchObject({covered: true, ending: true});
    const ended = renderAdmin();
    expect(ended.html).toContain("The session ended.");
    expect(ended.html).not.toContain("Continue");
    expect(ended.mainFocused).toBe(true);
    // The effect depends on what is shown, so React runs it again when the button goes away.
    expect(ended.deps).not.toEqual(live.deps);
    release();
    stop();
  });
});
