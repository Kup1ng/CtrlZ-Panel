import {ADMIN_IDLE_PAUSE_MS, ADMIN_PRESENCE_KEY, ADMIN_SESSION_IDLE_MS, holdSignedInSurface, IDLE_PAUSE_MS, isUserPresent, SESSION_IDLE_MS} from "@ctrlz/api-client/activity.ts";
import {NextIntlClientProvider} from "next-intl";
import {renderToString} from "react-dom/server";
import {afterEach, describe, expect, it, vi} from "vitest";

// renderToString runs no effect, and there is no DOM here, so useEffect is collected and run by hand.
// The effects of the libraries below AppProviders are collected too: they may throw without a document,
// and only the presence window matters to this test.
const effects = vi.hoisted(() => [] as Array<() => unknown>);

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useEffect: (effect: () => unknown) => void effects.push(effect),
}));
vi.mock("@ctrlz/i18n/navigation.ts", () => ({useRouter: () => ({push: () => undefined})}));

import {AppProviders} from "./AppProviders.tsx";
import {useApp} from "./appContext.tsx";

// What the effects returned: each mount arms the activity watch, which must be stopped.
const stops: Array<() => void> = [];

afterEach(() => {
  for (const stop of stops.splice(0)) stop();
  effects.length = 0;
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** Mounts AppProviders for one app, runs its effects against a window that records nothing, and returns what is below it saw. */
function mount(app: "panel" | "admin") {
  vi.stubGlobal("window", {addEventListener: () => undefined, removeEventListener: () => undefined});
  const seen: string[] = [];
  function Probe() {
    seen.push(useApp());
    return null;
  }
  renderToString(
    <AppProviders app={app} locale="en">
      <Probe />
    </AppProviders>,
  );
  for (const effect of effects) {
    try {
      const stop = effect();
      if (typeof stop === "function") stops.push(stop as () => void);
    } catch {
      // A library effect that needs a document: not what is under test.
    }
  }
  return seen;
}

describe("AppProviders gives each app its own presence window (wp4-r4-3)", () => {
  // A later edit that drops `idleMs`, or ignores `app`, would put the admin console back at the panel's
  // 30 minutes, twice its 15-minute idle limit, with every other test still green.
  it("the admin console stops counting as present after 5 minutes, the panel after 30", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-14T10:00:00Z"));
    mount("admin");
    vi.advanceTimersByTime(ADMIN_IDLE_PAUSE_MS - 1_000);
    expect(isUserPresent()).toBe(true);
    vi.advanceTimersByTime(2_000);
    expect(isUserPresent()).toBe(false);

    effects.length = 0;
    mount("panel");
    vi.advanceTimersByTime(ADMIN_IDLE_PAUSE_MS + 1_000);
    expect(isUserPresent()).toBe(true);
    vi.advanceTimersByTime(IDLE_PAUSE_MS - ADMIN_IDLE_PAUSE_MS);
    expect(isUserPresent()).toBe(false);
  });
});

describe("the app comes from AppProviders (wp4-r5-9)", () => {
  it("is what the parts below read", () => {
    expect(mount("admin")).toEqual(["admin"]);
    expect(mount("panel")).toEqual(["panel"]);
  });

  it("is not guessed: without a provider the hook throws instead of falling back to the panel", () => {
    function Bare() {
      useApp();
      return null;
    }
    expect(() => renderToString(<Bare />)).toThrow(/AppProviders/);
  });
});

// wp4-r6-3: past the session's idle limit with no input, nothing of the page may stay on screen.
describe("AppProviders covers the page after the session's idle limit (wp4-r6-3)", () => {
  const messages = {errors: {idle: {title: "Hidden for your security", text: "Press Continue.", continue: "Continue", adminText: "The session ended. Taking you to sign in."}}};

  function render(app: "panel" | "admin", seen: string[]) {
    function Page() {
      seen.push(useApp());
      return <p>the user list</p>;
    }
    return renderToString(
      <NextIntlClientProvider locale="en" messages={messages}>
        <AppProviders app={app} locale="en">
          <Page />
        </AppProviders>
      </NextIntlClientProvider>,
    );
  }

  it("shows the cover instead of the page, per app: 15 minutes for the admin console, 2 hours for the panel", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-14T10:00:00Z"));
    vi.stubGlobal("window", {addEventListener: () => undefined, removeEventListener: () => undefined});
    const release = holdSignedInSurface();

    const cleanups: Array<() => void> = [];
    const run = (app: "panel" | "admin") => {
      effects.length = 0;
      render(app, []);
      for (const effect of effects) {
        try {
          const cleanup = effect();
          if (typeof cleanup === "function") cleanups.push(cleanup as () => void);
        } catch {
          // A library effect that needs a document: not what is under test.
        }
      }
    };

    run("admin");
    expect(render("admin", [])).toContain("the user list");
    vi.advanceTimersByTime(ADMIN_SESSION_IDLE_MS + 1_000);
    const seen: string[] = [];
    const html = render("admin", seen);
    // The admin console has no way back from a cover: its guard ends the session and loads the login
    // page, so there is no Continue to press, a reload or a passer-by cannot revive it (wp4-r8-4).
    expect(html).toContain("Taking you to sign in");
    expect(html).not.toContain("Continue");
    expect(html).not.toContain("the user list");
    expect(seen).toEqual([]);
    for (const c of cleanups.splice(0)) c();

    run("panel");
    vi.advanceTimersByTime(ADMIN_SESSION_IDLE_MS + 1_000);
    expect(render("panel", [])).toContain("the user list");
    vi.advanceTimersByTime(SESSION_IDLE_MS - ADMIN_SESSION_IDLE_MS);
    const panelCover = render("panel", []);
    expect(panelCover).toContain("Hidden for your security");
    // Something to activate: only a press on it brings the page back (wp4-r7-1).
    expect(panelCover).toContain("Continue");
    expect(panelCover).not.toContain("the user list");
    for (const c of cleanups.splice(0)) c();
    release();
  });

  // wp4-r9-3: the admin session is shared by every admin tab, so a background tab covered by its own clock
  // must not end it while another tab is in use. It is hidden all the same, and Continue is offered.
  it("admin: a tab covered while another admin tab is in use hides the page but offers Continue", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-14T10:00:00Z"));
    const data = new Map<string, string>();
    vi.stubGlobal("window", {
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      localStorage: {getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v)},
    });
    const release = holdSignedInSurface();
    effects.length = 0;
    render("admin", []);
    const cleanups: Array<() => void> = [];
    for (const effect of effects) {
      try {
        const cleanup = effect();
        if (typeof cleanup === "function") cleanups.push(cleanup as () => void);
      } catch {
        // A library effect that needs a document: not what is under test.
      }
    }
    // The key is the one the admin tabs share; the other tab wrote it at minute 10.
    vi.advanceTimersByTime(10 * 60_000);
    data.set(ADMIN_PRESENCE_KEY, String(Date.now()));
    vi.advanceTimersByTime(5 * 60_000 + 1_000);
    const html = render("admin", []);
    expect(html).toContain("Hidden for your security");
    expect(html).toContain("Continue");
    expect(html).not.toContain("Taking you to sign in");
    expect(html).not.toContain("the user list");
    for (const c of cleanups) c();
    release();
  });
});
