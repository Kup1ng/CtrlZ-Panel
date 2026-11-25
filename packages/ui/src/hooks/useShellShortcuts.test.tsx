import {renderToString} from "react-dom/server";
import {afterEach, describe, expect, it, vi} from "vitest";

// No DOM and no effects in renderToString, so useEffect is collected and run by hand (see SessionBinding.test.tsx).
const effects = vi.hoisted(() => [] as Array<() => unknown>);
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useEffect: (effect: () => unknown) => void effects.push(effect),
}));

import {useShellShortcuts} from "./useShellShortcuts.ts";

afterEach(() => {
  effects.length = 0;
  vi.unstubAllGlobals();
});

type Present = {role: "dialog" | "alertdialog"; toast?: boolean; navSheet?: boolean};

// A stand-in for querySelector that reads the selector the hook really sends: a comma list of `[role="x"]` clauses, each with an optional
// `:not([data-slot="toast"])` and `:not(.sidebar__mobile-dialog)`. A clause it does not know fails the test, so the selector cannot drift into something this does not model.
function querySelector(present: Present[]) {
  return (selector: string) => {
    for (const clause of selector.split(",").map((c) => c.trim())) {
      const match = /^\[role="(dialog|alertdialog)"\](:not\(\[data-slot="toast"\]\))?(:not\(\.sidebar__mobile-dialog\))?$/.exec(clause);
      if (!match) throw new Error(`unmodelled selector clause: ${clause}`);
      const [, role, notToast, notSheet] = match;
      if (present.some((el) => el.role === role && !(notToast && el.toast) && !(notSheet && el.navSheet))) return {};
    }
    return null;
  };
}

function press(code: "KeyK" | "KeyB", present: Present[]) {
  const openPalette = vi.fn();
  const toggleSidebar = vi.fn();
  let listener: ((e: unknown) => void) | undefined;
  vi.stubGlobal("document", {
    addEventListener: (_type: string, fn: (e: unknown) => void) => (listener = fn),
    removeEventListener: () => undefined,
    querySelector: querySelector(present),
  });
  function Probe() {
    useShellShortcuts({openPalette, toggleSidebar});
    return null;
  }
  renderToString(<Probe />);
  for (const effect of effects) effect();
  const event = {code, ctrlKey: true, defaultPrevented: false, preventDefault: vi.fn(), isComposing: false};
  listener!(event);
  return {event, openPalette, toggleSidebar};
}

describe("useShellShortcuts mod+k", () => {
  it("opens the palette on a page with no dialog", () => {
    expect(press("KeyK", []).openPalette).toHaveBeenCalledTimes(1);
  });

  // gate-r33-7: the palette's pick is a router push that no leave guard sees, so over a dialog that holds a one-time secret it would lose it.
  it("does not open it over a dialog or an alert dialog, and still takes the key", () => {
    for (const role of ["dialog", "alertdialog"] as const) {
      const {event, openPalette} = press("KeyK", [{role}]);
      expect(event.preventDefault).toHaveBeenCalled();
      expect(openPalette).not.toHaveBeenCalled();
    }
  });

  // gate-r34-1: a toast is an alertdialog with aria-modal=false, and the page behind it is usable.
  it("opens it while a toast is on screen", () => {
    expect(press("KeyK", [{role: "alertdialog", toast: true}]).openPalette).toHaveBeenCalledTimes(1);
  });

  it("opens it while the mobile nav sheet is open, which holds nothing a jump could drop (gate-r35-6)", () => {
    expect(press("KeyK", [{role: "dialog", navSheet: true}]).openPalette).toHaveBeenCalledTimes(1);
  });

  it("does not open it over a real dialog that has a toast beside it", () => {
    expect(press("KeyK", [{role: "alertdialog", toast: true}, {role: "dialog"}]).openPalette).not.toHaveBeenCalled();
  });
});

describe("useShellShortcuts mod+b", () => {
  it("toggles the sidebar on a page with no dialog, and while a toast is on screen", () => {
    expect(press("KeyB", []).toggleSidebar).toHaveBeenCalledTimes(1);
    expect(press("KeyB", [{role: "alertdialog", toast: true}]).toggleSidebar).toHaveBeenCalledTimes(1);
  });

  // gate-r34-5: below 48rem the toggle opens the mobile nav sheet, whose links are router pushes that no leave guard sees.
  it("does not toggle it over a dialog, and still takes the key", () => {
    const {event, toggleSidebar} = press("KeyB", [{role: "dialog"}]);
    expect(event.preventDefault).toHaveBeenCalled();
    expect(toggleSidebar).not.toHaveBeenCalled();
  });

  // gate-r35-1 to 7: the mobile nav sheet is a role=dialog itself, and the key that opened it has to close it.
  it("toggles it while the only dialog is the mobile nav sheet, and not while another dialog is open beside it", () => {
    expect(press("KeyB", [{role: "dialog", navSheet: true}]).toggleSidebar).toHaveBeenCalledTimes(1);
    expect(press("KeyB", [{role: "dialog", navSheet: true}, {role: "dialog"}]).toggleSidebar).not.toHaveBeenCalled();
  });
});
