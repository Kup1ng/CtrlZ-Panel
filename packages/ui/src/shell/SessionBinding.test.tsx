import {ApiError} from "@ctrlz/api-client/errors.ts";
import {handleSessionEnded, clearLeaving} from "@ctrlz/api-client/session.ts";
import {NextIntlClientProvider} from "next-intl";
import {renderToString} from "react-dom/server";
import {afterEach, describe, expect, it, vi} from "vitest";

// No DOM and no effects in renderToString, so useEffect is collected and run by hand (see AppProviders.test.tsx).
const effects = vi.hoisted(() => [] as Array<() => unknown>);
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useEffect: (effect: () => unknown) => void effects.push(effect),
}));

import {AppContextProvider} from "../providers/appContext.tsx";
import {SessionBinding} from "./SessionBinding.tsx";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";

afterEach(() => {
  effects.length = 0;
  clearLeaving();
  vi.unstubAllGlobals();
});

function mount(app: "panel" | "admin", pathname = "/fa/suspended") {
  const assign = vi.fn();
  const listened: string[] = [];
  vi.stubGlobal("window", {
    location: {assign, pathname, search: ""},
    addEventListener: (type: string) => void listened.push(type),
    removeEventListener: () => undefined,
  });
  vi.stubGlobal("sessionStorage", {getItem: () => null, setItem: () => undefined, removeItem: () => undefined});
  const queryClient = new QueryClient();
  const html = renderToString(
    <QueryClientProvider client={queryClient}>
      <NextIntlClientProvider locale="fa" messages={{}}>
        <AppContextProvider value={app}>
          <SessionBinding />
        </AppContextProvider>
      </NextIntlClientProvider>
    </QueryClientProvider>,
  );
  for (const effect of effects) effect();
  return {html, assign, listened, queryClient};
}

// wp4-r5-4: /change-password, /suspended and /setup live outside SessionGate. A page that mounts this
// is still bound to the session.
describe("SessionBinding, for a signed-in page outside the shell", () => {
  it("renders nothing", () => {
    expect(mount("panel").html).toBe("");
    expect(mount("admin").html).toBe("");
  });

  it("panel: a refused refresh leaves for the login page", () => {
    const {assign} = mount("panel");
    handleSessionEnded();
    expect(assign).toHaveBeenCalledWith("/fa/login");
  });

  it("panel and admin: a page restored from the back/forward cache is reloaded", () => {
    expect(mount("panel").listened).toContain("pageshow");
    effects.length = 0;
    expect(mount("admin").listened).toContain("pageshow");
  });

  // wp4-r6-4: /setup is outside AdminGate, and admin has no middleware, so a 401 session_expired of any
  // admin call is seen in the cache. The one-time password, the TOTP secret and the recovery codes of
  // /setup must not stay on screen over a dead session.
  it("admin: a call that answers 401 session_expired leaves for the login page with the ended marker", async () => {
    const {assign, queryClient} = mount("admin", "/fa/setup");
    // The page has had a session (a first call that answered), so the notice is true (gate-r33-11).
    await queryClient.fetchQuery({queryKey: ["admin", "me"], queryFn: () => Promise.resolve({username: "root"})});
    await queryClient
      .fetchQuery({queryKey: ["admin", "totp"], queryFn: () => Promise.reject(new ApiError(401, "session_expired")), retry: false})
      .catch(() => undefined);
    await new Promise((r) => setTimeout(r, 0));
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign.mock.calls[0]![0]).toBe("/fa/login?next=%2Fsetup&ended=1");
  });

  it("admin: a first call that answers 401 on a page with no session leaves without the ended marker", async () => {
    const {assign, queryClient} = mount("admin", "/fa/setup");
    await queryClient
      .fetchQuery({queryKey: ["admin", "me"], queryFn: () => Promise.reject(new ApiError(401, "session_expired")), retry: false})
      .catch(() => undefined);
    await new Promise((r) => setTimeout(r, 0));
    expect(assign.mock.calls[0]![0]).toBe("/fa/login?next=%2Fsetup");
  });

  it("admin: another error of the same call does not leave", async () => {
    const {assign, queryClient} = mount("admin", "/fa/setup");
    await queryClient
      .fetchQuery({queryKey: ["admin", "totp"], queryFn: () => Promise.reject(new ApiError(422, "totp_invalid")), retry: false})
      .catch(() => undefined);
    await new Promise((r) => setTimeout(r, 0));
    expect(assign).not.toHaveBeenCalled();
  });
});
