import {existsSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {describe, expect, it} from "vitest";

import {endpointHref, endpointIdOf, endpointTabOf, ENDPOINT_TABS} from "../endpoints/endpointRoutes.ts";
import {folderHref, profileHref, profileIdOf, profileTabOf, switchProfileHref, thirdPartyHref} from "../profiles/profileRoutes.ts";
import {PANEL_ROUTES, listRoutes, withoutLocale} from "../testing/routes.ts";
import {FRAME_PARTS, NAMESPACE_LANES, SCREENS} from "./lanes.ts";

const ui = join(import.meta.dirname, "..");
const app = join(import.meta.dirname, "../../../../apps/panel/src/app/[locale]");
const ID = "6f1c1b0e-8f35-4d57-9b8f-1d1c2a3b4c5d";

describe("the lanes' screens", () => {
  it("has a component file, with the export it names, for every screen and every frame part", () => {
    for (const s of [...SCREENS, ...FRAME_PARTS]) {
      const file = join(ui, s.file);
      expect(existsSync(file), s.file).toBe(true);
      expect(readFileSync(file, "utf8"), s.file).toMatch(new RegExp(`export function ${s.component}\\b`));
    }
  });

  it("mounts every frame part in each frame that lanes.ts names, so a dialog a header opens has somewhere to draw", () => {
    for (const part of FRAME_PARTS) {
      for (const file of part.mountedBy) {
        expect(existsSync(join(ui, file)), file).toBe(true);
        // The frames are the foundation's and carry the element today; a list screen is the lane's body and may still be a stub.
        if (file.endsWith("Frame.tsx")) expect(readFileSync(join(ui, file), "utf8"), `${file} mounts ${part.component}`).toMatch(new RegExp(`<${part.component}\\b`));
      }
    }
  });

  it("has a page for every screen, and the page renders that component and no other of the lanes", () => {
    for (const s of SCREENS) {
      const page = join(app, s.page);
      expect(existsSync(page), s.page).toBe(true);
      const source = readFileSync(page, "utf8");
      expect(source, s.page).toContain(`@ctrlz/ui/${s.file}`);
      expect(source, s.page).toContain(`<${s.component}`);
    }
  });

  it("puts every route of a lane in the route allowlist, and no route in two lanes", () => {
    const routes = SCREENS.map((s) => s.route);
    expect(new Set(routes).size).toBe(routes.length);
    for (const route of routes) expect(PANEL_ROUTES as readonly string[], route).toContain(route);
  });

  it("covers every page of the app that is a screen: a page with a route of P2 or P3 is in the list or is a frame redirect", () => {
    const redirects = new Set(["/profiles/[id]", "/endpoints/[id]"]);
    const listed = new Set(SCREENS.map((s) => s.route));
    const shown = listRoutes(app).map(withoutLocale);
    for (const route of shown) {
      if (/^\/(profiles|endpoints|s|docs|status)(\/|$)/.test(route) || route === "/preferences/api") {
        expect(listed.has(route) || redirects.has(route), route).toBe(true);
      }
    }
  });

  it("gives every screen a stub that carries its data-screen, until its lane fills it", () => {
    for (const s of SCREENS) {
      const source = readFileSync(join(ui, s.file), "utf8");
      // A lane that has filled the screen no longer has the stub, and this line is the one it deletes with it.
      if (source.includes("screens/LaneStub")) expect(source, s.file).toContain(`screen="${s.screen}"`);
    }
  });

  it("names a lane for the namespaces the lanes write into", () => {
    expect(Object.keys(NAMESPACE_LANES).sort()).toEqual(["api", "endpoints", "jobs", "profiles", "rules", "services", "setup"]);
  });
});

describe("profile routes", () => {
  it("builds the path of each tab by id, never by name", () => {
    expect(profileHref(ID, "filters")).toBe(`/profiles/${ID}/filters`);
    expect(profileHref(ID, "rules")).toBe(`/profiles/${ID}/custom-rules`);
    expect(profileHref(ID)).toBe(`/profiles/${ID}/options`);
    expect(thirdPartyHref(ID)).toBe(`/profiles/${ID}/filters/third-party`);
    expect(folderHref(ID, "f1")).toBe(`/profiles/${ID}/custom-rules/f1`);
  });

  it("reads the tab and the id back from a path, and treats a sub-page as its tab", () => {
    expect(profileTabOf(`/profiles/${ID}/filters`)).toBe("filters");
    expect(profileTabOf(`/profiles/${ID}/filters/third-party`)).toBe("filters");
    expect(profileTabOf(`/profiles/${ID}/custom-rules/f1`)).toBe("rules");
    expect(profileTabOf(`/profiles/${ID}`)).toBeNull();
    expect(profileTabOf("/profiles")).toBeNull();
    expect(profileTabOf(`/profiles/${ID}/other`)).toBeNull();
    expect(profileIdOf(`/profiles/${ID}/services`)).toBe(ID);
    expect(profileIdOf("/profiles")).toBeNull();
  });

  it("opens the same tab of another profile, and Options when there is no tab, and drops a folder", () => {
    const other = "11111111-1111-4111-8111-111111111111";
    expect(switchProfileHref(`/profiles/${ID}/services`, other)).toBe(`/profiles/${other}/services`);
    expect(switchProfileHref(`/profiles/${ID}/custom-rules/f1`, other)).toBe(`/profiles/${other}/custom-rules`);
    expect(switchProfileHref(`/profiles/${ID}`, other)).toBe(`/profiles/${other}/options`);
  });
});

describe("endpoint routes", () => {
  it("builds and reads the tabs, and does not take `export` for an id", () => {
    for (const tab of ENDPOINT_TABS) {
      expect(endpointHref(ID, tab)).toBe(`/endpoints/${ID}/${tab}`);
      expect(endpointTabOf(`/endpoints/${ID}/${tab}`)).toBe(tab);
    }
    expect(endpointHref(ID)).toBe(`/endpoints/${ID}/clients`);
    expect(endpointTabOf(`/endpoints/${ID}`)).toBeNull();
    expect(endpointIdOf(`/endpoints/${ID}/ips`)).toBe(ID);
    expect(endpointIdOf("/endpoints/export")).toBeNull();
    expect(endpointIdOf("/endpoints")).toBeNull();
  });
});
