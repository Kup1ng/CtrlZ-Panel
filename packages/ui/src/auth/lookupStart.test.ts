import {readFileSync} from "node:fs";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {createLookupStart} from "./lookupStart.ts";

describe("the invite page starts one lookup per link (gate-r31, wp8-r6-2)", () => {
  it("lets a stale effect claim only the number it was made for, so the new link keeps its turn", () => {
    const start = createLookupStart();
    // Link 0 is taken on load and its effect starts the lookup.
    expect(start.claim(0)).toBe(true);
    // The second link is pasted: the state moves to 1, but the effect queued by the render that held link 0 runs first.
    expect(start.claim(0)).toBe(false);
    // The render with link 1 then runs its own effect and the second lookup starts.
    expect(start.claim(1)).toBe(true);
    // Rendering again with link 1 (a pending flag, a config answer) does not start a third.
    expect(start.claim(1)).toBe(false);
  });

  it("a link taken again after the first one was looked up is a new number and is looked up again", () => {
    const start = createLookupStart();
    expect(start.claim(0)).toBe(true);
    expect(start.claim(1)).toBe(true);
  });

  it("the page moves the number in state and never resets a lookup flag from outside React", () => {
    const source = readFileSync(path.resolve(import.meta.dirname, "InviteFlow.tsx"), "utf8");
    expect(source).toMatch(/setLinkSeq\(\(n\) => n \+ 1\)/);
    expect(source).toMatch(/lookupStart\.claim\(linkSeq\)/);
    expect(source).not.toMatch(/lookedUp/);
    // The effect lists the stable `run`, not the object that `useLookup` makes anew on every render.
    expect(source).toMatch(/\[phase, token, linkSeq, run, lookupStart\]/);
  });
});
