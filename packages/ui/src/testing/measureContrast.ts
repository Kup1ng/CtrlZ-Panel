import type {Locator} from "@playwright/test";

import {contrastRatio, type Rgb} from "./axeLogic.ts";

// Contrast of what the page really paints, for the states axe cannot decide (a pointer on a button, a tab over its own indicator, a ten pixel
// digit): the foreground and the background are the computed colours, turned into sRGB by a canvas (the tokens are oklch, so the computed value
// may be lab(), oklch() or color-mix()), and a translucent layer is composited over the ones behind it. The ratio is WCAG 2.x, the same
// function as the accent pair. A wait for a transition to settle is the caller's: this reads one instant.
//
// What it reads, and what it does not. It composites background-color layers up the ancestor chain, then the colour (the text colour, or the
// colour of the top border with `part: "border"`, for a ring that must reach 3:1, WCAG 1.4.11). It does not model text-shadow, filters or
// backdrop-filter, and it cannot compose opacity, because an element's opacity fades its fill and its text together. So it waits up to
// two seconds for the target and its ancestors to reach opacity 1 (a fade-in), and throws if they do not, instead of returning a ratio that the
// pixels do not meet.

export type Measured = {fg: Rgb; bg: Rgb; ratio: number};

/**
 * @param target the element that holds the text
 * @param options.part what is measured: the text colour (default) or the colour of the top border of the target, a ring or an outline
 * @param options.bg an element whose fill is what the text sits on, when it is not an ancestor of the text (a tab indicator, which is
 *   a sibling painted behind it). Without it the background is the first opaque fill up the ancestors, the target's own included.
 */
export async function measureContrast(target: Locator, options: {bg?: Locator; part?: "text" | "border"} = {}): Promise<Measured> {
  // An element that is fading in (an input's digit, a dialog) has an opacity below 1 for a few frames: wait for it to end, then refuse.
  const deadline = Date.now() + 2000;
  for (;;) {
    const read = await readOnce(target, options);
    if (!read.faded) return read.measured;
    if (Date.now() >= deadline) {
      throw new Error(`measureContrast: the target or an ancestor still has opacity ${read.faded.toFixed(2)} after 2 s, so the painted contrast is not what is computed here`);
    }
    await target.page().waitForTimeout(50);
  }
}

async function readOnce(target: Locator, options: {bg?: Locator; part?: "text" | "border"}): Promise<{measured: Measured; faded: number}> {
  const bgHandle = options.bg ? await options.bg.elementHandle() : null;
  const part = options.part ?? "text";
  const [fg, bg, faded] = await target.evaluate((el, [bgEl, what]) => {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const probe = canvas.getContext("2d", {willReadFrequently: true})!;
    // Straight (not premultiplied) RGBA of any CSS colour. A 1x1 fill of a translucent colour loses precision in 8 bits, so alpha is read
    // from the colour drawn over black and over white instead of from the alpha channel.
    const rgba = (css: string): [number, number, number, number] => {
      const over = (base: string) => {
        probe.fillStyle = base;
        probe.fillRect(0, 0, 1, 1);
        probe.fillStyle = css;
        probe.fillRect(0, 0, 1, 1);
        const d = probe.getImageData(0, 0, 1, 1).data;
        return [d[0]!, d[1]!, d[2]!];
      };
      const onBlack = over("#000");
      const onWhite = over("#fff");
      // black: c*a ; white: c*a + 255*(1-a)  =>  a = 1 - (white - black) / 255
      const a = Math.min(1, Math.max(0, 1 - (onWhite[0]! - onBlack[0]!) / 255));
      if (a === 0) return [0, 0, 0, 0];
      return [onBlack[0]! / a, onBlack[1]! / a, onBlack[2]! / a, a];
    };
    const blend = (top: number[], under: number[]): [number, number, number, number] => {
      const a = top[3]! + under[3]! * (1 - top[3]!);
      if (a === 0) return [0, 0, 0, 0];
      return [0, 1, 2].map((i) => (top[i]! * top[3]! + under[i]! * under[3]! * (1 - top[3]!)) / a).concat(a) as [number, number, number, number];
    };
    const fillsFrom = (start: Element | null) => {
      const layers: number[][] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = rgba(getComputedStyle(n).backgroundColor);
        if (c[3]! > 0) layers.push(c);
        if (c[3]! >= 1) break;
      }
      // The canvas of the page is white when nothing opaque is found.
      layers.push([255, 255, 255, 1]);
      return layers.reduceRight((under, top) => blend(top, under) as number[]);
    };
    const back = fillsFrom(bgEl ?? el);
    let opacity = 1;
    for (let n: Element | null = el; n; n = n.parentElement) opacity *= Number(getComputedStyle(n).opacity);
    const style = getComputedStyle(el);
    const fgRaw = rgba(what === "border" ? style.borderTopColor : style.color);
    const front = blend(fgRaw, back);
    const round = (c: number[]): number[] => [Math.round(c[0]!), Math.round(c[1]!), Math.round(c[2]!)];
    return [round(front), round(back), opacity < 0.999 ? opacity : 0];
  }, [bgHandle, part] as const);
  const f = fg as Rgb;
  const b = bg as Rgb;
  return {measured: {fg: f, bg: b, ratio: contrastRatio(f, b)}, faded: faded as number};
}
