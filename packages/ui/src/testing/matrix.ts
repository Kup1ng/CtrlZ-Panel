// Spec 17.1: the projects of a Playwright run are the product of width, language and theme, 12 in all.
// This file is plain data and holds no Playwright import, so a unit test can check it and a spec can
// read the project it runs in.

export const WIDTHS = [375, 768, 1280] as const;
export const LANGUAGES = ["fa", "en"] as const;
export const THEMES = ["light", "dark"] as const;

/** Heights from the spec: a phone, a tablet and a desktop window. */
export const HEIGHTS: Record<(typeof WIDTHS)[number], number> = {375: 812, 768: 1024, 1280: 800};

export type Width = (typeof WIDTHS)[number];
export type Language = (typeof LANGUAGES)[number];
export type Theme = (typeof THEMES)[number];
export type Matrix = {width: Width; lang: Language; theme: Theme};

export const DIRECTION: Record<Language, "rtl" | "ltr"> = {fa: "rtl", en: "ltr"};

/** `w375-fa-dark`. */
export const projectName = ({width, lang, theme}: Matrix) => `w${width}-${lang}-${theme}`;

export const MATRIX: Matrix[] = WIDTHS.flatMap((width) => LANGUAGES.flatMap((lang) => THEMES.map((theme) => ({width, lang, theme}))));

/** What a matrix project stores in its `metadata`, and what a test reads back from it. */
export function readMatrix(metadata: unknown): Matrix | null {
  if (!metadata || typeof metadata !== "object") return null;
  const m = (metadata as {matrix?: Partial<Matrix>}).matrix;
  if (!m) return null;
  const found = MATRIX.find((x) => x.width === m.width && x.lang === m.lang && x.theme === m.theme);
  return found ?? null;
}
