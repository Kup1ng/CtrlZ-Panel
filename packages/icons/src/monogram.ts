import manifest from "../logos/manifest.json" with {type: "json"};

export type LogoEntry = {slug: string; source: string; licence: string; licenceUrlAsText: string};

const entries: readonly LogoEntry[] = manifest;
const slugs = new Set(entries.map((e) => e.slug));

// A slug that does not match this can never become a URL, so a remote address is impossible.
const SLUG = /^[a-z0-9-]+$/;

export function hasLogo(slug: string): boolean {
  return SLUG.test(slug) && slugs.has(slug);
}

export function logoSrc(slug: string): string | null {
  return hasLogo(slug) ? `/logos/${slug}.svg` : null;
}

const segmenter = typeof Intl !== "undefined" && "Segmenter" in Intl ? new Intl.Segmenter(undefined, {granularity: "grapheme"}) : null;

/**
 * The first grapheme of a name, for the monogram tile. A grapheme, not a code
 * unit, so a Persian letter with its marks or an emoji is never cut in half.
 * Latin letters are upper-cased; other scripts have no case.
 */
export function monogramLetter(name: string): string {
  const trimmed = name.trim();
  if (trimmed === "") return "?";
  const first = segmenter ? segmenter.segment(trimmed)[Symbol.iterator]().next().value?.segment : Array.from(trimmed)[0];
  if (!first) return "?";
  if (/^\p{Script=Latin}/u.test(first)) {
    const upper = first.toUpperCase();
    // The German sharp s becomes "SS": keep the original rather than show two letters in one tile.
    return Array.from(upper).length === Array.from(first).length ? upper : first;
  }
  return first;
}
