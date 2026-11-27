import type {CatalogService, ProfileService, ServiceCategory} from "@ctrlz/api-client/hooks/services.ts";

import {catalogName} from "./filtersModel.ts";

// The rules of the Services screen and of Choose Service (spec p2 9.4, T-162 to T-166, T-521), with no DOM so that they are tested alone.

/** A service of the profile with what the catalogue knows of it. A slug the catalogue no longer lists is kept, with no `service`. */
export type ServiceItem = {row: ProfileService; service?: CatalogService; name: string};
export type ServiceGroup = {category: ServiceCategory; items: ServiceItem[]};

/** The id of the group that holds profile services the catalogue no longer lists. They stay visible, so they can be removed. */
export const UNKNOWN_CATEGORY = "__unknown";

type Fold = (text: string) => string;

/**
 * The profile's services grouped by category, in the catalogue's order of categories, each group sorted by name in the reader's language.
 * `query` keeps the services whose name or slug matches (the fold makes Persian and Arabic letters and digits equal).
 */
export function groupProfileServices(args: {
  categories: readonly ServiceCategory[];
  catalogue: readonly CatalogService[];
  rows: readonly ProfileService[];
  locale: string;
  query: string;
  fold: Fold;
  compare: (a: string, b: string) => number;
  unknownCategory: ServiceCategory;
}): ServiceGroup[] {
  const {categories, catalogue, rows, locale, query, fold, compare, unknownCategory} = args;
  const bySlug = new Map(catalogue.map((s) => [s.slug, s]));
  const q = fold(query.trim());
  const items: {item: ServiceItem; categoryId: string}[] = [];
  for (const row of rows) {
    const service = bySlug.get(row.slug);
    const name = service ? catalogName(service, locale) : row.slug;
    if (q !== "" && !fold(name).includes(q) && !fold(row.slug).includes(q)) continue;
    items.push({item: {row, ...(service ? {service} : {}), name}, categoryId: service?.category_id ?? UNKNOWN_CATEGORY});
  }
  const groups: ServiceGroup[] = [];
  for (const category of [...categories, unknownCategory]) {
    const inGroup = items.filter((i) => i.categoryId === category.id);
    if (inGroup.length === 0) continue;
    inGroup.sort((a, b) => compare(a.item.name, b.item.name));
    groups.push({category, items: inGroup.map((i) => i.item)});
  }
  return groups;
}

export type ChooseGroup = {category: ServiceCategory; services: CatalogService[]};

/**
 * What Choose Service lists (T-164): the services that are not in the profile yet, so the count of a category drops by the ones it has.
 * A deprecated service cannot be added and is not listed. The search keeps a service by its name or slug, and a whole category by its name.
 */
export function chooseGroups(args: {
  categories: readonly ServiceCategory[];
  catalogue: readonly CatalogService[];
  inProfile: ReadonlySet<string>;
  locale: string;
  query: string;
  fold: Fold;
  compare: (a: string, b: string) => number;
}): ChooseGroup[] {
  const {categories, catalogue, inProfile, locale, query, fold, compare} = args;
  const q = fold(query.trim());
  const offered = catalogue.filter((s) => !inProfile.has(s.slug) && s.state !== "deprecated");
  return categories.flatMap((category) => {
    const categoryHit = q !== "" && fold(catalogName(category, locale)).includes(q);
    const services = offered
      .filter((s) => s.category_id === category.id)
      .filter((s) => q === "" || categoryHit || fold(catalogName(s, locale)).includes(q) || fold(s.slug).includes(q))
      .sort((a, b) => compare(catalogName(a, locale), catalogName(b, locale)));
    return services.length > 0 ? [{category, services}] : [];
  });
}

export type CategoryCheck = "all" | "some" | "none";

/** The state of the check box of a category: all of its listed services are selected, some, or none. */
export function categoryCheck(selected: ReadonlySet<string>, slugs: readonly string[]): CategoryCheck {
  const n = slugs.filter((s) => selected.has(s)).length;
  return n === 0 ? "none" : n === slugs.length ? "all" : "some";
}

/** The selection after the check box of a category was pressed: a whole category on, or off. A part selected becomes all. */
export function toggleCategory(selected: ReadonlySet<string>, slugs: readonly string[]): Set<string> {
  const next = new Set(selected);
  const on = categoryCheck(selected, slugs) !== "all";
  for (const s of slugs) {
    if (on) next.add(s);
    else next.delete(s);
  }
  return next;
}

/** The services of the selection that carry the risk flag (T-165): they need Enable Anyway before they are added. */
export function riskyOf(selected: ReadonlySet<string>, catalogue: readonly CatalogService[]): CatalogService[] {
  return catalogue.filter((s) => selected.has(s.slug) && s.risk_flag);
}

/** The selection holds a service that is never proxied, so Redirect is not offered for the group (T-521, D42). */
export function selectionNeverProxied(selected: ReadonlySet<string>, catalogue: readonly CatalogService[]): CatalogService | undefined {
  return catalogue.find((s) => selected.has(s.slug) && !s.redirect_allowed);
}

// The page draws this many cards at first, counted over all its categories, and a category draws one step more on request. A card is a Switch, a
// three-button group, a remove button and a logo, and the catalogue holds about a thousand services (Plan D74), so a profile with most of it, spread
// over many categories, drew a thousand of them at the first paint. The categories after the budget show their header and a button to draw them.
// The step divides the columns of the grid at every width (1, 2, 3, 4, 6), so no row is left half full.
export const CARDS_PER_STEP = 48;
const ROW_MULTIPLE = 12;

/**
 * How many cards each category draws: the whole category while the page budget lasts, then the part of it that fits (a whole number of rows at
 * any width), then none. What a person asked for with Show more (`asked`) is kept on top of that.
 */
export function cardLimits(
  groups: readonly {category: {id: string}; items: readonly unknown[]}[],
  asked: ReadonlyMap<string, number>,
  budget = CARDS_PER_STEP,
): Map<string, number> {
  let left = budget;
  return new Map(
    groups.map((g) => {
      const n = g.items.length;
      let base: number;
      if (n <= left) {
        base = n;
        left -= n;
      } else {
        base = left - (left % ROW_MULTIPLE);
        left = 0;
      }
      return [g.category.id, Math.min(n, Math.max(asked.get(g.category.id) ?? 0, base))] as const;
    }),
  );
}
