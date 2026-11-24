export function fieldRadiusSelectors(css: string): string[];
export function tableSelectors(rows: {selector: string}[]): Set<string>;
export function readUnused(text: string): {selectors: Set<string>; problems: string[]};
export function checkRoundedField(
  stylesheets: {file: string; css: string}[],
  rows: {selector: string}[],
  unusedText: string,
): string[];
