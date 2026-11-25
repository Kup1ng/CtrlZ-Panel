export function parseAllow(text: string): {types: Set<string>; packages: string[]; problems: string[]};
export function expressionAllowed(expression: string, types: Set<string>): boolean;
export function checkLicences(listing: Record<string, {name: string; versions?: string[]}[]>, allowText: string): string[];
