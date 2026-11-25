export function findInlineUris(
  files: {path: string; text: string}[],
  allowText?: string,
): {found: string[]; allowed: string[]; stale: string[]; problems: string[]};
export function builtFiles(root: string, app: string): {path: string; text: string}[];
