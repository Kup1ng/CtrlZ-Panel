export const FALLBACK: "dev";
export function cleanVersion(value: unknown): string | undefined;
export function ctrlzVersion(options?: {env?: Record<string, string | undefined>; describe?: (cwd: string, env: Record<string, string | undefined>) => string | undefined; cwd?: string}): string;
