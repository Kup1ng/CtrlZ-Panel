export const PROJECT: string;
export const COMPOSE_FILES: string[];
export function base32Decode(text: string): Buffer;
export function totp(secretBase32: string, nowMs?: number, options?: {digits?: number; stepSeconds?: number}): string;
export function stepOf(nowMs?: number, stepSeconds?: number): number;
export function generatePassword(): string;
export function generatePhone(): string;
export function composeArgs(args: string[], options?: {envFile?: string}): string[];
export function describeRun(run: {error?: {code?: string} | null; signal?: string | null; status?: number | null}): string;
export function readerImage(composeText: string): string | undefined;
export function readContainerFile(
  dir: string,
  name: string,
  options?: {read?: (path: string) => string; run?: (dir: string, name: string, image: string) => string; image?: string},
): string;
