export type AllowRule = {kind: "url" | "host"; values: string[]; scope?: string; line: number; used: Set<string>};
export type UrlEntry = {url: string; query: string; partial: boolean; cut: boolean; climbs: boolean; built: boolean; afters: string[]; alt?: {url: string; query: string; bounded?: boolean}};
export type ScanIo = {
  readdirSync: (dir: string, options: {withFileTypes: true}) => {name: string}[];
  statSync: (path: string) => {isDirectory(): boolean; isFile(): boolean};
  realpathSync: (path: string) => string;
};
export function extractUrlEntries(text: string): UrlEntry[];
export function extractUrls(text: string): string[];
export function hostOf(url: string): string;
export function parseAllow(text: string): {rules: AllowRule[]; problems: string[]};
export function explain(url: string, path: string, rules: AllowRule[], query?: string, partial?: boolean, alt?: {url: string; query: string; bounded?: boolean}, cut?: boolean, climbs?: boolean, built?: boolean, afters?: string[]): AllowRule | undefined;
export function explainEntry(entry: UrlEntry, path: string, rules: AllowRule[]): AllowRule | undefined;
export function scanApp(
  appDir: string,
  rules: AllowRule[],
  io?: ScanIo,
): {unexplained: Map<string, {path: string; count: number; partial: boolean}>; files: number; strings: number; skipped: number; dangling: number};
export function staleLines(rules: AllowRule[]): {fail: string[]; warn: string[]};
export function printable(url: string, partial?: boolean): string;
export function isLoadable(url: string, query?: string): boolean;
export function main(argv: string[]): number;
export function normalise(text: string): string;
export function decode(buffer: Buffer): string;
