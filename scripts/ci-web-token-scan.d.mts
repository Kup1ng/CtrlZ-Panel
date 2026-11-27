export function createScanner(needle: Buffer): {push(chunk: Buffer): void; readonly found: boolean};
export function tarContains(stream: AsyncIterable<Buffer>, needle: Buffer): Promise<boolean>;
export function createEntryScanner(needle: Buffer): {pushRaw(chunk: Buffer): void; pushDecoded(chunk: Buffer): void; readonly found: boolean};
