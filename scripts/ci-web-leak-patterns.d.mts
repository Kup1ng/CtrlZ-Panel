export function phoneTail(phone: string): string;
export function asToken(value: string): string;
export function leakPatterns(
  seed: {user?: {phone?: string; password?: string}; admin?: {password?: string; totp_secret?: string}},
  noopText: string,
): {fixed: string[]; regex: string[]; records: number};
