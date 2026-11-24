export function phoneTail(phone: string): string;
export function asToken(value: string): string;
export const TOKEN_HEAD: number;
export function leakPatterns(
  seed: {user?: {phone?: string; password?: string}; admin?: {password?: string; totp_secret?: string}},
  noopText: string,
  tokensText?: string,
): {fixed: string[]; regex: string[]; records: number; tokens: number};
