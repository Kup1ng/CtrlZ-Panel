#!/usr/bin/env node
// What step 10f1 of scripts/ci-web.sh looks for in the logs of the front tier after the real sign-in flows (merge-r3-10, merge-r4-8):
// the values of this run that must never be written by Caddy or Next. The values are the seed's (phone, passwords, TOTP secret) and the
// ones the noop SMS driver recorded (the codes of the login, the reset and the invite's registration, and the numbers they went to). An invite is
// never sent by SMS (D67), so its token is not in the noop file: the stack spec writes each token it makes to a file of its own, and the token itself
// is a pattern, whole and by its first forty characters (a log line may cut it).
//
//   node scripts/ci-web-leak-patterns.mjs <seed.json> <noop.jsonl> <fixed-out> <regex-out> <invite-tokens.txt>
//
// Two files are written, mode 0600, one pattern per line, and nothing is printed: `fixed-out` is for `grep -F` and `regex-out` for `grep -E`.
// The shell reads them with grep and prints a count only, so a leak is never copied into the CI log (fixed rule 8).
import {existsSync, readFileSync, writeFileSync} from "node:fs";
import {pathToFileURL} from "node:url";

/** The phone as the API stores it is +98912..., a URL carries %2B98912..., and the seed holds 0912...: the last ten digits are in all three. */
export const phoneTail = (phone) => String(phone).replace(/\D/g, "").slice(-10);

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A code is judged as a whole token, not as a substring: a six digit code appears inside timestamps and byte counts of a busy log. The
 * characters allowed around it exclude letters, digits and the dot, so the fraction of a timestamp (`1732412123.456789`) is not a hit.
 */
export const asToken = (value) => `(^|[^0-9A-Za-z.])${escapeRegex(value)}([^0-9A-Za-z.]|$)`;

/** How much of a token is searched on its own: enough that nothing else in a log can be it, short enough to survive a cut line. */
export const TOKEN_HEAD = 40;

/** `seed` is the parsed seed.json, `noopText` the text of the noop driver's file (one JSON record per line), `tokensText` the invite tokens, one per line. */
export function leakPatterns(seed, noopText, tokensText = "") {
  const fixed = new Set();
  const regex = new Set();
  for (const value of [phoneTail(seed.user?.phone ?? ""), seed.user?.password, seed.admin?.password, seed.admin?.totp_secret, "Authorization", "Cookie"]) {
    if (value) fixed.add(String(value));
  }
  let records = 0;
  for (const line of noopText.split("\n")) {
    if (!line.trim()) continue;
    const record = JSON.parse(line);
    records++;
    if (record.to) fixed.add(phoneTail(record.to));
    for (const value of Object.values(record.values ?? {})) {
      // A one or two character value (a locale, a digit) would match every log; the codes and invites are longer.
      if (typeof value === "string" && value.length >= 4) regex.add(asToken(value));
    }
  }
  let tokens = 0;
  for (const line of tokensText.split("\n")) {
    const token = line.trim();
    if (!token) continue;
    tokens++;
    fixed.add(token);
    fixed.add(token.slice(0, TOKEN_HEAD));
  }
  return {fixed: [...fixed].filter((v) => v.length > 0), regex: [...regex], records, tokens};
}

function main() {
  const [seedFile, noopFile, fixedOut, regexOut, tokensFile] = process.argv.slice(2);
  if (!seedFile || !noopFile || !fixedOut || !regexOut || !tokensFile) {
    console.error("usage: node scripts/ci-web-leak-patterns.mjs <seed.json> <noop.jsonl> <fixed-out> <regex-out> <invite-tokens.txt>");
    process.exit(2);
  }
  const {fixed, regex, records, tokens} = leakPatterns(
    JSON.parse(readFileSync(seedFile, "utf8")),
    readFileSync(noopFile, "utf8"),
    existsSync(tokensFile) ? readFileSync(tokensFile, "utf8") : "",
  );
  // A scan with no SMS record has no code to look for: the sign-in flows sent some, so an empty file means the scan is blind.
  if (records === 0) {
    console.error("ci-web-leak-patterns: the noop SMS file holds no message, so the codes of this run are unknown");
    process.exit(1);
  }
  // The invite flow of the stack run made a token. No token means the flow did not run, and the one new secret of an invite would go unwatched.
  if (tokens === 0) {
    console.error("ci-web-leak-patterns: no invite token was recorded, so the link of this run is unknown");
    process.exit(1);
  }
  // An empty file, never a file with one empty line: an empty pattern matches every line of the log.
  const lines = (list) => (list.length ? `${list.join("\n")}\n` : "");
  writeFileSync(fixedOut, lines(fixed), {mode: 0o600});
  writeFileSync(regexOut, lines(regex), {mode: 0o600});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
