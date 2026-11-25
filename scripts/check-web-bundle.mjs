// Step 7 of scripts/ci-web.sh (spec 3.5, 16.2). Scans what ships for URL strings and fails on any
// that tools/web-lint/bundle-url-allow.txt does not explain, so a new `https://` in the browser
// bundle or the server image is a review item and not an accident.
//
//   node scripts/check-web-bundle.mjs                    both apps, after `next build` of each
//   node scripts/check-web-bundle.mjs --app panel        one app (stale lines are then not reported)
//   node scripts/check-web-bundle.mjs --reveal           print each string whole, to write its allow line. A
//                                                        local aid only: never in CI, since a secret in a
//                                                        string would then reach the log
//   node scripts/check-web-bundle.mjs --root <dir> --allow <file>   used by the unit test
//
// What is scanned, per app: `.next/static` (what a browser downloads), `.next/standalone` (what
// the image runs, node_modules included) and `public/` (served as is). The match is any
// `http://`, `https://`, `ws://` or `wss://` string, and a scheme-relative `//host.tld/...` one, which a
// browser fetches with the page's scheme. JSON and JS escape the slash (`https://host`, `/`), so
// that is undone before matching. So is the rest of JS string unescaping: \x40, @, \u{40} and octal escapes, a
// backslash before an ordinary character (a backslash-dot is a dot, backslash-@ is an at sign), a backslash before a
// line break (a line continuation, deleted), and a tab, line feed or carriage return inside a URL, which the engine
// and a browser's URL parser turn into the real character or delete (see `normalise`). Every file that is not
// binary by name is scanned: a UTF-16 file as UTF-16, and a file that holds a NUL as UTF-8 and as latin1 with the
// NULs removed (see `decode`). A URL is cut at the first quote, space, backslash, bracket or query; when it is cut
// at a backslash that goes on as the same URL for a browser (a path backslash is a slash, an escaped quote may be
// a character of the host), or when its authority holds a space, VT or FF before an `@`, no host line explains it
// (see `isCutAtBackslash` and `extractUrlEntries`). A URL also ends where its string ends and not before (wp5-r8): after
// a quote it ends at that quote, so a bracket, a comma, a quote of the other kind, `<`, `>` and white space are
// characters of its host or its path, and a host line vouches only when that whole reading is a page (see `CLOSER` and
// `alternativeOf`). Literal text after the `}` of a placeholder is part of the host, and a placeholder in the path
// or a percent escape in it makes the link no page for a host line (wp5-r9). An exact `url` line does not explain a string
// whose wide reading climbs (a dot segment or an encoded separator) or that was cut at a backslash and then climbs.
// A host line also refuses a URL built with `+` or `.concat(` (`built`) and one with a placeholder in its query, and an
// exact `url` line that ends in an open `${` explains the text after the `}` only when it is a page or the template closes
// there, or names the whole template (wp5-r10, see `explain` and `afterOk`).
// A host line never explains a bare origin (a base) and a break escape before a closing quote does not stop a build
// from being a build (wp5-r11).
//
// WHAT THIS GATE IS (wp5-r11-2, wp5-r11-6). It judges one extracted string at a time, so it is a heuristic second layer.
// It cannot see how a page-shaped string that a program keeps in a variable, extends with `+=`, passes as the base of
// `new URL(path, base)` or joins from an array is completed at run time, and a host line (`github.com`, `nextjs.org`)
// then explains the string whose download path is written somewhere else. Eleven rounds closed spelling after spelling
// and this class cannot be closed by more rules. The proof that nothing at run time reaches the international internet
// is the offline run of spec 17.4 (closed network, the guard of 17.2 failing any request), and this gate is what makes a
// new string a review item before that run. Dropping `github.com` and `gist.github.com` from the host lines (the two
// hosts that serve downloads) and naming their ~40 comment links per app one by one would narrow it, and is the
// owner's call.
//
// Cost (wp5-r11-1): the scan takes time in proportion to the size of a file, whatever it holds. See `stripEnd`.
//
// A file is also read as CSS and as HTML (hex escapes, identity escapes, character references with any number of leading
// zeros), see `extractUrlEntries`. What is printed is shorter still (see `printable`): a secret can sit in a query, in the
// userinfo or in the path, and secrets never reach a log (fixed rule 8). The full string is kept
// only for matching, and the report names the file to read.
//
// The allowlist has two kinds of line, each ending in " # reason":
//
//   url  <string>...  [in <path part>]   exact strings, anywhere; `in` limits it to paths that
//                                        contain that part. The browser bundle has only these.
//   host <name>...                       a host, only for files under `node_modules/` inside
//                                        `.next/standalone`: Next and its dependencies carry
//                                        documentation and specification links in comments and
//                                        messages, and listing every one would change with each
//                                        upgrade. Never for `.next/static`, `public/` or the compiled
//                                        code of this repository (`.next/server`): there a host that
//                                        serves content must be an exact `url` line.
//
// A `url` line without `in` that matches nothing is stale and fails (the browser bundle is the same
// on every machine). Other lines that match nothing are reported and do not fail: the packages
// that Next traces into the standalone folder differ between Windows and Linux.
//
// Not scanned in node_modules: package.json, Markdown, licence files and type declarations. They
// hold homepage and issue-tracker links of every package and no code that can run. A file called
// `notice-client.js` or `license.js` is code and is scanned: only the names that a licence or credits
// text really has are skipped (no extension, or .txt or Markdown, with an optional `-MIT` style tail).
import {existsSync, readdirSync, readFileSync, realpathSync, statSync} from "node:fs";
import {join, relative, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));

// Images, fonts, media and archives: data, not code that runs. `.wasm` and `.node` are NOT here (wp5-r7-5): a native
// addon is a shared library that require() loads with full network access, and a WebAssembly module runs too and keeps
// its URL strings in plain ASCII, so both are read like any other file that holds a NUL (see `decode`). The same bytes
// under the name .so, .dll or .dat were scanned already, so the name must not decide.
const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot|mp[34]|webm|zip|gz|br|zst|pdf)$/i;
const VENDOR_METADATA = /(^|\/)(package\.json|[^/]*\.mdx?|[^/]*\.markdown|(license|licence|notice|copying|authors|contributors)([-_][^/.]*)?(\.(txt|md|markdown))?|[^/]*\.d\.[cm]?ts)$/i;

// A URL ends at a quote, a space, an escape, a bracket or a separator (REST below), which is where it ends in
// code, a comment or a message. `${` is kept on purpose: `https://${host` is a URL built at run time, and that is
// exactly what a reviewer must see. Its AUTHORITY is read further than that (see extractUrlEntries), because a
// browser ends the authority only at / ? # or a backslash.
//
// A host label may hold an underscore (an S3 bucket made before 2018 has one, `my_bucket.s3.amazonaws.com`) and the
// labels are separated by a dot of any of the four kinds a browser's host parser maps to one: U+002E, U+3002, U+FF0E
// and U+FF61 (wp5-r10-1). `hostOf` and `printable` read them all as a dot.
// A scheme-relative URL must not follow a word character, a colon (that is the schemed form), a slash, a
// backslash, a dot or a dash. Its host is a dotted name whose top-level domain is letters (Unicode ones and
// punycode xn-- ones count), a dotted-quad address, or a bracketed IPv6 address (it holds a colon, so that a
// regular-expression class [abc] is not one), with an optional userinfo. A name needs its dot and its letters so
// that a "//" in a comment, a regular expression or "a//b" is not a hit, and a "// " with a space never is one.
//
// A browser also reads a special-scheme URL (http, https, ws, wss) more loosely than `scheme://` (wp5-r4-7): a
// backslash is a slash, any number of slashes may follow the scheme, and `http:evil.example` is a URL too. So
// the separator is any run of `/` and `\`, a scheme with fewer than two of them counts when a host follows,
// and a scheme-relative URL may start with any mix of two. The match is then written back as `scheme://rest`
// or `//rest`, so that hostOf, the allow file and the report see one spelling.
// The userinfo is bounded (512): its class holds `:`, so in `http:http:http:...` every `http:` would scan the rest of the
// run for an `@` (wp5-r11-1). The `scheme://` form does not use HOST, so a longer userinfo is still found there.
const HOST =
  "(?:[^\\s\"'`<>/\\\\?#@]{0,512}@)?(?:(?:[\\p{L}\\p{N}_-]+[.。．｡])+(?:xn--[a-z0-9-]+|\\p{L}{2,})(?![\\p{L}\\p{N}-])|\\d{1,3}(?:\\.\\d{1,3}){3}(?![\\w-]|\\.\\d)|\\[(?=[0-9a-f.]*:)[0-9a-f:.]+\\])";
const REST = "[^\\s\"'`<>\\\\)\\]}|,;^]*";
// With fewer than two separators the form is rare, and code such as `agent = tls ? u.https:u.http` has the same
// shape, so there the scheme must not be a property (`.https`) or a variable part (`$https`).
// The separator run must not end in a backslash that escapes a punctuation mark (`https:\/\/\*\.verify`, a regular
// expression whose slashes were unescaped above): that backslash is no slash, and what follows is no host.
const SCHEMED = `\\b(?:https?|wss?):[/\\\\]{2,}(?:(?<!\\\\)|(?![*+.?\\[\\](){}|^$]))|(?<![.$])\\b(?:https?|wss?):[/\\\\]?${HOST}`;
// A scheme-relative URL whose host starts with a placeholder (`//${b}.cdn.evil.example/lib.js`) has no literal host to
// match, so it is a second form (wp5-r9-5). It counts only when the slashes follow a quote, a backtick, `(`, `=`, white
// space or the start of the text, which is where a URL starts: after a `}` they are a path join (`${base}//${path}`).
// The entry is then the placeholder and the literal text after its `}` is read as part of the host (see
// `afterPlaceholder`), so it is a review item and no host line explains it. It starts with a forward slash: in
// JS source a pair of backslashes before a placeholder (`\`\\\\${e}\``, how a regular-expression builder escapes a
// character) is ONE backslash at run time, no scheme-relative URL.
const SCHEME_RELATIVE = `(?:(?<![\\w:/.\\\\-])[/\\\\]{2,}${HOST}|(?<=^|["'\`(=\\s])/[/\\\\]\\$\\{)`;
const URL_PATTERN = new RegExp(`(?:${SCHEMED}|${SCHEME_RELATIVE})${REST}`, "giu");

// Time per file (wp5-r11-1). A regular expression that starts with an unanchored run (`\\+`, `BREAK+`, `[.:]+$`) is
// retried by the engine at every position of a run, so a run of n characters costs n squared steps: a blank-padded
// file or a long escaped string stalled step 7 with no output. Every run below is therefore anchored at its start
// (a lookbehind that the run's own character cannot satisfy), matched greedily once and judged in a callback, or
// trimmed by `stripEnd`. The test 'takes time in proportion to the size of a run' holds the class.
/** Removes the trailing characters that match `one` (a single-character pattern), in one pass. */
function stripEnd(text, one) {
  let end = text.length;
  while (end > 0 && one.test(text[end - 1])) end--;
  return end === text.length ? text : text.slice(0, end);
}

/** A backslash-slash and a / escape are a slash in JSON and in JS strings: https://host is https://host. */
const unescapeSlashes = (text) => text.replace(/\\u002f/gi, "/").replace(/(?<!\\)\\+\//g, "/");

// What a JS or JSON string holds is not what the source spells (wp5-r5-1, wp5-r5-2): the engine turns \x40, \u0040 and
// \u{40} into "@", and the URL parser of a browser or of Node deletes every tab, line feed and carriage return in a
// URL, wherever it sits. So the host a program reaches is another one than the source seems to name
// (`https://github.com\x40evil.example`). The text is rewritten to what the runtime string holds before any
// matching. More than one backslash is accepted before the letter, because JSON inside a JS string doubles them, and
// decoding too much only adds a string for a reviewer to read.
const CODE_ESCAPE = /(?<!\\)\\+(?:u\{0*([0-9a-f]{1,6})\}|u([0-9a-f]{4})|x([0-9a-f]{2}))/gi;
const decodeEscapes = (text) =>
  text.replace(CODE_ESCAPE, (all, braced, four, two) => {
    const code = Number.parseInt(braced ?? four ?? two, 16);
    return code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ? all : String.fromCodePoint(code);
  });

// The rest of JS string unescaping (wp5-r6-1, wp5-r6-2). In a JS string, a template literal too, a backslash before
// an ordinary character is that character (backslash-@ is @, backslash-p is p), a backslash before a line break is
// deleted (LF, CR, CRLF, U+2028, U+2029: a line continuation), and a legacy octal escape (backslash-100) is the
// character of its code. Two backslashes are one backslash and stay as they are, and are consumed as a pair so that
// two backslashes and a dot are not read as an escaped dot. Left alone: backslash-n, -r and -t (a break, which the
// URL parser deletes, see BREAK), -b, -f, -v, -0, a malformed -x or -u, and a backslash before a quote or a
// backtick, which ends a URL as it did before. A regular expression has the same escapes with other meanings
// (backslash-d is a class), so decoding adds a few strings that are no URL: a reviewer reads them and the allow
// file explains them. Decoding too little is the fail-open side.
const JS_ESCAPE = /(\\\\)|\\(\r\n|[\n\r\u2028\u2029])|\\([0-3][0-7]{0,2}|[4-7][0-7]?)|\\([^\\nrtbfvxu0-7"'`/\r\n\u2028\u2029])/g;
const decodeJsEscapes = (text) =>
  text.replace(JS_ESCAPE, (all, pair, continuation, octal, identity) => {
    if (pair !== undefined) return all;
    if (continuation !== undefined) return "";
    if (octal !== undefined) return octal === "0" ? all : String.fromCharCode(Number.parseInt(octal, 8));
    return identity;
  });

// A tab, line feed or carriage return, as an escape or as the character. The escape is ONE backslash: `\\r` is an
// escaped backslash and a letter (`'\\path\\route.js'` in Next), which is no break.
const BREAK = String.raw`(?:(?<!\\)\\[tnr]|[\t\n\r])`;
const BREAKS = new RegExp(BREAK, "g");
// A scheme with a break inside it (`ht\ttps://`) is that scheme.
const BROKEN_SCHEME = new RegExp(String.raw`(?:h${BREAK}*t${BREAK}*t${BREAK}*p${BREAK}*(?:s${BREAK}*)?|w${BREAK}*s${BREAK}*(?:s${BREAK}*)?):`, "gi");
// A break right before a URL only separates it from what came before (`"a\nhttps://x"` is two words and not
// "nhttps"): the \b of the scheme and the boundary of the scheme-relative form need a gap there.
// A break right after an opening quote is no gap: the URL is the start of its string (`"\nhttps://x"`), which the URL
// parser reads as the URL, so its string and its opening quote stay known to `collectEntries`.
// One greedy run per match, so the engine does not retry from every break of a run; the callback of `breaksBeforeUrl`
// decides with a sticky test what follows (wp5-r11-1).
const BREAK_RUN = new RegExp(`(?:${BREAK})+`, "g");
const URL_START = /(?:https?|wss?):|[/\\]{2}/iy;
function breaksBeforeUrl(text) {
  return text.replace(BREAK_RUN, (run, offset, whole) => {
    URL_START.lastIndex = offset + run.length;
    if (!URL_START.test(whole)) return run;
    return QUOTES.includes(whole[offset - 1] ?? "") ? "" : " ";
  });
}
// Characters that the host mapping of a browser (IDNA) maps to nothing, U+FEFF among them: they are no part of the
// host, but JS `\s` matches U+FEFF, so it would cut the string (`github.com<U+FEFF>.evil.example` is the host
// github.com.evil.example, wp5-r6-2).
const IGNORED = String.raw`[\u00AD\u034F\u180B-\u180D\u180F\u200B\u2060\uFE00-\uFE0F\uFEFF]`;
const DROPPED_IN_AUTHORITY = new RegExp(`${BREAK}|${IGNORED}`, "g");
// Inside an authority a break is deleted: `https://github.com\t.evil.example` is the host github.com.evil.example.
const AUTHORITY_WITH_BREAKS = new RegExp(
  String.raw`(\b(?:https?|wss?):[/\\]*|(?<![\w:/.\\-])[/\\]{2,})((?:[^\s"'` + "`" + String.raw`<>/\\?#]|${BREAK}|${IGNORED})+)`,
  "giu",
);
// A URL that sits in a string ends where that string ends, and the character before the URL says which quote opened
// the string (wp5-r8-2, wp5-r8-3): after a quote, the URL ends at that quote only, so a quote of another kind, a
// backtick, `<`, `>` and the cut characters are characters of the URL, as they are for a browser's URL parser, which
// percent-encodes some of them and keeps the rest. After anything else the URL sits in the middle of a message or a
// comment, where the string opened earlier and is unknown, and it ends at white space or at any quote. A URL that
// follows a line break right after its opening quote is the start of its string: see AFTER_QUOTE_BEFORE_URL.
// Every scan that starts at a match runs to the next delimiter, so many URLs in one run with no white space, quote or
// backslash between them would rescan the rest of the run for each match, in proportion to the square of its length
// (wp5-r12-3). Each such scan is bounded. A host name is at most 253 characters, so an authority scan of 512 holds the
// longest real one with its userinfo. A path may be long, so a token scan is bounded at 2048. A scan that reaches its
// bound knows nothing of what lies beyond it, so the entry is partial (no line explains it), and an entry whose wide
// reading reached it is no page either (`boundedToken`).
const AUTH_BOUND = 512;
const TOKEN_BOUND = 2048;
const CLOSER = new Map([['"', '"'], ["'", "'"], ["`", "`"]]);
const QUOTES = `"'` + "`";
// The token of a URL from its scheme on, path included, up to white space, the closing quote of its string and a
// backslash, and not into a `${` placeholder, whose text is not the path (see `alternativeOf`).
const TOKENS = new Map(
  [undefined, '"', "'", "`"].map((closer) => [
    closer,
    // Inside a string the URL goes on past a space too: the URL parser percent-encodes it, so `.../o/r /../x.zip` still
    // climbs. Only a URL in the middle of a message, whose string is unknown, ends at white space.
    new RegExp(String.raw`^(?:(?!\$\{)[^${closer ?? String.raw`\s` + QUOTES}\\]|${BREAK}){1,${TOKEN_BOUND}}`, "u"),
  ]),
);
// The authority a browser reads, up to / ? # a backslash, white space or the closing quote of the string.
const AUTHORITIES = new Map(
  [undefined, '"', "'", "`"].map((closer) => [closer, new RegExp(String.raw`^[^/\\?#\s${closer ?? QUOTES}]{0,${AUTH_BOUND}}`, "u")]),
);

/**
 * The text as the runtime strings in it read: escapes decoded, slashes unescaped, breaks in a URL applied.
 * `jsEscapes` also applies the ordinary JS string escapes (`decodeJsEscapes`). The text of a file is not always the
 * source of a JS string: in JSON that was decoded, in an HTML page or in an RSC payload a backslash is a backslash,
 * and a browser reads it as a slash. So `extractUrlEntries` reads both ways.
 */
export function normalise(text, jsEscapes = true) {
  return breaksBeforeUrl(
    unescapeSlashes(jsEscapes ? decodeJsEscapes(decodeEscapes(text)) : decodeEscapes(text)).replace(BROKEN_SCHEME, (m) => m.replace(BREAKS, "")),
  ).replace(AUTHORITY_WITH_BREAKS, (_m, scheme, authority) => scheme + authority.replace(DROPPED_IN_AUTHORITY, ""));
}

/**
 * The strings of one file, normalised: no query or fragment, and no trailing dot or colon. Each entry
 * keeps things the string alone has lost:
 *
 *   query    what followed the `?`. It is never printed or matched by an allow line, but a host line must not
 *            vouch for a link that asks for the file itself (`?raw=true`, `?download`), see `isLoadable`.
 *   partial  the report must not print the authority. The string was cut inside its authority and an `@` follows
 *            within the next 256 characters of the same token, or the browser's authority is longer than the cut
 *            string (see below), or the authority holds a colon and an `@` follows in the path. What is left of
 *            a cut userinfo (`https://deploy:Xy7`) looks like a host and port, and a log keeps what it is given.
 *
 * The authority is read the way a browser reads it (wp5-r4-5): it ends only at `/`, `?`, `#`, a backslash, a
 * space or a quote, so `https://github.com,x@evil.example/p` is a URL on evil.example, not on github.com. The
 * cut characters `, ; | ^ ) ] }` end the string only after the authority. When the browser's authority runs
 * on past the cut, over anything but trailing punctuation or the `}` that closes a `${` placeholder, the
 * string is the whole authority, so that no host line or url line can explain a host that is not the real one.
 */
export function extractUrlEntries(text) {
  const found = new Map();
  const readings = new Set([normalise(text, true), normalise(text, false)]);
  // CSS and HTML are read by other rules than JS (wp5-r9-2): a browser reads `\2f` in a stylesheet as a slash and
  // `&#104;`, `&#47;` or `&sol;` in an attribute value as the character, so `url(https:\2f\2fcdn.evil.example/x.png)`
  // is a request that the JS reading never sees. Two more readings are kept, each decoded the way a browser reads
  // markup and a stylesheet: CSS escapes of up to six hex digits (the real rule), and of two (`\2f\2fcdn` is
  // `\2fcd` and `n` by the rule, and it is what an author who forgot the space meant). They are only worth reading
  // when the text has an entity or a backslash before a hex digit.
  if (MARKUP_HINT.test(text)) {
    for (const digits of [6, 2]) readings.add(normalise(decodeCss(decodeHtml(text), digits), false));
  }
  for (const reading of readings) collectEntries(reading, found);
  return [...found.values()];
}

const MARKUP_HINT = /&(?:#x?[0-9a-f]|[a-z]+;)|\\[0-9a-f]/i;
// The names that can spell what a URL is made of. HTML names are case-sensitive.
const HTML_NAMED = new Map(
  Object.entries({colon: ":", sol: "/", bsol: "\\", period: ".", commat: "@", lowbar: "_", hyphen: "-", dash: "-", num: "#", quest: "?", equals: "=", percnt: "%", plus: "+", comma: ",", semi: ";", lpar: "(", rpar: ")", amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", Tab: "\t", NewLine: "\n"}),
);
const validCodePoint = (code) => code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff);
/**
 * Numeric references (a missing semicolon is accepted, as HTML does) and the named ones above, decoded. HTML takes any
 * number of digits in a numeric reference, so leading zeros are legal (`&#00000000104;`, wp5-r10-5) and are skipped,
 * the way CODE_ESCAPE skips them in `\u{0000040}`.
 */
function decodeHtml(text) {
  return text.replace(/&(?:#0*(\d{1,7})|#[xX]0*([0-9a-fA-F]{1,6}));?|&([A-Za-z]+);/g, (all, dec, hex, name) => {
    if (name !== undefined) return HTML_NAMED.get(name) ?? all;
    const code = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex, 16);
    return validCodePoint(code) ? String.fromCodePoint(code) : all;
  });
}
/**
 * CSS hex escapes: a backslash and 1 to `digits` hex digits, one white space after them being part of the escape, and a
 * backslash before a line break (deleted, a string continuation). A backslash before any other character is left as
 * it is: CSS reads it as that character, which is also what the JS reading does for every character but n, r, t, v, x,
 * u and the quotes, and decoding those here would turn the backslash-n of a JS message into the letter n and invent
 * strings (`.../middleware-request-pagen`). A stylesheet that spells a letter with one of them is a residual.
 */
function decodeCss(text, digits) {
  // A pair of backslashes is one escaped backslash and is consumed as a pair, so that `\\evil` is not read as a
  // backslash and the hex escape `\e`.
  const pattern = new RegExp(String.raw`\\(?:(\\)|([0-9a-fA-F]{1,${digits}})(?:\r\n|[ \t\n\r\f])?|(?:\r\n|[\n\r\f])|([^0-9a-fA-F\r\n\f\\nrtvxu"'\`]))`, "g");
  return text.replace(pattern, (all, pair, hex, identity) => {
    if (pair !== undefined) return all;
    // Any other character after a backslash is that character (wp5-r10-4): a stylesheet that mixes a hex escape with
    // an identity one (`htt\p:\2f/`) is spelled wrongly in the JS reading, which reads `\2f` as an octal escape, and in
    // a CSS reading that leaves `\p` alone. The excluded letters and the quotes are the ones the JS reading owns.
    if (identity !== undefined) return identity;
    if (hex === undefined) return "";
    const code = Number.parseInt(hex, 16);
    return validCodePoint(code) ? String.fromCodePoint(code) : all;
  });
}

/** Adds the strings of one normalised text to `found`. */
function collectEntries(unescaped, found) {
  for (const m of unescaped.matchAll(URL_PATTERN)) {
    const raw = m[0];
    const prefix = /^(?:[a-z]+:)?[/\\]*/i.exec(raw)?.[0] ?? "";
    const scheme = /^[a-z]+/i.exec(prefix)?.[0];
    const canonPrefix = scheme === undefined ? "//" : `${scheme}://`;
    const body = raw.slice(prefix.length);
    const at = body.search(/[?#]/);
    const headBody = at === -1 ? body : body.slice(0, at);
    const query = at !== -1 && body[at] === "?" ? (body.slice(at + 1).split("#")[0] ?? "") : "";
    const headAuthority = headBody.split("/")[0] ?? "";

    const afterPrefix = m.index + prefix.length;
    const fullRaw = (FULL_AUTHORITY.exec(unescaped.slice(afterPrefix)) ?? [""])[0];
    let reachedBound = fullRaw.length >= AUTH_BOUND;
    const fullAuthority = stripEnd(fullRaw, AUTHORITY_TRAIL);
    let tail = fullAuthority.startsWith(headAuthority) ? fullAuthority.slice(headAuthority.length) : "";
    // Text after the `}` that closes a placeholder is literal text of the host: `https://${b}.cdn.evil.example` is a
    // name under cdn.evil.example whatever b holds (wp5-r8-4). Only a port, which may itself be a placeholder, is no host text.
    let afterPlaceholder = false;
    if (tail.startsWith("}") && headAuthority.lastIndexOf("${") > headAuthority.lastIndexOf("}")) {
      tail = tail.slice(1);
      // Placeholders after the first (`https://${host}${path}`) hold text that is not in the source, and a port is no
      // name: only literal characters of a host count.
      afterPlaceholder = tail.replace(/\$\{[\w.]*\}?/g, "").replace(/^:\d*$/, "") !== "";
    }
    // An `@` in the tail makes the head a userinfo. A cut character without one counts only when the whole
    // authority is a host spelled with it (`github.com;x.attacker.io`): a regular expression such as
    // `/^(\/|https:\/\/|http:\/\/)/`, or minified code after an unquoted `https://`, is not a host. The end of the
    // host must not decide, so a port or a punycode label counts (`github.com;x.attacker.io:443`, `...xn--p1ai`, wp5-r5-3).
    const authorityRunsOn =
      afterPlaceholder ||
      tail.includes("@") ||
      (/[)\]}|,;^]/.test(tail) && /^[\p{L}\p{N}._:${}\-,;|^)\]}]*$/u.test(fullAuthority) && /\.[\p{L}\p{N}-]+(?::\d{0,5})?$/u.test(fullAuthority));

    // The authority once more, the way a browser reads it from inside the string the URL sits in (wp5-r8-3): the
    // quotes of the other kinds, a backtick, `<` and `>` are characters of it, and only the quote that opened the
    // string ends it. `"https://github.com'.evil.example/x"` is a name under evil.example, where the extractor, which
    // ends a string at any quote, read github.com. The same test as for the cut characters decides: what follows
    // must hold an `@` or be a host spelled with it.
    const closer = CLOSER.get(unescaped[m.index - 1] ?? "");
    const wideRaw = ((AUTHORITIES.get(closer) ?? AUTHORITIES.get(undefined)).exec(unescaped.slice(afterPrefix)) ?? [""])[0];
    reachedBound ||= wideRaw.length >= AUTH_BOUND;
    const wideAuthority = stripEnd(wideRaw, WIDE_TRAIL);
    const wideTail = wideAuthority.startsWith(fullAuthority) ? wideAuthority.slice(fullAuthority.length) : "";
    const wideRunsOn =
      wideTail !== "" &&
      /['"`<>]/.test(wideTail) &&
      (wideTail.includes("@") || (/^[\p{L}\p{N}._:${}\-,;|^)\]}'"`<>]*$/u.test(wideAuthority) && /\.[\p{L}\p{N}-]+(?::\d{0,5})?$/u.test(wideAuthority)));
    const url = wideRunsOn
      ? `${canonPrefix}${wideAuthority}`
      : authorityRunsOn
        ? `${canonPrefix}${fullAuthority}`
        : stripEnd(`${canonPrefix}${headBody}`, /[.:]/);
    // The rest of the token the string was cut out of, up to white space and at most 256 characters, and not up
    // to a quote, a slash or a backslash, because a hand-written secret can hold any of them (`ci.bot:12345?pw/x@host`,
    // `ci.bot:1234'5@host`).
    const tokenRest = (/^\S{0,256}/.exec(unescaped.slice(afterPrefix + headBody.length)) ?? [""])[0];
    const cutInAuthority = !headBody.includes("/") && tokenRest.includes("@");
    // Whole, with an `@` in its path after an authority that holds a colon (`deploy.bot:4321/aB9x@host`): a
    // browser reads that as host, port and path, but a person may have written user, password and host.
    const colonThenAt = headAuthority.includes(":") && !headAuthority.includes("@") && headBody.slice(headAuthority.length).includes("@");
    // The runtime string goes on in a way that the extractor cannot follow (wp5-r6-1, wp5-r6-2): a backslash right
    // after the authority that is no slash, no backslash and no quote (backslash-b, -f, -v, -0, a malformed -x
    // or -u: `normalise` decoded the ordinary escapes), or a white space character that is not ASCII (a JS `\s`
    // matches it and a host name has none). The host is then not known, and no line explains it.
    const rawAuthority = (RAW_AUTHORITY.exec(unescaped.slice(afterPrefix)) ?? [""])[0];
    reachedBound ||= rawAuthority.length >= AUTH_BOUND;
    const afterRaw = unescaped.slice(afterPrefix + rawAuthority.length);
    // An empty authority (a bare `https://`, as in a regular expression) names no host, so there is nothing to hide.
    // An escaped quote right after the authority is two things the extractor cannot tell apart once decoded: the
    // quote that closes an embedded string (JSON inside a JS string: backslash-quote https://example.com backslash-quote
    // and a bracket) and a literal quote that is part of the host ('https://github.com\'.evil.example/x' reaches the
    // host github.com'.evil.example, wp5-r7-1). So the authority is read once more with an escaped quote as one of its
    // characters: when it then runs on past trailing punctuation, the cut is not trusted. Any other backslash right
    // after the authority is not trusted either. A pair of backslashes is a path separator for a browser, not a part
    // of the host, and is judged as a path (see isCutAtBackslash). VT and FF are no exemption (wp5-r7-3): the URL
    // parser deletes only tab, LF and CR.
    const quoteRaw = (QUOTE_AUTHORITY.exec(unescaped.slice(afterPrefix)) ?? [""])[0];
    reachedBound ||= quoteRaw.length >= AUTH_BOUND;
    const quoteAuthority = stripQuoteTrail(quoteRaw);
    const keptAuthority = stripEnd(rawAuthority, AUTHORITY_TRAIL);
    const quoteTail = quoteAuthority.slice(keptAuthority.length);
    const quoteHost = quoteAuthority.replace(/\\["'`]/g, "'");
    // Minified code follows a closing quote without a gap (`\");return t}`), and that is no host: the authority must
    // either hold an `@` after the quote, or be spelled as a host with the quote in it and end in a label, as in
    // `github.com\'.evil.example`, the same test as for the cut characters above.
    const quoteRunsOn =
      quoteTail !== "" &&
      (quoteTail.includes("@") || (/^[\p{L}\p{N}._:${}\-,;|^)\]}']*$/u.test(quoteHost) && /\.[\p{L}\p{N}-]+(?::\d{0,5})?$/u.test(quoteHost)));
    const odd =
      rawAuthority !== "" &&
      (quoteRunsOn || (afterRaw[0] === "\\" && !/[/\\"'`]/.test(afterRaw[1] ?? "")) || /[^\S\x09\x0a\x0d\x20]/.test(afterRaw[0] ?? ""));
    // A space, VT or FF inside the authority before an `@` is no end of it (wp5-r7-3): the URL parser ends the
    // authority only at / ? # or a backslash, and percent-encodes the gap into the userinfo, so the host is what
    // follows the `@`. `https://github.com @evil.example/x` reaches evil.example. Without an `@` the string stays
    // as it was (`https://x foo`), and the scan stops at a quote and at a line end as everywhere else.
    const gapAuthority = (/^[^/\\?#"'`<>\n\r]{0,256}/.exec(unescaped.slice(afterPrefix)) ?? [""])[0];
    const gapAt = gapAuthority.lastIndexOf("@");
    const spaced = gapAt !== -1 && /[^\S\n\r]/.test(gapAuthority.slice(0, gapAt));
    const wholeUrl = spaced ? `${canonPrefix}${gapAuthority.trimEnd()}` : url;
    const alternative = alternativeOf(unescaped, m.index, prefix, canonPrefix, wholeUrl, query, closer);
    const built = isBuilt(unescaped, m.index, closer);
    // A scan that reached its bound saw nothing of what lies beyond it, so what it found is a guess (wp5-r12-3). Nothing
    // is explained on a guess: the entry is partial, and printed as an authority that is hidden.
    const partial = authorityRunsOn || wideRunsOn || cutInAuthority || colonThenAt || odd || spaced || reachedBound || alternative?.bounded === true || built.bounded;
    const key = `${wholeUrl}\u0000${query}`;
    const before = found.get(key);
    const alt = alternative ?? before?.alt;
    const cutAtBackslash = isCutAtBackslash(unescaped, m.index + raw.length);
    const climbing = hostOf(wholeUrl) !== "" && continuesPast(unescaped, m.index + raw.length);
    // A template literal with a placeholder in its host or path: what the program appends after the `}` is not in the
    // entry, and an exact line must not vouch for it (wp5-r10-3). The text after the matching brace is kept, one per
    // occurrence of the entry.
    const afters = new Set(before?.afters);
    const placeholderAt = headBody.lastIndexOf("${");
    if (placeholderAt !== -1) afters.add(placeholderRemainder(unescaped, afterPrefix + placeholderAt + 2, closer));
    found.set(key, {
      url: wholeUrl,
      query,
      partial: partial || (before?.partial ?? false),
      cut: cutAtBackslash || (before?.cut ?? false),
      climbs: climbing || (before?.climbs ?? false),
      built: built.built || (before?.built ?? false),
      afters: [...afters],
      alt,
    });
  }
}

// A URL that the program builds at run time: its string is closed and a concatenation follows (`"https://github.com/" + repo`,
// `"https://github.com/".concat(o, "/")`). Babel, TypeScript and SWC write a template literal this way for an older
// target, so traced packages carry it. What is extracted is the start of the URL, a page shape, and the rest is
// decided by a variable, so no host line vouches for it (wp5-r10-2), as for a `${` in the path. An exact line can still name it.
//
// Between the closing quote and the `+` there may be white space and comments (`"https://github.com/" /* owner */ + repo`,
// wp5-r11-6). And a break escape or a literal break between the URL and its closing quote does not end the URL: the URL
// parser deletes a tab, LF and CR anywhere, so `"https://github.com/\n" + repo + "/releases/download/..."` is the same
// build as one without the `\n` (wp5-r11-5). Next's own messages end in `\n` before a `+` and are named by exact lines.
// The gate cannot see how a base URL that is kept in a variable, extended with `+=`, passed to `new URL(path, base)` or
// joined from an array is completed: that is a residual of spec 3.5, and the offline run of 17.4 is the proof.
const BUILT_AFTER = /^(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*(?:\n|$))*(?:\+|\.\s*concat\s*\()/;
const BREAKS_STICKY = /(?:\\[tnr]|[\t\n\r])*/y;
const BUILT_TOKENS = new Map(
  [undefined, '"', "'", "`"].map((closer) => [closer, new RegExp(String.raw`^[^${closer ?? String.raw`\s` + QUOTES}\\]{0,${TOKEN_BOUND}}`, "u")]),
);
// The bounded authority scans of collectEntries (wp5-r12-3).
const FULL_AUTHORITY = new RegExp(String.raw`^[^/\\?#\s"'\x60<>]{0,${AUTH_BOUND}}`);
const RAW_AUTHORITY = FULL_AUTHORITY;
const QUOTE_AUTHORITY = new RegExp(String.raw`^(?:[^/\\?#\s"'\x60<>]|\\["'\x60]){0,${AUTH_BOUND}}`);
function isBuilt(text, index, closer) {
  const token = (BUILT_TOKENS.get(closer) ?? BUILT_TOKENS.get(undefined)).exec(text.slice(index))?.[0] ?? "";
  // A token that reaches the bound has an end that is not known, so it is neither built nor not built (wp5-r12-3).
  if (token.length >= TOKEN_BOUND) return {built: false, bounded: true};
  BREAKS_STICKY.lastIndex = index + token.length;
  BREAKS_STICKY.test(text);
  const stop = BREAKS_STICKY.lastIndex;
  const quote = text[stop];
  return {built: quote !== undefined && QUOTES.includes(quote) && BUILT_AFTER.test(text.slice(stop + 1, stop + 513)), bounded: false};
}

// What stands in for the text after a placeholder whose closing brace cannot be found: it is no page and no host-only
// string, so nothing explains it.
const UNKNOWN_REMAINDER = "${…";
/**
 * The text after the `}` that closes the placeholder opened right before `from`, up to the end of its string (white space or
 * a quote when the string is unknown), as written. The expression inside may hold braces and quotes of its own
 * (`${req.headers.host || 'localhost'}`), so the closing brace is found by counting.
 */
function placeholderRemainder(text, from, closer) {
  let depth = 1;
  let close = -1;
  for (let i = from; i < Math.min(text.length, from + 256); i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) {
      close = i;
      break;
    }
  }
  if (close === -1) return UNKNOWN_REMAINDER;
  // The remainder is read the way the URL parser reads it (wp5-r11-4): a backslash, as a JS pair or alone, is a slash, and a
  // tab, line feed and carriage return are deleted, so `${r}\\x.zip` is `${r}/x.zip` and `${r}\\..\\..\\dl` climbs. And
  // it is never a prefix: when its end is not reached within the bound, nothing is known about what follows.
  const bound = close + 1 + 256;
  let out = "";
  for (let j = close + 1; ; j++) {
    if (j >= text.length) return out;
    if (j >= bound) return UNKNOWN_REMAINDER;
    const c = text[j];
    if (c === "\t" || c === "\n" || c === "\r") continue;
    if (closer !== undefined ? c === closer : QUOTES.includes(c) || /\s/.test(c)) return out;
    if (c !== "\\") {
      out += c;
      continue;
    }
    const next = text[j + 1];
    if (next !== undefined && QUOTES.includes(next)) {
      // Placeholders exist in template literals, where an escaped quote is an ordinary character, and the URL parser
      // keeps it in the path (or percent-encodes it) and goes on (wp5-r12-2): `${r}\"/../../dl/x.tar.xz` climbs.
      if (closer === "`") {
        out += next;
        j++;
        continue;
      }
      // The closer is unknown (or a quote of the kind that does not open a template): the quote may close an embedded
      // string, which is no part of the URL. Path text after it is the isCutAtBackslash rule: the URL goes on, so what
      // the end holds is not known.
      return isCutAtBackslash(text, j) ? UNKNOWN_REMAINDER : out;
    }
    if (next === "t" || next === "n" || next === "r") j++; // a break escape is deleted
    else {
      out += "/";
      if (next === "\\") j++; // a pair is one backslash at run time
    }
  }
}

/**
 * True when the string ended at a backslash that a browser or the runtime reads as more of the same URL (wp5-r7-2,
 * wp5-r7-4). A backslash in the path of an http, https, ws or wss URL is a slash for the URL parser (a JS `\\` pair
 * is one such backslash at run time), and the other escapes that survive `normalise` (an escaped quote, `\b`, a
 * malformed `\x`) are characters of the string too, so the path goes on past the cut and only its start was
 * judged. A `\n`, `\r` or `\t` is a break, which `alternativeOf` reads, and a backslash before white space or at
 * the end of the text goes nowhere. `explain` never lets a host line vouch for such a string.
 */
function isCutAtBackslash(text, end) {
  if (text[end] !== "\\") return false;
  const next = text[end + 1];
  if (next === undefined || /\s/.test(next) || /[ntr]/.test(next)) return false;
  if (/["'`]/.test(next)) {
    // An escaped quote is a literal character of the string or the end of an embedded one. It continues the URL when
    // path text follows it, up to white space or a quote, and not only punctuation or a break.
    const rest = stripEnd((/^[^\s"'`<>]*/.exec(text.slice(end + 2)) ?? [""])[0].replace(/\\[ntr]/g, ""), /[.:,;)\]}|^\\]/);
    return rest !== "";
  }
  return true;
}

/**
 * True when a string that ended at a backslash goes on, for the URL parser, in a way that leaves what an exact `url`
 * line named (wp5-r9-4): a dot segment or an encoded separator after the cut, or a path backslash, which the parser
 * reads as a slash (a pair of backslashes, a lone one before an ordinary character). A backslash before a quote, a
 * break or white space only closes or splits a string, and what follows it is code (`new URL(\"https://example.com\");`),
 * which is no part of the URL. A bare scheme with no host (`https:\/\/\*\.verify`, a regular expression) has nothing to
 * climb to, so it is never asked (the caller passes it by checking the host).
 */
function continuesPast(text, end) {
  if (text[end] !== "\\") return false;
  const continuation = (/^\S{0,256}/.exec(text.slice(end)) ?? [""])[0].replaceAll("\\", "/");
  if (PATH_TRICK.test(continuation)) return true;
  const next = text[end + 1];
  return next !== undefined && !/["'`ntr\s]/.test(next);
}

/**
 * The wide reading of a string (wp5-r6-2, wp5-r8-2). A browser's URL parser deletes a tab, line feed and carriage
 * return anywhere in a URL, and ends the URL at the end of the string it sits in, not at a bracket, a comma or a
 * quote of another kind, which are characters of the path. So `https://github.com/o/r/re\nleases/download/v1/tool` is a
 * release download although the string is cut at the break and reads as a page, and so is
 * `"https://github.com/o/r)/../../o/r/releases/download/v1/tool"`, which is cut at the `)`. The wide reading is the
 * token from the scheme to the end of its string (the quote that opened it, white space included, or white space and
 * any quote for a URL in the middle of a message: see CLOSER) with its
 * breaks deleted and its trailing punctuation dropped, or undefined when it is the string itself. It matters for one
 * decision only, whether a link is a page (`isLoadable`): a `host` line explains a string only when this reading is a page
 * too. An exact `url` line names the string as it is written and ignores it. The token stops at a `${`, so the next
 * line of a comment, or the code after a message's `\n`, does not become part of the path. Its trailing punctuation is
 * dropped, so a link in a sentence or in a markdown bracket is the page it names.
 */
function alternativeOf(unescaped, index, prefix, canonPrefix, url, query, closer) {
  const token = (TOKENS.get(closer) ?? TOKENS.get(undefined)).exec(unescaped.slice(index))?.[0];
  if (token === undefined || token.length < prefix.length) return undefined;
  // The token is bounded (wp5-r12-3): when it reaches the bound, its end, and so its path, is not known.
  const bounded = token.length >= TOKEN_BOUND;
  const merged = token.replace(BREAKS, "");
  const rest = merged.slice(prefix.length);
  const at = rest.search(/[?#]/);
  const head = stripEnd(at === -1 ? rest : rest.slice(0, at), TRAILING_PUNCTUATION);
  const altQuery = at !== -1 && rest[at] === "?" ? (rest.slice(at + 1).split("#")[0] ?? "") : "";
  const altUrl = stripEnd(`${canonPrefix}${head}`, /[.:]/);
  return altUrl === url && altQuery === query && !bounded ? undefined : {url: altUrl, query: altQuery, bounded};
}
const TRAILING_PUNCTUATION = /[\s.,;:!)\]}>'"`*|^]/;
const AUTHORITY_TRAIL = /[.:,;)\]}|^]/;
const WIDE_TRAIL = /[.:,;)\]}|^'"`>*!]/;
/** Trailing punctuation of an authority that may also end in an escaped quote (a backslash and a quote). */
function stripQuoteTrail(text) {
  let end = text.length;
  for (;;) {
    if (end > 0 && AUTHORITY_TRAIL.test(text[end - 1])) end--;
    else if (end > 1 && text[end - 2] === "\\" && QUOTES.includes(text[end - 1])) end -= 2;
    else break;
  }
  return text.slice(0, end);
}

/** The strings of one file, as `extractUrlEntries` finds them, once each. */
export function extractUrls(text) {
  return [...new Set(extractUrlEntries(text).map((e) => e.url))];
}

/** Scheme (or the leading `//`), authority and the rest. The authority ends at the first / ? or #, as a browser reads it. */
// The dots a browser's host parser maps to U+002E (U+3002, U+FF0E, U+FF61).
const IDEOGRAPHIC_DOTS = /[。．｡]/g;
const SPLIT_URL = /^((?:[a-z]+:)?\/\/)([^/?#]*)(.*)$/is;

/**
 * The host part, lower case, the way a browser reads it: the authority ends at the first / ? or #, the
 * userinfo is everything up to the last @ of it, and the port is dropped. So `https://github.com:pw@evil.example`
 * is evil.example, and `https://evil.example?a@github.com` is evil.example too. A placeholder such as
 * `${origin` is its own host, and no `host` line names it.
 */
export function hostOf(url) {
  const m = SPLIT_URL.exec(url);
  if (!m) return "";
  const authority = m[2];
  const afterUserinfo = authority.slice(authority.lastIndexOf("@") + 1);
  return (afterUserinfo.split(":")[0] ?? "").replace(IDEOGRAPHIC_DOTS, ".").toLowerCase();
}

// An authority is printed only when all of it is a host name, an address or a placeholder, and it holds no colon.
// A colon is where a user name ends and a password begins, and a cut (a quote, a space, a bracket) can leave
// `ci.bot:1234` behind, which looks like a host and a port. So a port is never printed either: an unexplained
// `host:port` shows as hidden, which costs a reviewer nothing, since the file is named and --reveal exists (wp5-r4-1).
const PRINTABLE_HOST = /^(?:(?:[a-z0-9_-]+\.)+[a-z0-9-]+|localhost|\$\{[\w.]*)$/i;

/**
 * What a report may show of a URL: scheme, host and how long the rest is, never the rest. A secret can
 * be in the userinfo (https://user:pw@h), in the path (/services/T0/B0/<secret>, /bot<token>/) or in a
 * query, and a CI log keeps what it is given. The file is named beside it, so the reviewer reads the
 * string there. `partial` is the flag of `extractUrlEntries`: the authority was cut before an `@` and is
 * hidden whatever it looks like.
 */
export function printable(url, partial = false) {
  const m = SPLIT_URL.exec(url);
  if (!m) return `(${url.length} characters, not a URL)`;
  const [, scheme, authority, rest] = m;
  const at = authority.lastIndexOf("@");
  const host = (at === -1 ? authority : authority.slice(at + 1)).replace(IDEOGRAPHIC_DOTS, ".");
  const notes = [];
  let shown = host;
  if (partial || !PRINTABLE_HOST.test(host)) {
    shown = `[authority of ${authority.length} characters hidden]`;
  } else if (at !== -1) {
    notes.push("userinfo hidden");
  }
  if (rest.length > 0) notes.push(`path of ${rest.length} characters hidden`);
  return `${scheme}${shown}${notes.length > 0 ? `  [${notes.join(", ")}]` : ""}`;
}

/**
 * Lines are `url <strings> [in <part>] # reason` and `host <names> # reason`. A line without a
 * reason is an error, like in check-licences.mjs, because the reason is the whole point.
 */
export function parseAllow(text) {
  const rules = [];
  const problems = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const at = i + 1;
    const [decision = "", ...reason] = line.split(" # ");
    if (reason.join(" # ").trim() === "") return problems.push(`line ${at}: no reason after " # ": ${line}`);
    const words = decision.trim().split(/\s+/);
    const kind = words.shift();
    if (kind !== "url" && kind !== "host") return problems.push(`line ${at}: must start with "url" or "host": ${line}`);
    let scope;
    const inAt = words.indexOf("in");
    if (inAt !== -1) {
      if (kind === "host") return problems.push(`line ${at}: "in" is for url lines only: ${line}`);
      scope = words.slice(inAt + 1).join(" ");
      words.splice(inAt);
      if (scope === "") return problems.push(`line ${at}: "in" needs a path part: ${line}`);
    }
    if (words.length === 0) return problems.push(`line ${at}: nothing to allow: ${line}`);
    if (kind === "host" && words.some((w) => w.includes("/") || w.includes(":"))) {
      return problems.push(`line ${at}: a host is a name only, no scheme, port or path: ${line}`);
    }
    rules.push({kind, values: words.map((w) => (kind === "host" ? w.toLowerCase() : w)), scope, line: at, used: new Set()});
  });
  return {rules, problems};
}

// A `host` line is for what we did not write. The compiled code of this repository (`.next/server`) is
// checked string by string, since a host that serves content (a search engine, a video site, a code
// host) is a real destination when our own code, or a dependency bundled into it, names it.
const inVendorCode = (path) => path.startsWith(".next/standalone/") && /(^|\/)node_modules\//.test(path);
const isVendorMetadata = (path) => /(^|\/)node_modules\//.test(path) && VENDOR_METADATA.test(path);

// A `host` line vouches for one thing only: a link to a PAGE (documentation, a specification, an issue). It
// never vouches for what a program loads or downloads. A deny-list of such things cannot be complete (each round
// found one more: a release asset, a `.tar.xz`, a Git LFS `/media/`, `/info/refs`, `/releases/expanded_assets/`),
// so the rule is the other way round: a link is a page only when its last path segment has no extension or ends
// in .html or .htm, and it is not under a folder that serves files or Git (`media`, `info`, `releases` except a
// release's own page `releases/tag/`, `archive`, `raw`, `zipball`, `tarball`). Anything else is left to an exact
// `url` line, whatever the host is. A repository host such as github.com is then safe as a documentation host in
// a comment and is still refused as the place a dependency downloads something from.
const FILE_FOLDER = /\/(?:media|info|archive|raw|zipball|tarball|releases(?!\/tag\/))(?:\/|$)/i;
const PAGE_EXTENSION = /^\.html?$/i;
// A link whose query asks for the file itself (`?raw=true`, `?download`) is a download, whatever the path says.
const QUERY_LOADS = /(?:^|[&;])(?:raw|download)(?:[=&;]|$)/i;
// A path that climbs (`..`) or hides a slash (`%2f`, `%5c`, `%2e`) names a file the host decides on, not a page.
const PATH_TRICK = /(?:^|\/)\.\.(?:\/|$)|%2e|%2f|%5c/i;
// What a run-time placeholder leaves unknown (wp5-r9-1, wp5-r9-3). The extractor ends a string at the `}` of a
// placeholder, so the text after it (`/releases/download/`, `.zip`, `/../`) is never read, and a program decides the
// placeholder's value. A link like that is no page to a host line, not even a viewer page: an exact `url` line names
// it, as the mkcert line does.
const PLACEHOLDER = /\$\{/;
// A percent escape in a path: a host may decode it before routing (`%72eleases` is `releases`), so the path is not
// what it looks like. A viewer page stays a page, as the URL parser's own `x%20x.zip` encoding of a space shows.
const PERCENT = /%/;
// A source viewer's page names a file too (github.com/o/r/blob/<sha>/x.js) and is a page, which comments
// cite by the hundred. It is the page of a repository, so `/blob/` must be the third segment: anywhere
// else in the path it proves nothing.
const VIEWER_PAGE = /^\/[^/]+\/[^/]+\/(?:blob|tree|commit|issues|pull|wiki|discussions)(?:\/|$)/i;
// A path with no extension that starts with one of these is something a program calls, on any host: an endpoint
// is not a page (wp5-r4-2). A `.html` page under /api/ is one (nodejs.org/api/fs.html), and so is a source viewer
// page of an organisation that is called "graphql".
const ENDPOINT_ROOT = /^\/(?:api|login|oauth2?|auth|graphql|socket(?:\.io)?|ws|websocket|rpc|token)(?:\/|$)/i;
/**
 * A bare origin (`https://github.com`, no path at all) is a base that a program extends (`new URL(path, base)`, `base + path`,
 * a variable), not a link to a page (wp5-r11-6): a host line never explains it, and an exact `url` line can. A comment
 * that cites a site's home page is the one thing this costs, and the real builds have one.
 */
// A path of slashes only is bare too (wp5-r12-1): `new URL` writes every bare origin as `https://github.com/`, and the
// usual way to write a base for `B + path` keeps that slash. (`https://github.com//` and `//github.com/` are the same base.)
const isBareOrigin = (url) => /^\/*$/.test(SPLIT_URL.exec(url)?.[3] ?? "x");

/** True when the link is not a page. `query` is what followed the `?`, which `extractUrlEntries` keeps for this. */
export function isLoadable(url, query = "") {
  const path = url.replace(/^(?:[a-z]+:)?\/\/[^/]*/, "");
  // A placeholder in the query is as unknown as one in the path: GitHub answers a blob page with `?raw=true` by
  // redirecting to the raw file, and a program decides what the placeholder holds (wp5-r10-2).
  if (QUERY_LOADS.test(query) || PLACEHOLDER.test(query) || PATH_TRICK.test(path) || PLACEHOLDER.test(path)) return true;
  if (VIEWER_PAGE.test(path)) return false;
  if (PERCENT.test(path)) return true;
  if (FILE_FOLDER.test(path)) return true;
  const last = path.split("/").pop() ?? "";
  // An extension has a letter in it: ".9" in /schemas/sitemap/0.9 is a version number, ".7z" and ".mp4" are files.
  // Only the last dot can start one (a regular expression for this is retried at every dot and is quadratic).
  const lastDot = last.lastIndexOf(".");
  const extension = lastDot !== -1 && /[a-z]/i.test(last.slice(lastDot + 1)) ? last.slice(lastDot) : undefined;
  if (extension !== undefined) return !PAGE_EXTENSION.test(extension);
  return ENDPOINT_ROOT.test(path);
}
/**
 * Which rule explains this URL in this file, if any. `path` is relative to the app folder, with `/`. A host
 * line vouches for documentation links, so it covers http, https and scheme-relative strings only: a ws: or
 * wss: string is a socket and is never a link (wp5-r4-2). An exact `url` line can still name one.
 */
export function explain(url, path, rules, query = "", partial = false, alt = undefined, cut = false, climbs = false, built = false, afters = undefined) {
  // A partial string was cut where its runtime host is not known (see extractUrlEntries): never explained, since a
  // line names the part before the cut and the program reaches something else (wp5-r4-1, wp5-r6-2).
  if (partial) return undefined;
  const host = hostOf(url);
  const scheme = /^([a-z]+):/i.exec(url)?.[1]?.toLowerCase();
  const documentation = scheme === undefined || scheme === "http" || scheme === "https";
  for (const rule of rules) {
    if (rule.kind === "url") {
      // An exact line names the string as it is written, but not a string whose runtime path climbs away from what the
      // line vouched for (wp5-r9-4): one cut at a bracket, a comma or a quote with a dot segment after the cut
      // (`https://github.com/vercel/next.js)/../../o/r/releases/download/v1/tool`), or one cut at a backslash that goes
      // on with a dot segment, an encoded separator or a path backslash (`climbs`, see `continuesPast`). A line that
      // has to name such a string lists it on purpose, which cannot happen by accident.
      if (climbs || (alt !== undefined && PATH_TRICK.test(alt.url.replace(/^(?:[a-z]+:)?\/\/[^/]*/, "")))) continue;
      if (rule.scope !== undefined && !path.includes(rule.scope)) continue;
      // An entry with a placeholder in its host or path (`https://nextjs.org/docs/messages/${r`) has more after the `}`
      // than the entry shows (wp5-r10-3). A line names the entry as it is written, and would then vouch for any text
      // after the brace, a climb to a download included. So each text that follows must be one that no program can
      // turn into a download (see `afterOk`), or the line must name the whole template, brace and remainder included
      // (the mkcert line does).
      const open = afters !== undefined && afters.length > 0;
      const names = (after) => rule.values.includes(`${url}}${after}`);
      if (open && afters.every(names)) return rule;
      if (rule.values.includes(url) && (!open || afters.every((after) => names(after) || afterOk(url, query, after)))) return rule;
    } else if (documentation && inVendorCode(path) && host !== "" && rule.values.includes(host) && !cut && !built && !isBareOrigin(url) && !isLoadable(url, query) && (alt === undefined || !isLoadable(alt.url, alt.query))) {
      return rule;
    }
  }
  return undefined;
}

/**
 * Whether the text that follows the `}` of a placeholder leaves an exact line's string a string the line can name
 * (wp5-r10-3). When the placeholder is the host (`https://${b`), whatever b holds, the template must close there or go
 * on with a port: a path after it is a path on a host that a program chooses (`/releases/download/v1/tool`). When it
 * is in the path, the template must still be a page: no dot segment, no encoded separator, no file folder, no extension,
 * no placeholder, no query that asks for the file (`isLoadable` on the template with the placeholder read as a plain
 * word). The punctuation of a sentence around a link is dropped.
 */
function afterOk(url, query, after) {
  const rest = stripEnd(after, TRAILING_PUNCTUATION);
  const authority = SPLIT_URL.exec(url)?.[2] ?? "";
  if (authority.includes("${")) return rest.replace(/^:(?:\$\{[^}]*\}?|\d*)/, "") === "";
  const at = rest.search(/[?#]/);
  const path = at === -1 ? rest : rest.slice(0, at);
  const afterQuery = at !== -1 && rest[at] === "?" ? (rest.slice(at + 1).split("#")[0] ?? "") : "";
  // The placeholder that is still open at the end of the entry is read as a plain word. (A `lastIndexOf` and not an
  // unanchored `\$\{[^}]*$`, which is retried at every `${` of a long string.)
  const open = url.lastIndexOf("${");
  const closed = open === -1 || url.includes("}", open);
  return !isLoadable((closed ? url : `${url.slice(0, open)}x`) + path, [query, afterQuery].join("&"));
}

/** `explain` for one entry of `extractUrlEntries`: every field that the decision needs. */
export function explainEntry(entry, path, rules) {
  return explain(entry.url, path, rules, entry.query, entry.partial, entry.alt, entry.cut, entry.climbs, entry.built, entry.afters);
}

/**
 * The files under `dir`, following links once (pnpm's node_modules is a tree of them).
 *
 * The gate fails closed (wp5-r13-2): a folder that cannot be listed, or an entry that cannot be inspected for a
 * reason other than "it is not there", stops the run with the path named, because a subtree that was skipped is a
 * subtree that was never scanned, and the summary would still say every string is explained. Only a link whose
 * target does not exist (ENOENT) is left out, and `counts.dangling` says how many, so the summary line shows it.
 * `io` is a seam for the tests: a folder that cannot be read is hard to make the same way on every system.
 */
function* walk(dir, counts, io, seen = new Set()) {
  let entries;
  try {
    entries = io.readdirSync(dir, {withFileTypes: true});
  } catch (error) {
    throw new Error(`cannot list ${dir}: ${error.code ?? error.message}. The scan would skip everything below it`, {cause: error});
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    let info;
    try {
      info = io.statSync(path);
    } catch (error) {
      if (error.code !== "ENOENT") throw new Error(`cannot inspect ${path}: ${error.code ?? error.message}`, {cause: error});
      counts.dangling++; // a dangling link
      continue;
    }
    if (info.isDirectory()) {
      const real = io.realpathSync(path);
      if (seen.has(real)) continue;
      seen.add(real);
      yield* walk(path, counts, io, seen);
    } else if (info.isFile()) {
      yield path;
    }
  }
}

// A NUL byte is legal in a JS comment or string (`/*\0*/` runs under Node and in a browser), and Node loads a file
// with no extension as JavaScript, so a NUL says nothing about whether a file is code (wp5-r4-6, wp5-r5-5). Only a
// name on the BINARY list is skipped, and it is counted. Any other file is scanned, and how it is read depends on
// what the bytes are (wp5-r6-3):
//   - A UTF-16 file, with a byte order mark or with a NUL on every other byte, is decoded as UTF-16. A browser
//     decodes a classic script, an HTML page or an SVG by its BOM, and read as latin1 every ASCII character of it
//     is followed by a NUL, so no URL would match.
//   - Any other file with a NUL is scanned twice: as UTF-8, which keeps a Unicode host (`//пример.рф/x.js`), and
//     as latin1 with the NULs removed, which keeps what a NUL inside a word breaks. The two texts are joined.
//   - A file without a NUL is UTF-8.
export function decode(buffer) {
  const swapped = (bytes) => Buffer.from(bytes.subarray(0, bytes.length - (bytes.length % 2))).swap16().toString("utf16le");
  if (buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.toString("utf16le");
  if (buffer[0] === 0xfe && buffer[1] === 0xff) return swapped(buffer);
  const sample = buffer.subarray(0, 8000);
  const pairs = sample.length >> 1;
  let even = 0;
  let odd = 0;
  for (let i = 0; i + 1 < sample.length; i += 2) {
    if (sample[i] === 0) even++;
    if (sample[i + 1] === 0) odd++;
  }
  // ASCII text in UTF-16 has a NUL in every other byte. A minified file with one NUL has none to speak of.
  if (pairs >= 2 && odd > pairs * 0.3 && even <= pairs * 0.05) return buffer.toString("utf16le");
  if (pairs >= 2 && even > pairs * 0.3 && odd <= pairs * 0.05) return swapped(buffer);
  if (!buffer.includes(0)) return buffer.toString("utf8");
  return `${buffer.toString("utf8")}\n${buffer.toString("latin1").replaceAll("\u0000", "")}`;
}

/**
 * Scans one app folder. Returns the strings no rule explains, with the first file of each, and
 * how many files and strings were looked at.
 */
export function scanApp(appDir, rules, io = {readdirSync, statSync, realpathSync}) {
  const unexplained = new Map();
  let files = 0;
  let strings = 0;
  let skipped = 0;
  const counts = {dangling: 0};
  const roots = [".next/static", ".next/standalone", "public"];
  for (const rootName of roots) {
    const root = join(appDir, rootName);
    if (!existsSync(root)) {
      if (rootName === "public") continue;
      throw new Error(`${root} does not exist: run \`next build\` for this app first`);
    }
    for (const file of walk(root, counts, io)) {
      // A logical path with `/`, from the app folder: symlinks are not resolved, so a package that pnpm
      // links under node_modules is still "in node_modules".
      const path = relative(appDir, file).split("\\").join("/");
      if (isVendorMetadata(path)) continue;
      if (BINARY.test(path)) {
        skipped++;
        continue;
      }
      files++;
      for (const entry of extractUrlEntries(decode(readFileSync(file)))) {
        const {url, partial} = entry;
        strings++;
        const rule = explainEntry(entry, path, rules);
        if (rule) rule.used.add(url);
        else if (!unexplained.has(url)) unexplained.set(url, {path, count: 1, partial});
        else {
          const seen = unexplained.get(url);
          seen.count++;
          seen.partial ||= partial;
        }
      }
    }
  }
  return {unexplained, files, strings, skipped, dangling: counts.dangling};
}

/** What the allow file holds that nothing matched, split into lines that fail and lines that only warn. */
export function staleLines(rules) {
  const fail = [];
  const warn = [];
  for (const rule of rules) {
    for (const value of rule.values) {
      // A line that names a whole template (`url}remainder`) is matched by the entry that ends at its open placeholder.
      const matched = rule.kind === "host" ? [...rule.used].some((u) => hostOf(u) === value) : rule.used.has(value) || [...rule.used].some((u) => value.startsWith(`${u}}`));
      if (matched) continue;
      // Only an unscoped url line is the same on every machine: the browser bundle's strings.
      (rule.kind === "url" && rule.scope === undefined ? fail : warn).push(`line ${rule.line}: ${rule.kind} ${value}`);
    }
  }
  return {fail, warn};
}

export function main(argv) {
  const apps = [];
  let reveal = false;
  let root = resolve(here, "..");
  // `--allow` is kept apart and the default is worked out after the loop, so that the order of the arguments
  // does not change which file is read (wp5-r4-4).
  let allowArg;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--app") apps.push(argv[++i]);
    else if (argv[i] === "--reveal") reveal = true;
    else if (argv[i] === "--root") root = resolve(argv[++i]);
    else if (argv[i] === "--allow") allowArg = resolve(argv[++i]);
    else {
      console.error(`check-web-bundle: unknown argument ${argv[i]}`);
      return 2;
    }
  }
  const allowFile = allowArg ?? join(root, "tools/web-lint/bundle-url-allow.txt");
  const all = apps.length === 0;
  if (all) apps.push("panel", "admin");

  const {rules, problems} = parseAllow(readFileSync(allowFile, "utf8"));
  if (problems.length > 0) {
    console.error(`check-web-bundle: the allow file has ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join("\n")}`);
    return 1;
  }

  let failed = false;
  for (const app of apps) {
    let result;
    try {
      result = scanApp(join(root, "apps", app), rules);
    } catch (error) {
      console.error(`check-web-bundle: ${error.message}`);
      return 1;
    }
    const skipped = (result.skipped > 0 ? `, ${result.skipped} binary file(s) skipped` : "") + (result.dangling > 0 ? `, ${result.dangling} dangling link(s) not followed` : "");
    console.log(`check-web-bundle: ${app}: ${result.files} files, ${result.strings} URL strings${skipped}`);
    if (result.unexplained.size > 0) {
      failed = true;
      console.error(`  ${result.unexplained.size} URL string(s) that bundle-url-allow.txt does not explain:`);
      // Strings that print the same (the same host, a path of the same length) are one line, with how many.
      const lines = new Map();
      for (const [url, {path, count, partial}] of result.unexplained) {
        const shown = reveal ? url : printable(url, partial);
        const line = lines.get(shown);
        if (line) line.strings++;
        else lines.set(shown, {path, count, strings: 1});
      }
      for (const [shown, {path, count, strings}] of lines) {
        const more = [strings > 1 ? `${strings} strings like it` : "", count > 1 ? `${count - 1} more in that file` : ""].filter(Boolean).join(", ");
        console.error(`    ${shown}   (${path}${more ? `, ${more}` : ""})`);
      }
    }
  }

  // Stale lines are only meaningful when both apps were scanned: a string may belong to one of them.
  if (all) {
    const {fail, warn} = staleLines(rules);
    if (warn.length > 0) console.log(`check-web-bundle: ${warn.length} allow line(s) matched nothing on this machine (reported, not failed):\n${warn.map((w) => `  ${w}`).join("\n")}`);
    if (fail.length > 0) {
      failed = true;
      console.error(`check-web-bundle: ${fail.length} stale allow line(s), remove them:\n${fail.map((w) => `  ${w}`).join("\n")}`);
    }
  }

  if (failed) {
    console.error("check-web-bundle: FAILED. A new URL string is a review item: read where it comes from, then add one line with the reason.");
    return 1;
  }
  console.log("check-web-bundle: every URL string is explained");
  return 0;
}


// Run as a command, not when imported. Node resolves the symlinks of the main module, so `import.meta.url` is a
// real path and `process.argv[1]` is the path as it was typed: through a symlink, a junction or a path that
// differs in case or drive letter on Windows they differ, and comparing them would run nothing and exit 0, which
// is a green gate that scanned nothing. Both sides go through the real path, in the form Windows reports.
function isMain() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync.native(fileURLToPath(import.meta.url)) === realpathSync.native(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMain()) process.exit(main(process.argv.slice(2)));
