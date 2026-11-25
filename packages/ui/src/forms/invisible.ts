// The request schemas of the API refuse every string that holds a control, format or private-use character
// (`pattern: ^[^\p{C}]*$`, AUTH 8a), and they do it before any handler runs, so the answer is a bare 400
// `bad_request` that no field can show and that reloading cannot cure. The characters a visitor meets in
// practice are format characters: a phone number copied from Telegram, Contacts or a Persian page carries
// U+200E or U+200F (wp8-r10-1). The passwords also accept U+200C, the half-space, which the server removes (hasInvisiblePassword);
// a name accepts it and the server drops it (cleanName). One helper per kind of value, so the rule is the
// same on every screen and in the API layer.

// Go's regexp (kin-openapi) reads \p{C} as Cc, Cf, Co and Cs only. JavaScript's \p{C} also holds Cn, the code
// points the browser has no data for (a newer emoji, U+0378), which the API accepts. So the class is spelled out
// here, and a character the browser does not know yet is never refused (wp8-r13-2).
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}]/gu;
const ANY_INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}]/u;

/** A phone number is a token: the invisible characters are dropped, since the server would have ignored them anyway. */
export const stripInvisible = (value: string) => value.replace(INVISIBLE, "");

/**
 * A value that is not a password and takes no half-space (a username, an rp_id, a gateway credential): it is refused
 * with a message when it holds any control, format or private-use character, U+200C included. Their patterns are
 * `content` or `text`, which have no exception.
 */
export const hasInvisible = (value: string) => ANY_INVISIBLE.test(value);

const HALF_SPACE = /\u200c/gu;

/**
 * A password is never changed on the visitor's behalf, because what they typed is what they must be able to type
 * again, so one that holds an invisible character is refused with a message before it is sent. Except U+200C: main's
 * `prose` pattern lets the half-space through and `password.Normalize` removes it at set and at verify, so a password is
 * the same with or without it (D64 zwnj-fields: refusing it "sent Persian users into a loop of refusals"). The Persian
 * keyboard types it on Shift+B inside a word, and a visitor cannot know whether they pressed it. It is sent as typed.
 */
export const hasInvisiblePassword = (value: string) => ANY_INVISIBLE.test(value.replace(HALF_SPACE, ""));

/**
 * A name the visitor chose for something (a passkey), made ready for the API. Names are not secrets, so unlike a
 * password nothing is refused: every control, format and private-use character is dropped (a name pasted from Telegram
 * with an RLM would get a bare 400 `bad_request` that no field can show), and the ends are trimmed after that, so a stray
 * invisible character cannot hide a space from the trim. The half-space goes too. The schema of a name (`prosecontent`)
 * lets U+200C through, but the handler removes it before it stores the name (routes_passkey.go, D64 zwnj-fields), so the
 * list shows the name without it. Sending it that way makes the limit of 64 characters the server's count, and what the
 * visitor sees after a save is what they typed here (P1 web merge, B5, review round 1).
 */
const NOT_NAME = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}]/gu;

export const cleanName = (value: string) => value.replace(NOT_NAME, "").trim();

/** Length in code points, as the server counts (utf8.RuneCountInString), not UTF-16 units: an emoji is one. */
export const nameLength = (value: string) => Array.from(value).length;
