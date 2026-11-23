# FrequencyWords, Persian list (P1 auth review round 18, primitives-r18-1)

**Outcome: allowed, with the notice below shipped.**

The strength gate of `internal/auth/pwstrength` embeds a ranked list of Persian words so that a password in
Persian letters is not scored as random text (D64 `persian-passwords`).

## What it is

| Item | Value |
|---|---|
| Source | `fa_50k.txt` of FrequencyWords by Hermit Dave, commit `525f9b560de45753a5ea01069454e72e9aa541c6`, path `content/2018/fa/fa_50k.txt` |
| Derived from | the OpenSubtitles2018 corpus (opus.nlpl.eu) |
| Licence of the content | Creative Commons Attribution-ShareAlike 4.0 International (the project README: MIT for code, CC BY-SA 4.0 for content) |
| SHA-256 of the source | `96ea178f77022cdb2d358feb75a4fc474754daa224a4beba296ad777a514bdf7` |
| Approved | by the owner, Plan.md D64 (question 12); downloaded 2026-11-20 |
| In the repository | `internal/auth/pwstrength/persian/words.txt` (36,969 words, folded, one per line, rank = line number), `SOURCE.txt`, `NOTICE.md` |
| Not in the repository | the source file (50,000 lines of third-party content); the generator (`persian_gen_test.go`) refuses any file with another hash |

## Conditions

1. **Attribution and share-alike.** `words.txt` is an adaptation of the source (words put in one normal form,
   entries that are not words dropped, counts removed). It stays under CC BY-SA 4.0, and
   `internal/auth/pwstrength/persian/NOTICE.md` ships beside it with the source, the licence and the changes.
   The third-party notices file of the release (P8 release work) names it, with the same text.
2. **Scope of the licence.** The licence covers the list, not the program that reads it: the list is data compiled
   in and read by a few functions, not a work the Panel's code is a derivative of. If the owner wants a counsel's
   reading before the release, this is the question.
3. **Offline.** The list is compiled into the binary and read from memory. Nothing is fetched at run time.
4. **No leaked password dump.** The source is film subtitles; a list of leaked passwords is never part of it.

## Not checked

- The licence text on creativecommons.org was not re-read; the project README is what states the licence.
