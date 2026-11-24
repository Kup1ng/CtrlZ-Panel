# Notice for words.txt

`words.txt` is a derivative of the Persian word frequency list `fa_50k.txt` of the FrequencyWords project
(https://github.com/hermitdave/FrequencyWords, by Hermit Dave), whose content is derived from the
OpenSubtitles2018 corpus (https://opus.nlpl.eu/OpenSubtitles2018.php).

- Licence of the content: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0),
  https://creativecommons.org/licenses/by-sa/4.0/. The project's own README gives MIT for its code and
  CC BY-SA 4.0 for its content.
- Changes made: every word is put in one normal form (NFKC, the Arabic yeh and kaf written as the Persian
  letters, the hamza forms of alef as alef, diacritics, tatweel and invisible characters removed), entries
  that are not a word of two to twenty-four letters of the Arabic script are dropped, duplicates of the
  folded form are dropped, and the counts are removed: the line number is the rank. See `SOURCE.txt`.
- The list stays under CC BY-SA 4.0. It is used by `internal/auth/pwstrength` only to recognise common
  words in a new password, offline and compiled in; it is never fetched at run time and no leaked password
  dump is part of it.
- The third-party notices of the product name it (docs/licences/frequencywords-fa.md).
