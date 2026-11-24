package pwstrength

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// The generator of the embedded Persian list (round 18, primitives-r18-1, D64 persian-passwords).
//
// The list is built once from FrequencyWords' fa_50k.txt (hermitdave/FrequencyWords, commit 525f9b5,
// content CC-BY-SA 4.0, derived from OpenSubtitles2018), which the owner approved for download (D64,
// question 12). The source is not kept in the repository (it is 50,000 lines of third-party content);
// its address and SHA-256 are, in persian/SOURCE.txt, and the generator refuses any other file.
//
//	go test ./internal/auth/pwstrength -run TestPersianListIsTheGeneratedOne \
//	    -persian-source <path to fa_50k.txt> -persian-update
//
// writes persian/words.txt and persian/SOURCE.txt. With the source given and no -persian-update the
// test regenerates in memory and fails on any difference; without the source it checks the list on its
// own terms (its hash is the one SOURCE.txt records and the one faListSHA256 holds in code, every line
// is folded, unique and made of letters of the Arabic script), so a hand edit of the list that leaves
// the other copies of its hash alone is a failure on every run and not only where the source is at hand.
// An edit that changes the list, the note and the constant together is a reviewable diff, and only a run
// with the source proves the list is what the source makes. The source file is untrusted data: it is read
// as text and nothing in it is run.

var (
	persianSource = flag.String("persian-source", os.Getenv("CTRLZ_FA50K"), "path of fa_50k.txt (also CTRLZ_FA50K)")
	persianUpdate = flag.Bool("persian-update", false, "rewrite persian/words.txt and persian/SOURCE.txt from -persian-source")
)

const (
	faSourceURL    = "https://github.com/hermitdave/FrequencyWords/blob/525f9b560de45753a5ea01069454e72e9aa541c6/content/2018/fa/fa_50k.txt"
	faSourceSHA256 = "96ea178f77022cdb2d358feb75a4fc474754daa224a4beba296ad777a514bdf7"
	// faListSHA256 is the hash of persian/words.txt in code (primitives-r18-26). SOURCE.txt records the same
	// hash beside the list, in the same commit, so a hand edit that updated the list and the note together
	// passed. The third copy is a Go constant, which a reviewer reads in a diff and which -persian-update does
	// not write: regenerating the list from a new source changes this line by hand, with the source hash
	// above. What the three together prove is that the list is the one that was reviewed, and no more: that
	// it is what the source makes is shown only by TestPersianListIsTheGeneratedOne, which runs where the
	// source is at hand (CTRLZ_FA50K), and CI has no copy of it (it is CC-BY-SA content and is not kept in
	// the repository).
	faListSHA256 = "0f2fb0c7bd2be0aaed9f720a537170ac1f2aa18ea4ec3db9c88291d2b7af0ec7"
	// The size bounds of the list the owner decided (D64: about 20,000 to 50,000 entries).
	faMinWords = 20000
	faMaxWords = 50000
)

// generatePersianList reads the source and returns the list text: one folded word a line, in the
// frequency order of the source, the first of each folded form kept.
func generatePersianList(src []byte) (string, error) {
	sum := sha256.Sum256(src)
	if got := hex.EncodeToString(sum[:]); got != faSourceSHA256 {
		return "", fmt.Errorf("the source has sha256 %s, want %s: not the file the owner approved", got, faSourceSHA256)
	}
	seen := map[string]bool{}
	var out strings.Builder
	sc := bufio.NewScanner(strings.NewReader(string(src)))
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		word, _, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		w := persianFold(word)
		n := utf8.RuneCountInString(w)
		if n < persianMinWord || n > persianMaxWord || seen[w] {
			continue
		}
		letters := true
		for _, r := range w {
			if !isPersianLetter(r) {
				letters = false
				break
			}
		}
		if !letters {
			continue
		}
		seen[w] = true
		out.WriteString(w)
		out.WriteByte('\n')
	}
	return out.String(), sc.Err()
}

func listSum(list string) string {
	s := sha256.Sum256([]byte(list))
	return hex.EncodeToString(s[:])
}

func sourceNote(list string) string {
	return fmt.Sprintf(`source: %s
source-sha256: %s
source-licence: content CC-BY-SA-4.0 (README of the project: MIT for code, CC-BY-SA 4.0 for content), derived from OpenSubtitles2018 (opus.nlpl.eu)
approved: owner, Plan.md D64 (question 12), downloaded 2026-11-20
list: words.txt, %d words, one folded word per line in frequency order (the line number is the rank)
list-sha256: %s
generator: internal/auth/pwstrength/persian_gen_test.go (persianFold, filter: 2 to %d letters of the Arabic script, first of each folded form)
licence: words.txt is a derivative of the source and is under the same licence, CC-BY-SA 4.0; see NOTICE.md
`, faSourceURL, faSourceSHA256, strings.Count(list, "\n"), listSum(list), persianMaxWord)
}

func TestPersianListIsTheGeneratedOne(t *testing.T) {
	dir := "persian"
	if *persianSource != "" {
		src, err := os.ReadFile(*persianSource)
		if err != nil {
			t.Fatal(err)
		}
		list, err := generatePersianList(src)
		if err != nil {
			t.Fatal(err)
		}
		if *persianUpdate {
			if err := os.WriteFile(filepath.Join(dir, "words.txt"), []byte(list), 0o644); err != nil {
				t.Fatal(err)
			}
			note := sourceNote(list)
			if err := os.WriteFile(filepath.Join(dir, "SOURCE.txt"), []byte(note), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("wrote %d words; set faListSHA256 in this file to %s in the same reviewed diff", strings.Count(list, "\n"), listSum(list))
			return
		}
		if list != persianWordsText() {
			t.Errorf("persian/words.txt is not what the generator makes from %s: run with -persian-update and review the diff", *persianSource)
		}
	}
}

// TestPersianListOnItsOwnTerms holds on every run, with no source at hand.
func TestPersianListOnItsOwnTerms(t *testing.T) {
	note, err := os.ReadFile(filepath.Join("persian", "SOURCE.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for _, l := range strings.Split(string(note), "\n") {
		if v, ok := strings.CutPrefix(l, "list-sha256: "); ok {
			want = strings.TrimSpace(v)
		}
	}
	if listSum(persianWordsText()) != faListSHA256 {
		t.Errorf("persian/words.txt has sha256 %s and faListSHA256 in persian_gen_test.go is %s: the list was edited by hand; regenerate it from the source with -persian-update and change the constant in the same reviewed diff", listSum(persianWordsText()), faListSHA256)
	}
	if want == "" || listSum(persianWordsText()) != want {
		t.Errorf("persian/words.txt has sha256 %s and SOURCE.txt records %q: the list was edited by hand, or SOURCE.txt is stale; regenerate it from the source", listSum(persianWordsText()), want)
	}
	if !strings.Contains(string(note), faSourceSHA256) || !strings.Contains(string(note), "CC-BY-SA") {
		t.Error("persian/SOURCE.txt must name the source hash and the licence")
	}
	words := strings.Split(strings.TrimSuffix(persianWordsText(), "\n"), "\n")
	if len(words) < faMinWords || len(words) > faMaxWords {
		t.Errorf("%d words, want %d to %d (D64)", len(words), faMinWords, faMaxWords)
	}
	seen := map[string]bool{}
	for i, w := range words {
		if w != persianFold(w) {
			t.Fatalf("line %d %q is not in folded form", i+1, w)
		}
		if seen[w] {
			t.Fatalf("line %d %q is a duplicate", i+1, w)
		}
		seen[w] = true
		if n := utf8.RuneCountInString(w); n < persianMinWord || n > persianMaxWord {
			t.Fatalf("line %d %q has %d letters", i+1, w, n)
		}
		for _, r := range w {
			if !isPersianLetter(r) {
				t.Fatalf("line %d %q holds %q, which is not a letter of the Arabic script", i+1, w, r)
			}
		}
	}
	if _, err := os.Stat(filepath.Join("persian", "NOTICE.md")); err != nil {
		t.Errorf("the licence notice ships with the list: %v", err)
	}
}
