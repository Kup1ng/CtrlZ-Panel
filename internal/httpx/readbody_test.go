package httpx

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// splitRules stops at max+1 items, so a file of 149,000 empty rules costs the memory of 10,001 (p2-B3-r5-1).
func TestSplitRulesStopsAtOneAboveTheLimit(t *testing.T) {
	raw := []byte("[" + strings.TrimSuffix(strings.Repeat("{},", 149000), ",") + "]")
	items, ok := splitRules(raw, 10000)
	if !ok || len(items) != 10001 {
		t.Fatalf("got %d items, ok %v; want 10001", len(items), ok)
	}
	items, ok = splitRules([]byte(`[{"a":1},{}]`), 10000)
	if !ok || len(items) != 2 || string(items[0]) != `{"a":1}` {
		t.Fatalf("got %q, ok %v", items, ok)
	}
	for _, bad := range []string{`{}`, `"x"`, ``, `[{]`} {
		if _, ok := splitRules([]byte(bad), 10); ok {
			t.Errorf("%q is not an array of values", bad)
		}
	}
}

// The body is read once: a body that ReadBody read is returned as it is by the next call, and the reader can be read again.
func TestReadBodyReadsOnceAndCanBeReadAgain(t *testing.T) {
	body := []byte(`{"a":"` + strings.Repeat("x", 1000) + `"}`)
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	first, e := ReadBody(r)
	if e != nil || !bytes.Equal(first, body) {
		t.Fatalf("first read: %v", e)
	}
	again, e := ReadBody(r)
	if e != nil || &again[0] != &first[0] {
		t.Fatal("the second call copied the body")
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("the body could not be read again: %v", err)
	}
}

// The result has exactly the length of the body, however the body was declared or chunked.
func TestReadBodyReturnsABufferOfTheBodysLength(t *testing.T) {
	for _, n := range []int{0, 1, readChunk - 1, readChunk, readChunk + 1, 3*readChunk + 7, 1 << 20} {
		body := bytes.Repeat([]byte("a"), n)
		r := httptest.NewRequest("POST", "/", io.MultiReader(bytes.NewReader(body[:n/2]), bytes.NewReader(body[n/2:])))
		r.ContentLength = 10
		raw, e := ReadBody(r)
		if n == 0 {
			if e != nil || len(raw) != 0 {
				t.Fatalf("an empty body: %d bytes, refusal %v", len(raw), e)
			}
			continue
		}
		if e != nil || !bytes.Equal(raw, body) || cap(raw) != len(body) {
			t.Fatalf("%d bytes: len %d cap %d, refusal %v", n, len(raw), cap(raw), e)
		}
	}
}

func TestReadBodyRefusals(t *testing.T) {
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte{0xff, 0xfe}))
	if _, e := ReadBody(r); e == nil || e.Status != http.StatusBadRequest {
		t.Errorf("bad UTF-8: %v", e)
	}
	r = httptest.NewRequest("POST", "/", io.NopCloser(&failReader{&http.MaxBytesError{Limit: 1}}))
	if _, e := ReadBody(r); e == nil || e.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over its limit: %v", e)
	}
	r = httptest.NewRequest("POST", "/", io.NopCloser(&failReader{errors.New("reset")}))
	if _, e := ReadBody(r); e == nil || e.Status != http.StatusBadRequest {
		t.Errorf("a read error: %v", e)
	}
	if raw, e := ReadBody(httptest.NewRequest("GET", "/", nil)); raw != nil || e != nil {
		t.Errorf("no body: %v, %v", raw, e)
	}
}

type failReader struct{ err error }

func (f *failReader) Read([]byte) (int, error) { return 0, f.err }
