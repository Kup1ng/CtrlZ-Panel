package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// unreadable is a body that must not be read: a declared length over the limit is refused before a byte is asked for
// (p2-B3-r6-1, r6-3).
type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("a body that declared more than its limit was read")
	return 0, io.EOF
}

func TestADeclaredLengthOverTheLimitIsRefusedBeforeAnyRead(t *testing.T) {
	h, reached := validateRig(t, validateDoc)
	for _, n := range []int64{httpx.DefaultBodyLimit + 1, 64 << 20, 1 << 40} {
		r := httptest.NewRequest("POST", "/api/v1/open", unreadable{t})
		r.ContentLength = n
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || code(t, w) != httpx.CodeTooLarge {
			t.Errorf("declared %d: %d %s, want 413 too_large", n, w.Code, w.Body.String())
		}
	}
	if *reached != 0 {
		t.Fatal("a handler ran")
	}
}
