package adminnotice

import (
	"strings"
	"testing"
	"time"
)

func TestAppendAndParse(t *testing.T) {
	at := time.Date(2026, 11, 7, 10, 0, 0, 5, time.UTC)
	raw, err := Append(nil, Notice{Kind: PasswordReset, At: at})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = Append(raw, Notice{Kind: TOTPReset, At: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got := Parse(raw)
	if len(got) != 2 || got[0].Kind != PasswordReset || got[1].Kind != TOTPReset || !got[0].At.Equal(at.Truncate(time.Millisecond)) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseTolerates(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", "garbage", `[{"kind":"other","at":"2026-01-01T00:00:00Z"}]`} {
		if got := Parse([]byte(raw)); len(got) != 0 {
			t.Errorf("Parse(%q) = %+v", raw, got)
		}
	}
}

func TestBounded(t *testing.T) {
	var raw []byte
	for i := 0; i < 25; i++ {
		var err error
		if raw, err = Append(raw, Notice{Kind: PasswordReset, At: time.Unix(int64(i), 0)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := Parse(raw); len(got) != maxNotices || got[len(got)-1].At.Unix() != 24 {
		t.Fatalf("kept %d, newest %v", len(got), got[len(got)-1].At)
	}
	if strings.Contains(string(raw), "password") && !strings.Contains(string(raw), "password_reset") {
		t.Fatal("unexpected")
	}
}

// The kind added by review round 2 (admin-r2-8) survives Parse, and an unknown
// kind still does not.
func TestParseKeepsGatewayNotice(t *testing.T) {
	raw := []byte(`[{"kind":"sms_gateway_changed","at":"2026-01-02T03:04:05Z"},{"kind":"bogus","at":"2026-01-02T03:04:05Z"}]`)
	got := Parse(raw)
	if len(got) != 1 || got[0].Kind != SMSGatewayChanged {
		t.Fatalf("Parse = %+v", got)
	}
}
