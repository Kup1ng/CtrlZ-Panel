package iso3166

import "testing"

func TestList(t *testing.T) {
	if Count() != 249 {
		t.Fatalf("ISO 3166-1 has 249 assigned codes, the list has %d", Count())
	}
	for _, ok := range []string{"IR", "DE", "US", "ZW", "AD"} {
		if !Valid(ok) {
			t.Fatalf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"", "I", "IRN", "ir", "XX", "AA", "D E", "ZZ", "UK"} {
		if Valid(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}
