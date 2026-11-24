package sms_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Review round 10 (sms-r10-4, sms-r10-7): the two shared judges that every driver calls.

func TestParseCreditIsAPlainNonNegativeNumber(t *testing.T) {
	for in, want := range map[string]bool{
		"0": true, "7": true, "1500": true, "12.5": true, "0.5": true, "۱۲۳": true, " 42 ": true,
		"": false, " ": false, "Error": false, "-5": false, "+5": false, "1e9": false, "1.2.3": false, ".5": false, "5.": false,
		".": false, "12abc": false, "1,5": false, "NaN": false, "5-": false, "1_0": false,
	} {
		if _, ok := sms.ParseCredit(in); ok != want {
			t.Errorf("ParseCredit(%q) = %v, want %v", in, ok, want)
		}
	}
	if f, ok := sms.ParseCredit("۱۲.۵"); !ok || f.String() != "12.5" {
		t.Errorf("Persian digits: %q %v", f.String(), ok)
	}
}

func TestParseTemplateNumber(t *testing.T) {
	for in, want := range map[string]bool{
		"1": true, "42": true, "007": true, "999999999999999999": true,
		"": false, "0": false, "000": false, "-1": false, "+1": false, " 1": false, "1 ": false, "1.0": false, "1e3": false,
		"1000000000000000000": false, "۱": false,
	} {
		if _, ok := sms.ParseTemplateNumber(in); ok != want {
			t.Errorf("ParseTemplateNumber(%q) = %v, want %v", in, ok, want)
		}
	}
}
