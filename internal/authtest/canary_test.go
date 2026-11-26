package authtest

import (
	"strings"
	"testing"
)

// The canary check must not depend on what a random number generator drew. "09121" is the prefix
// of a Tehran mobile number and five hex digits of a UUID are as likely to spell it as any other
// five, which failed a full CI run once. A secret in the text is still found.
func TestScrubNoiseHidesRandomIdsAndClocksButNotSecrets(t *testing.T) {
	line := `{"time":"2026-11-14T04:57:07.498467+03:30","level":"INFO","msg":"sms sent","id":"01a1d7aa-573c-774e-a2ba-091213706079"}`
	if got := ScrubNoise(line); strings.Contains(got, "09121") || strings.Contains(got, "2026") || strings.Contains(got, "a2ba") {
		t.Errorf("a UUID or a clock value is still in the text: %s", got)
	}
	if got := ScrubNoise(line); !strings.Contains(got, `"msg":"sms sent"`) {
		t.Errorf("the scrub took more than the noise: %s", got)
	}
	leak := line + ` {"msg":"to 09121234567","id":"01a1d7aa-573c-774e-a2ba-091213706079"}`
	if !strings.Contains(ScrubNoise(leak), "09121234567") {
		t.Error("a phone number written beside a UUID was scrubbed away")
	}
	// AssertTextClean passes the first line and would flag the second.
	AssertTextClean(t, "a log", line, "09121", "+9891")
}
