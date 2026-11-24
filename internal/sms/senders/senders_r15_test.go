package senders_test

import (
	"net/url"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smshttp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
)

// Review round 15 (sms-r15-3). Every driver's production base is https and one smshttp accepts. A
// maintainer who pastes a provider's sample base URL (often http://) into DefaultBase fails here, and
// one who builds an http URL per request fails in smshttp.Do (TestDoRefusesAnythingButHTTPSToItsOwnHost),
// which the driver tests now reach over TLS.
func TestEveryDriverBaseIsHTTPS(t *testing.T) {
	for name, base := range map[string]string{"sms_ir": smsir.DefaultBase, "melipayamak": melipayamak.DefaultBase} {
		u, err := url.Parse(base)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
			t.Errorf("%s: base %q is not a plain https URL", name, base)
		}
		hp, err := smshttp.HostPort(base)
		if err != nil || hp == "" {
			t.Errorf("%s: smshttp refuses the base %q: %v", name, base, err)
		}
	}
}
