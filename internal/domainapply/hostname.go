package domainapply

import (
	"strings"
	"time"
)

// validHost is the hostname grammar of domain_settings' CHECK constraints (p4-nodes 3.2 item 6): lower-case labels of
// [a-z0-9-], 1 to 63 characters, never starting or ending with a hyphen, at most 253 characters in all. It is asked
// again here, whatever the database said, because these values end up in a file Compose reads, in a Caddyfile and in a
// file name: the one place the apply step may not trust a row is where the row becomes text for another program.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validZone is a DNS zone of the service: a hostname that starts with "dns." and has more after it (the CHECK's LIKE
// 'dns.%').
func validZone(z string) bool {
	return strings.HasPrefix(z, "dns.") && validHost(z)
}

// verifyOrigins is the value of CTRLZ_VERIFY_ORIGIN (10.3): the origin the panel's pages may open a connection to for the
// verify probe of each live zone, comma separated. The previous zone is listed only while its transition lasts, so a
// zone that is no longer in use leaves the Content-Security-Policy with the next recreate of web-panel.
//
// A zone is listed only when covered says an active uploaded wildcard covers it (T-237). Without one the nodes serve that zone
// on the zone CA, which no browser trusts, so every probe would fail and run out its two minutes while each lookup still
// reached a node. The origin is then absent, and the page shows the manual check instead (private-CA mode, T-089). With no
// zone covered the value is empty, which the panel reads as "no probe" (FE 15.3).
func verifyOrigins(zone, prev string, transitionUntil *time.Time, now time.Time, covered func(zone string) bool) string {
	var out []string
	if zone != "" && covered(zone) {
		out = append(out, "https://*.verify."+zone)
	}
	if prev != "" && transitionUntil != nil && now.Before(*transitionUntil) && covered(prev) {
		out = append(out, "https://*.verify."+prev)
	}
	return strings.Join(out, ",")
}
