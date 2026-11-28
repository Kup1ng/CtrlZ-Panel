package sharelink

import (
	"strings"
	"testing"
)

// B1-r4-9, now 7.3: the post-quantum encryption text of VLESS (mlkem768x25519plus) is not
// on the list, because its padding gaps are sleeps inside the handshake that nothing
// cancels. A link that carries any encryption but none is an error of its line, named
// and without the text.
func TestVLESSEncryptionOtherThanNoneIsAnErrorOfItsLine(t *testing.T) {
	key := strings.Repeat("A", 43)
	link := func(enc string) string {
		return "vless://" + uuid + "@203.0.113.7:443?encryption=" + enc + "&type=tcp"
	}
	norm(t, link("none"))
	for _, enc := range []string{
		"mlkem768x25519plus.native.1rtt.100-35-35.1-3-10000." + key,
		"mlkem768x25519plus.native.1rtt.100-35-35.1-3600000-86400000." + key,
		"aes-128-gcm",
	} {
		_, _, _, err := Convert(link(enc))
		if err == nil {
			t.Fatalf("%.30s is accepted", enc)
		}
		if !strings.Contains(err.Error(), `"encryption"`) || strings.Contains(err.Error(), "86400000") || strings.Contains(err.Error(), key) {
			t.Errorf("the error does not name the parameter alone: %v", err)
		}
	}
}
