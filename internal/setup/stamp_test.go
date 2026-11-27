package setup

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// decoded is a stamp read back by decodeStamp, which is written here from the
// DNS Stamps format and shares no code with the encoder.
type decoded struct {
	kind      byte
	props     uint64
	addr      string
	hashes    []string
	host      string
	path      string
	bootstrap []string
}

func decodeStamp(s string) (decoded, error) {
	var d decoded
	raw, ok := strings.CutPrefix(s, "sdns://")
	if !ok {
		return d, errors.New("no sdns:// prefix")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return d, err
	}
	if len(b) < 9 {
		return d, errors.New("short")
	}
	d.kind = b[0]
	d.props = binary.LittleEndian.Uint64(b[1:9])
	b = b[9:]
	lp := func() (string, error) {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return "", errors.New("truncated LP")
		}
		n := int(b[0])
		v := string(b[1 : 1+n])
		b = b[1+n:]
		return v, nil
	}
	vlp := func() ([]string, error) {
		var out []string
		for {
			if len(b) < 1 {
				return nil, errors.New("truncated VLP")
			}
			more := b[0]&0x80 != 0
			n := int(b[0] & 0x7f)
			if len(b) < 1+n {
				return nil, errors.New("truncated VLP element")
			}
			if n > 0 || more {
				out = append(out, string(b[1:1+n]))
			}
			b = b[1+n:]
			if !more {
				return out, nil
			}
		}
	}
	if d.addr, err = lp(); err != nil {
		return d, err
	}
	if d.hashes, err = vlp(); err != nil {
		return d, err
	}
	if d.host, err = lp(); err != nil {
		return d, err
	}
	if d.kind == stampDoH {
		if d.path, err = lp(); err != nil {
			return d, err
		}
	}
	if len(b) > 0 {
		if d.bootstrap, err = vlp(); err != nil {
			return d, err
		}
	}
	if len(b) != 0 {
		return d, errors.New("trailing bytes")
	}
	return d, nil
}

// The published stamp of a public resolver (Cloudflare, DoH): a known answer for
// the byte layout, with the properties that resolver claims.
func TestStampKnownAnswer(t *testing.T) {
	const want = "sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5"
	got, err := stamp{kind: stampDoH, props: 7, addr: "1.1.1.1", host: "cloudflare-dns.com", path: "/dns-query"}.encode()
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
	d, err := decodeStamp(want)
	if err != nil || d.addr != "1.1.1.1" || d.host != "cloudflare-dns.com" || d.path != "/dns-query" || d.props != 7 {
		t.Fatalf("decoded %+v, %v", d, err)
	}
}

// Every stamp of every golden view decodes back to its fields (P3 11.3): the
// hostname stamp has an empty addr, the address stamps one node's address each,
// primary first; the path is the DoH token only for DoH; properties and hashes
// are empty; the bootstrap list is primary then fallback.
func TestStampsDecodeBack(t *testing.T) {
	for _, c := range loadGolden(t) {
		v, err := View(c.input())
		if err != nil {
			t.Fatal(err)
		}
		type row struct {
			name string
			kind byte
			ps   ProtocolStamps
		}
		for _, r := range []row{{"doh", stampDoH, v.Stamps.DoH}, {"dot", stampDoT, v.Stamps.DoT}, {"doq", stampDoQ, v.Stamps.DoQ}} {
			wantPath := ""
			if r.kind == stampDoH {
				wantPath = "/" + c.Token
			}
			boot := []string{stampAddr(netip.MustParseAddr(c.Primary)), stampAddr(netip.MustParseAddr(c.Fallback))}
			check := func(label, text, wantAddr string) {
				d, err := decodeStamp(text)
				if err != nil {
					t.Errorf("%s %s %s: %v", c.Name, r.name, label, err)
					return
				}
				if d.kind != r.kind || d.props != 0 || len(d.hashes) != 0 {
					t.Errorf("%s %s %s: kind %x props %d hashes %v", c.Name, r.name, label, d.kind, d.props, d.hashes)
				}
				if d.addr != wantAddr || d.host != v.Host || d.path != wantPath {
					t.Errorf("%s %s %s: %+v", c.Name, r.name, label, d)
				}
				if strings.Join(d.bootstrap, ",") != strings.Join(boot, ",") {
					t.Errorf("%s %s %s: bootstrap %v", c.Name, r.name, label, d.bootstrap)
				}
			}
			check("hostname", r.ps.HostnameStamp, "")
			if len(r.ps.AddressStamps) != 2 {
				t.Fatalf("%s %s: %d address stamps", c.Name, r.name, len(r.ps.AddressStamps))
			}
			for i, a := range r.ps.AddressStamps {
				want := []string{c.Primary, c.Fallback}[i]
				if a.IP.String() != want {
					t.Errorf("%s %s: address stamp %d is %s", c.Name, r.name, i, a.IP)
				}
				check("address", a.Stamp, stampAddr(a.IP))
			}
		}
	}
}

// DoH3 has no stamp of its own (D51) and Plain DNS none: the view's Stamps holds
// the three protocols and nothing else.
func TestStampProtocolsAreThree(t *testing.T) {
	v := readyView(t)
	if v.Stamps.DoH.HostnameStamp == v.Stamps.DoT.HostnameStamp || v.Stamps.DoT.HostnameStamp == v.Stamps.DoQ.HostnameStamp {
		t.Fatal("two protocols share a stamp")
	}
}

func TestStampEncodingLimits(t *testing.T) {
	long := strings.Repeat("a", 256)
	cases := map[string]stamp{
		"host over 255":       {kind: stampDoT, host: long},
		"path over 255":       {kind: stampDoH, host: "a", path: long},
		"bootstrap over 127":  {kind: stampDoT, host: "a", bootstrap: []string{strings.Repeat("1", 128)}},
		"addr over 255":       {kind: stampDoT, addr: long, host: "a"},
		"bootstrap last long": {kind: stampDoT, host: "a", bootstrap: []string{"1.1.1.1", strings.Repeat("1", 128)}},
	}
	for name, s := range cases {
		if _, err := s.encode(); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A bootstrap element of exactly 127 bytes is the longest that fits.
	if _, err := (stamp{kind: stampDoT, host: "a", bootstrap: []string{strings.Repeat("1", 127)}}).encode(); err != nil {
		t.Errorf("127: %v", err)
	}
}

func TestStampAddrIPv6InBrackets(t *testing.T) {
	if got := stampAddr(netip.MustParseAddr("2001:db8::1")); got != "[2001:db8::1]" {
		t.Fatal(got)
	}
	if got := stampAddr(netip.MustParseAddr("203.0.113.1")); got != "203.0.113.1" {
		t.Fatal(got)
	}
}
