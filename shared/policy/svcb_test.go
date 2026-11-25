package policy

import (
	"bytes"
	"net/netip"
	"testing"
)

func hexb(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}

func TestSvcHints(t *testing.T) {
	addr := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	cases := []struct {
		name string
		rd   string
		want []netip.Addr
	}{
		{"ipv4hint", "00010000040004c0a80101", addr("192.168.1.1")},
		{"two ipv4 hints", "000100" + "0004" + "0008" + "c0a801015db8d822", addr("192.168.1.1", "93.184.216.34")},
		{"ipv6hint", "000100" + "0006" + "0010" + "fd000000000000000000000000000001", addr("fd00::1")},
		{"both, after alpn", "000100" + "0001" + "0003" + "026832" + "0004" + "0004" + "0a000001" + "0006" + "0010" + "20010db8000000000000000000000001", addr("10.0.0.1", "2001:db8::1")},
		{"non-root target", "0001" + "03737663076578616d706c65036e657400" + "0004" + "0004" + "5db8d822", addr("93.184.216.34")},
		{"alias mode has no params", "0000" + "03737663076578616d706c65036e657400", nil},
		{"hint of 3 bytes is skipped", "000100" + "0004" + "0003" + "c0a801", nil},
		{"hint of 5 bytes is skipped whole", "000100" + "0004" + "0005" + "c0a8010102", nil},
		{"ipv6hint of 15 bytes", "000100" + "0006" + "000f" + "fd0000000000000000000000000001", nil},
		{"param past the end", "000100" + "0004" + "0008" + "c0a80101", nil},
		{"hint read before a truncated tail still counts", "000100" + "0004" + "0004" + "c0a80101" + "0006" + "0010" + "fd00", addr("192.168.1.1")},
		{"truncated header of a param", "000100" + "0004" + "00", nil},
		{"target name runs past the end", "0001" + "05616263", nil},
		{"compression pointer ends the target, the hint after it counts", "0001" + "c00c" + "0004" + "0004" + "c0a80101", addr("192.168.1.1")},
		{"label then pointer", "0001" + "03737663" + "c00c" + "0004" + "0004" + "c0a80101", addr("192.168.1.1")},
		{"pointer with nothing after it", "0001" + "c00c", nil},
		{"truncated pointer", "0001" + "c0", nil},
		{"reserved label type 0x40 stops the scan", "0001" + "40" + "0004" + "0004" + "c0a80101", nil},
		{"reserved label type 0x80 stops the scan", "0001" + "80" + "0004" + "0004" + "c0a80101", nil},
		{"too short", "0001", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		got := svcHints(hexb(c.rd))
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v want %v", c.name, got, c.want)
			}
		}
	}
}

// Rebind sees a private hint on an HTTPS or SVCB record, and only there.
func TestHasPrivateAddrReadsHints(t *testing.T) {
	priv := hexb("00010000040004c0a80101")
	pub := hexb("00010000040004" + "5db8d822")
	for _, typ := range []uint16{TypeHTTPS, TypeSVCB} {
		if !hasPrivateAddr([]RR{{Type: typ, Data: priv}}) {
			t.Errorf("type %d: a private hint was not seen", typ)
		}
		if hasPrivateAddr([]RR{{Type: typ, Data: pub}}) {
			t.Errorf("type %d: a public hint counted as private", typ)
		}
	}
	// The same bytes on another type are not a hint.
	if hasPrivateAddr([]RR{{Type: TypeTXT, Data: priv}}) {
		t.Error("RDATA of a TXT record was read as SvcParams")
	}
}

// FuzzSvcHints: any RDATA parses without a panic, and every address returned
// is made of bytes that are in the record.
func FuzzSvcHints(f *testing.F) {
	f.Add(hexb("00010000040004c0a80101"))
	f.Add(hexb("000100" + "0006" + "0010" + "fd000000000000000000000000000001"))
	f.Add(hexb("000100" + "0004" + "0008" + "c0a80101"))
	f.Add(hexb("0001c00c"))
	f.Add(hexb("0001c00c00040004c0a80101"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, rd []byte) {
		hints := svcHints(rd)
		if len(hints)*4 > len(rd) {
			t.Fatalf("%d hints from %d bytes", len(hints), len(rd))
		}
		for _, a := range hints {
			b := a.AsSlice()
			if !bytes.Contains(rd, b) {
				t.Fatalf("hint %v is not in the record", a)
			}
		}
	})
}
