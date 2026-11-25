package sysnames

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

func look(t *testing.T, name string, qtype uint16, iso bool) (Entry, bool) {
	t.Helper()
	n := names.MustString(name)
	return Lookup(&n, qtype, iso)
}

func TestTrueAnswerRows(t *testing.T) {
	for _, n := range []string{
		"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com",
		"captive.apple.com", "www.appleiphonecell.com", "www.itools.info", "www.ibook.info", "www.airport.us", "www.thinkdifferent.us",
		"www.msftconnecttest.com", "ipv6.msftconnecttest.com", "dns.msftncsi.com", "www.msftncsi.com",
		"x.metric.gstatic.com", "a.b.metric.gstatic.com",
	} {
		e, ok := look(t, n, 1, false)
		if !ok || e.Outcome != OutcomeTrue || e.Kind != KindTrueAnswer {
			t.Errorf("%s: %+v %v", n, e, ok)
		}
	}
	for _, n := range []string{"metric.gstatic.com", "example.com", "evilconnectivitycheck.gstatic.com", "sub.captive.apple.com"} {
		if _, ok := look(t, n, 1, false); ok {
			t.Errorf("%s matched", n)
		}
	}
}

func TestAndroidPrivateDNSCheck(t *testing.T) {
	name := "abc123-dnsotls-ds.metric.gstatic.com"
	e, ok := look(t, name, 1, false)
	if !ok || e.Outcome != OutcomeTrue || !e.FallbackSynth || e.Kind != KindIsolatedSynth || e.TTL != 60 {
		t.Fatalf("normal: %+v", e)
	}
	e, _ = look(t, name, 1, true)
	if e.Outcome != OutcomeSynthDNSIP || e.TTL != 60 {
		t.Fatalf("isolated: %+v", e)
	}
	// Longest match: the glob row beats *.metric.gstatic.com, but a plain
	// subdomain still gets the plain row.
	if e, _ := look(t, "abc.metric.gstatic.com", 1, true); e.Outcome != OutcomeTrue || e.Kind != KindTrueAnswer {
		t.Fatalf("plain sub: %+v", e)
	}
	// One label only: a deeper name does not match the glob.
	if e, _ := look(t, "x.abc-dnsotls-ds.metric.gstatic.com", 1, true); e.Kind != KindTrueAnswer {
		t.Fatalf("deeper: %+v", e)
	}
}

func TestLocalRows(t *testing.T) {
	e, ok := look(t, "ipv4only.arpa", 1, false)
	if !ok || e.Outcome != OutcomeLocal || len(e.Records) != 2 || e.Records[0].RData[3] != 170 || e.Records[1].RData[3] != 171 {
		t.Fatalf("%+v", e)
	}
	if e, _ := look(t, "ipv4only.arpa", 28, false); len(e.Records) != 0 || e.Outcome != OutcomeLocal {
		t.Fatalf("AAAA must be NODATA: %+v", e)
	}
	e, _ = look(t, "localhost", 28, false)
	if len(e.Records) != 1 || e.Records[0].RData[15] != 1 {
		t.Fatalf("%+v", e)
	}
	e, _ = look(t, "foo.localhost", 1, false)
	if len(e.Records) != 1 || e.Records[0].RData[0] != 127 {
		t.Fatalf("%+v", e)
	}
	e, _ = look(t, "1.0.0.127.in-addr.arpa", 12, false)
	if len(e.Records) != 1 || string(e.Records[0].RData) != "\x09localhost\x00" {
		t.Fatalf("%+v", e)
	}
	v6 := "1"
	for i := 0; i < 31; i++ {
		v6 += ".0"
	}
	if e, ok := look(t, v6+".ip6.arpa", 12, false); !ok || len(e.Records) != 1 {
		t.Fatalf("%+v", e)
	}
	if e, ok := look(t, "resolver.arpa", 65, false); !ok || e.Outcome != OutcomeLocal || len(e.Records) != 0 {
		t.Fatalf("%+v", e)
	}
	if e, ok := look(t, "_dns.resolver.arpa", 64, false); !ok || e.Kind != KindNoData {
		t.Fatalf("%+v", e)
	}
}

func TestLocalNX(t *testing.T) {
	for _, n := range []string{
		"10.in-addr.arpa", "5.4.3.10.in-addr.arpa", "16.172.in-addr.arpa", "31.172.in-addr.arpa", "9.9.31.172.in-addr.arpa",
		"168.192.in-addr.arpa", "1.1.168.192.in-addr.arpa", "254.169.in-addr.arpa", "d.f.ip6.arpa", "1.d.f.ip6.arpa",
		"8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa", "x.b.e.f.ip6.arpa",
	} {
		if e, ok := look(t, n, 12, false); !ok || e.Outcome != OutcomeNXDomain {
			t.Errorf("%s: %+v %v", n, e, ok)
		}
	}
	for _, n := range []string{"15.172.in-addr.arpa", "32.172.in-addr.arpa", "11.in-addr.arpa", "c.e.f.ip6.arpa", "e.f.ip6.arpa", "8.8.8.8.in-addr.arpa"} {
		if _, ok := look(t, n, 12, false); ok {
			t.Errorf("%s matched", n)
		}
	}
}

func TestMatcherPanelHostnames(t *testing.T) {
	m := NewMatcher([]names.Name{names.MustString("panel.example.ir"), names.MustString("admin.example.ir")})
	n := names.MustString("panel.example.ir")
	e, ok := m.Lookup(&n, 1, false)
	if !ok || e.Outcome != OutcomeTrue {
		t.Fatalf("%+v", e)
	}
	n = names.MustString("sub.panel.example.ir")
	if _, ok := m.Lookup(&n, 1, false); ok {
		t.Fatal("panel hostnames are exact only")
	}
	var nilM *Matcher
	n = names.MustString("captive.apple.com")
	if _, ok := nilM.Lookup(&n, 1, false); !ok {
		t.Fatal("nil matcher must fall back to the static table")
	}
}
