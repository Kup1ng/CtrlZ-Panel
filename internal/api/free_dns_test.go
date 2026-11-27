package api

import (
	"testing"
	"time"
)

// TestPublicFreeDNS covers GET /public/free-dns (p4-nodes 9.3, Plan T-556): the switch and the advertised addresses of the
// global pair's active nodes, the header, the 5 second cache and the class of its own.
func TestPublicFreeDNS(t *testing.T) {
	f := newFrig(t, frigOpts{})
	type body struct {
		Enabled  bool    `json:"enabled"`
		Primary  *string `json:"primary_dns_ip"`
		Fallback *string `json:"fallback_dns_ip"`
	}
	get := func() (body, *resp) {
		var v body
		r := f.client().get("/public/free-dns").want(200, "")
		r.json(&v)
		return v, r
	}
	const pair = "00000000-0000-7000-8000-0000000000d1"
	const node1, node2 = "00000000-0000-7000-8000-0000000000c1", "00000000-0000-7000-8000-0000000000c2"

	// With no global pair there is a switch and no address.
	f.env.Exec(t, `UPDATE ctrlz.public_settings SET global_pair_id = NULL`)
	v, r := get()
	if !v.Enabled || v.Primary != nil || v.Fallback != nil {
		t.Fatalf("no global pair: %+v", v)
	}
	if got := r.H.Get("Cache-Control"); got != "public, max-age=30" {
		t.Fatalf("Cache-Control %q", got)
	}

	// The api keeps the function's answer 5 seconds, so what changes in the database shows after that and not before.
	f.env.Exec(t, `UPDATE ctrlz.public_settings SET global_pair_id = $1`, pair)
	if v, _ = get(); v.Primary != nil {
		t.Fatalf("inside the 5 second cache the answer is the old one: %+v", v)
	}
	f.ck.add(6 * time.Second)
	v, _ = get()
	if v.Primary == nil || v.Fallback == nil || *v.Primary == *v.Fallback {
		t.Fatalf("with a global pair: %+v", v)
	}
	// A node that is not active gives no address; the other keeps its own, in its own place.
	f.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = $1`, node2)
	f.ck.add(6 * time.Second)
	if v, _ = get(); v.Primary == nil || v.Fallback != nil {
		t.Fatalf("a revoked fallback: %+v", v)
	}
	_ = node1
	// The switch off is the one off state: no address is hidden by it, the page reads `enabled` first.
	f.env.Exec(t, `UPDATE ctrlz.free_dns_settings SET enabled = false`)
	f.ck.add(6 * time.Second)
	if v, _ = get(); v.Enabled {
		t.Fatalf("switched off: %+v", v)
	}
}

// TestPublicFreeDNSHasItsOwnClass: the page without a login is read by every visitor behind a shared carrier address, so its
// class (600 a minute a source network) lets a /24 read it far more often than public-read's 60, and still ends.
func TestPublicFreeDNSHasItsOwnClass(t *testing.T) {
	f := newFrig(t, frigOpts{})
	c := f.client()
	refused := 0
	for i := 0; i < 700; i++ {
		r := c.get("/public/free-dns")
		switch r.Code {
		case 200:
			if i >= 590 && refused == 0 {
				continue
			}
		case 429:
			if i < 590 {
				t.Fatalf("refused after only %d requests of a 600 a minute class", i)
			}
			refused++
		default:
			t.Fatalf("request %d answered %d %q", i, r.Code, r.Body)
		}
	}
	if refused == 0 {
		t.Fatal("700 requests in an instant were never refused")
	}
}
