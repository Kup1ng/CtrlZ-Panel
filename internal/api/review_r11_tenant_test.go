package api

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAFloodOfJunkInviteTokensCannotRefuseAnInviteeOnAnotherNetwork is tenant-r10-3 (a flood from one /24) and
// tenant-r11-4 (the same flood from the /64s of one IPv6 /48), as D67 answers them. The rounds bounded the reads
// a junk token could cost in a pool (internal/netpool); a junk token now is a forged link, which is refused in
// process before any read and writes no throttle row, so there is no work left to pool and no row to count.
// The flood comes first and keeps running while the invitees ask. One invitee is on a /24 that strangers filled
// (the situation of tenant-r9-1) and must pass every time; the other is on the very /24 the flood comes from, whose
// plain otp-send bucket the flood spent, and his link opening is what lets him through. The database work the flood
// caused is none: not a throttle row beyond the one each invitee's own invite has.
func TestAFloodOfJunkInviteTokensCannotRefuseAnInviteeOnAnotherNetwork(t *testing.T) {
	cases := []struct {
		name string
		// attacker is the source of loop i; fillFrom is the source of the i-th request that fills the otp-send bucket.
		attacker, fillFrom func(i int) string
		// inviteeOnFlood is the address of an invitee inside the flooded network.
		inviteeOnFlood func(i int) string
		fills          int
	}{
		{
			name:           "one /24",
			attacker:       func(i int) string { return fmt.Sprintf("198.51.100.%d", 100+i) },
			fillFrom:       func(i int) string { return fmt.Sprintf("198.51.100.%d", 10+i) },
			inviteeOnFlood: func(i int) string { return fmt.Sprintf("198.51.100.%d", 200+i) },
			fills:          12,
		},
		{
			name:           "the /64s of one IPv6 /48",
			attacker:       func(i int) string { return fmt.Sprintf("2001:db8:7:%x::1", i+1) },
			fillFrom:       func(i int) string { return fmt.Sprintf("2001:db8:7:%x::2", 0x100+i) },
			inviteeOnFlood: func(i int) string { return fmt.Sprintf("2001:db8:7:%x::9", 0x200+i) },
			fills:          40, // more than 4 x the 5 a minute of the class
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFrig(t, frigOpts{})
			f.clearThrottle()
			const phone = "+989125553021"
			const phoneOnFlood = "+989125553022"
			code := f.plantInvite(phone, time.Hour, false)
			codeOnFlood := f.plantInvite(phoneOnFlood, time.Hour, false)
			junkToken := f.forgedInvite()

			// Strangers fill the plain otp-send bucket of the invitee's /24 and of the attacker's source.
			fill := func(from func(i int) string, n int, label string) {
				limited := 0
				for i := 0; i < n; i++ {
					c := f.client()
					c.ip = from(i)
					if c.post("/auth/otp/request", map[string]any{"phone": fmt.Sprintf("0912555%04d", i), "purpose": "login"}).Code == http.StatusTooManyRequests {
						limited++
					}
				}
				if limited == 0 {
					t.Fatalf("%s: never refused, the plain bucket was not filled and the test proves nothing", label)
				}
			}
			fill(func(i int) string { return fmt.Sprintf("203.0.113.%d", 10+i) }, 12, "invitee's /24")
			fill(tc.fillFrom, tc.fills, "attacker's source")
			f.clearOTP()
			// The fills above are strangers' login requests, which write throttle rows of their own: what is counted
			// below is what the flood of junk invite tokens adds from here.
			f.clearThrottle()

			// The flood: many loops on the attacker's source, started before the invitees ask.
			const loops = 32
			clients := make([]*client, loops)
			for i := range clients {
				clients[i] = f.client()
				clients[i].ip = tc.attacker(i)
			}
			var sent atomic.Int64
			stop := make(chan struct{})
			var wg sync.WaitGroup
			for _, c := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						c.do("POST", "/auth/otp/request", map[string]any{"phone": phone, "purpose": "invite", "invite_token": junkToken})
						sent.Add(1)
					}
				}()
			}
			for sent.Load() < 200 {
				time.Sleep(5 * time.Millisecond)
			}

			// The invitee, on the filled /24 of another network, gets his code every time, up to his invite's own five.
			passed := 0
			for i := 0; i < 5; i++ {
				c := f.client()
				c.ip = fmt.Sprintf("203.0.113.%d", 100+i)
				if r := c.requestOTP(phone, "invite", map[string]any{"invite_token": code}); r.Code == http.StatusAccepted {
					passed++
				}
			}
			// And the invitee inside the flooded network itself: his link opens, so the flood's spent bucket is not his.
			c := f.client()
			c.ip = tc.inviteeOnFlood(0)
			onFlood := c.requestOTP(phoneOnFlood, "invite", map[string]any{"invite_token": codeOnFlood}).Code
			close(stop)
			wg.Wait()
			if passed != 5 {
				t.Errorf("the invitee was answered %d times of 5 while another source flooded junk invite tokens", passed)
			}
			if onFlood != http.StatusAccepted {
				t.Errorf("the invitee on the flooded network was answered %d, want 202: his link opens and stands outside the plain bucket", onFlood)
			}
			// The flood wrote nothing: the only rows are the one of each invite that asked.
			if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`); sent.Load() < 200 || n != 2 {
				t.Errorf("the flood sent %d requests and %d invite throttle rows exist, want the two of the invitees' own invites", sent.Load(), n)
			}
		})
	}
}
