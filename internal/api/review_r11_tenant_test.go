package api

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestAFloodOfJunkInviteTokensCannotRefuseAnInviteeOnAnotherNetwork is tenant-r10-3 (a flood from one /24) and
// tenant-r11-4 (the same flood from the /64s of one IPv6 /48). The reads of an invite for a request the otp-send bucket
// refused are bounded per network, per /48 and for the process (internal/netpool, registered as the pool
// "invite-read"). The flood comes first and keeps running while the invitee asks, from a /24 that strangers filled (the
// situation of tenant-r9-1); the invitee must pass every time, and the database work the flood caused is bounded by
// its source's share and not by how long it kept sending: a /24's burst of reads, or for a /48 the 40 tries of
// invite_net48 and the one row it is kept in, and no row per /64 after that.
func TestAFloodOfJunkInviteTokensCannotRefuseAnInviteeOnAnotherNetwork(t *testing.T) {
	pool, ok := budget.FindNetPool(budget.Tenant, "invite-read")
	if !ok {
		t.Fatal("the invite-read pool is not registered")
	}
	n48, _ := budget.FindScope("invite_net48")
	cases := []struct {
		name string
		// attacker is the source of loop i; fillFrom is the source of the i-th request that fills the otp-send bucket.
		attacker, fillFrom func(i int) string
		fills              int
		// tooMany reports whether the database work of the flood stayed inside its source's share.
		within func(f *frig) (string, bool)
	}{
		{
			name:     "one /24",
			attacker: func(i int) string { return fmt.Sprintf("198.51.100.%d", 100+i) },
			fillFrom: func(i int) string { return fmt.Sprintf("198.51.100.%d", 10+i) },
			fills:    12,
			within: func(f *frig) (string, bool) {
				charged := f.count(`SELECT coalesce(sum(count), 0) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`)
				return fmt.Sprintf("%d reads were charged, want at most the network's burst of %d", charged, pool.Burst), charged <= pool.Burst+1
			},
		},
		{
			name:     "the /64s of one IPv6 /48",
			attacker: func(i int) string { return fmt.Sprintf("2001:db8:7:%x::1", i+1) },
			fillFrom: func(i int) string { return fmt.Sprintf("2001:db8:7:%x::2", 0x100+i) },
			fills:    pool.Burst, // more than 4 x the 5 a minute of the class
			within: func(f *frig) (string, bool) {
				rows := f.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`)
				return fmt.Sprintf("%d throttle rows were written, want at most the %d tries of invite_net48 and its own row", rows, n48.Max), rows <= n48.Max+1
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFrig(t, frigOpts{})
			f.clearThrottle()
			const phone = "+989125553021"
			code := f.plantInvite(phone, time.Hour, false)
			const junkToken = "AAAAA-AAAAA-AAAAA-AAAAA"

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

			// The flood: many loops on the attacker's source, started before the invitee asks.
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
			close(stop)
			wg.Wait()
			if passed != 5 {
				t.Errorf("the invitee was answered %d times of 5 while another source flooded the invite reads", passed)
			}
			if msg, ok := tc.within(f); sent.Load() < 200 || !ok {
				t.Errorf("the flood sent %d requests and %s", sent.Load(), msg)
			}
		})
	}
}
