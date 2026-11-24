package lint_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// admin-r16-12, rule 29 (the full half, for client memory). Keys are not the only thing that fills a Valkey:
// the memory of a client counts toward maxmemory, and under `noeviction` a command that a client has sent
// only in part is held for as long as the connection lives. The ACL refuses a command only after it has been
// read whole, the idle timeout does not close a client that sends a byte now and then, and the sweep walks
// keys, which are not where the memory is. Valkey's own limits for a client that is not signed in (a bulk of
// at most 16 KB) were the only bound, and a password-less `health` user lifted them for anybody who
// reached the port. The user is gone (TestValkeyACLUsersKeepToTheirOwnKeys), and valkey.conf bounds what a
// signed-in client may hold: proto-max-bulk-len, client-query-buffer-limit and maxmemory-clients.
//
// This test runs the attack against a real server of each zone with a small maxmemory: many signed-in
// connections that each hold most of a megabyte of a command that never ends, and a bulk header that asks for
// far more than the limit. The zone's limiter has to keep writing, and the server has to have closed the
// holders.

// respAuth is the AUTH command of a connection.
func respAuth(user, pw string) string {
	return fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(user), user, len(pw), pw)
}

// openClient dials, signs in as the zone's user and checks the server said OK.
func openClient(t *testing.T, addr, user, pw string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(respAuth(user, pw))); err != nil {
		t.Fatalf("auth write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("auth as %q answered %q (%v)", user, line, err)
	}
	return c
}

// closedByServer reports whether the server has closed the connection: a read that ends in EOF or a reset
// and not in a timeout. Anything the server wrote before it closed (an error text) is returned too.
func closedByServer(c net.Conn, within time.Duration) (bool, string) {
	_ = c.SetReadDeadline(time.Now().Add(within))
	var got strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return false, got.String()
			}
			return true, got.String()
		}
	}
}

func TestValkeyClientsCannotHoldTheServerFull(t *testing.T) {
	// 16 MB is far under the 128 MB of a profile and keeps the attack small: thirty holders of 0.8 MB
	// are 24 MB, more than the server may use, and a tenth of it (maxmemory-clients) is 1.6 MB.
	f := startValkeyFill(t, "16mb")
	for _, zone := range valkeyZones {
		t.Run(zone, func(t *testing.T) {
			z := f.zones[zone]
			pw := valkeyPasswords[zone]

			// A signed-in client that asks for a bulk far over the limit is refused at the header and closed;
			// the 100 MB never has to be held.
			c := openClient(t, z.addr, zone, pw)
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			bigKey := "ctrlz:rl:" + zone
			if _, err := c.Write([]byte(fmt.Sprintf("*3\r\n$4\r\nHSET\r\n$%d\r\n%s\r\n$100000000\r\n", len(bigKey), bigKey))); err != nil {
				t.Fatalf("write: %v", err)
			}
			if closed, said := closedByServer(c, 5*time.Second); !closed || !strings.Contains(said, "Protocol error") {
				t.Errorf("a bulk of 100 MB was not refused: closed %v, the server said %q", closed, said)
			}

			// A client that is not signed in is held to Valkey's own small limit: a bulk of 900 KB is refused.
			u, err := net.DialTimeout("tcp", z.addr, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			_ = u.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = u.Write([]byte("*3\r\n$4\r\nHSET\r\n$3\r\nabc\r\n$900000\r\n"))
			if closed, said := closedByServer(u, 3*time.Second); !closed {
				t.Errorf("an unauthenticated bulk of 900 KB was not refused (the server said %q)", said)
			}

			// Thirty signed-in clients that each hold 800 KB of a command that never ends.
			const holders = 30
			body := strings.Repeat("x", 800_000)
			var conns []net.Conn
			for i := 0; i < holders; i++ {
				h := openClient(t, z.addr, zone, pw)
				_ = h.SetWriteDeadline(time.Now().Add(10 * time.Second))
				key := fmt.Sprintf("ctrlz:rl:%s:h%02d", zone, i)
				if _, err := h.Write([]byte(fmt.Sprintf("*3\r\n$4\r\nHSET\r\n$%d\r\n%s\r\n$900000\r\n", len(key), key) + body)); err != nil {
					// The server may already have closed an earlier holder's neighbour; a refused write is a
					// holder that was evicted, which is the outcome under test.
					continue
				}
				conns = append(conns, h)
			}
			// The zone's own limiter keeps writing while the holders are connected, and within seconds of the
			// last one: with no client bound the server is over maxmemory and answers OOM to every write.
			f.waitLimiter(t, zone, "during-holders", 20*time.Second)
			open := 0
			for _, h := range conns {
				if closed, _ := closedByServer(h, 200*time.Millisecond); !closed {
					open++
				}
			}
			// maxmemory-clients is a tenth of 16 MB: at most a couple of 800 KB holders can still be open.
			if open > 4 {
				t.Errorf("%d of %d holders of 800 KB are still connected: the server did not close the largest clients", open, len(conns))
			}
			f.waitLimiter(t, zone, "after-holders", 10*time.Second)
			t.Logf("%s: %d of %d holders still open", zone, open, len(conns))
		})
	}
}
