// Package resolvguard refuses a container whose DNS forwarder starts in the host's network namespace.
//
// Why it exists (p6-ops 9.5): the worker resolves names outside the stack, and Docker's embedded resolver (127.0.0.11) forwards
// them to the `dns` addresses of the service. For an address that is a loopback of the host (ctrld on 127.0.0.1, systemd-resolved on
// 127.0.0.53) Docker forwards from the host namespace instead of the container's, so the query passes no row of the firewall table
// and nothing counts it. Compose can only refuse an empty CTRLZ_WORKER_DNS1, so the worker checks the effective configuration at
// start: Docker writes what it will forward to as an `# ExtServers: [...]` comment in the container's /etc/resolv.conf, and an
// entry written `host(addr)` is one it forwards from the host namespace.
package resolvguard

import (
	"errors"
	"net/netip"
	"os"
	"strings"
)

// ErrHostForward is the one error of Check. It names the rule and never the address: an address of the host's resolver stays out of
// logs, like every other detail of the network a deployment sits in.
var ErrHostForward = errors.New("resolvguard: the container's DNS would be forwarded from the host namespace or to a loopback address (set CTRLZ_WORKER_DNS1 to a resolver the host reaches over the network, p6-ops 9.5)")

// errUnverifiable is returned when the embedded resolver is in use and Docker's comment is missing, so the forward cannot be judged.
var errUnverifiable = errors.New("resolvguard: the container uses Docker's embedded resolver and /etc/resolv.conf does not say where it forwards to")

// embedded is the address of Docker's embedded resolver in a user-defined network.
const embedded = "127.0.0.11"

// Check reads a resolv.conf and returns nil when it is outside Docker's embedded resolver (a plain file the Go resolver reads
// itself, from this namespace, so there is no bypass to close) or when every address the embedded resolver forwards to is a
// real address reached from the container's own namespace.
func Check(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		// No file means the Go resolver uses its defaults inside this namespace, which is not the bypass.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errUnverifiable
	}
	return CheckText(string(b))
}

// CheckText is Check on the content of the file.
func CheckText(conf string) error {
	usesEmbedded := false
	var ext []string
	haveExt := false
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" && f[1] == embedded {
			usesEmbedded = true
		}
		if rest, ok := strings.CutPrefix(line, "# ExtServers:"); ok {
			haveExt = true
			rest = strings.TrimSpace(rest)
			rest = strings.TrimPrefix(rest, "[")
			rest = strings.TrimSuffix(rest, "]")
			ext = append(ext, strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })...)
		}
	}
	if !usesEmbedded {
		return nil
	}
	if !haveExt || len(ext) == 0 {
		return errUnverifiable
	}
	for _, e := range ext {
		if strings.HasPrefix(e, "host(") {
			return ErrHostForward
		}
		a, err := netip.ParseAddr(strings.Trim(e, "[]"))
		if err != nil {
			// An entry that is not an address (a port form, a name) cannot be judged, so it is not trusted.
			if ap, perr := netip.ParseAddrPort(e); perr == nil {
				a = ap.Addr()
			} else {
				return errUnverifiable
			}
		}
		if a.IsLoopback() || a.IsUnspecified() {
			return ErrHostForward
		}
	}
	return nil
}
