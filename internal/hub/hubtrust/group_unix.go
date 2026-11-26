//go:build unix

package hubtrust

import (
	"os"
	"syscall"
)

// keepGroup gives the new file the group of the one it replaces. It is best effort: a hub that is not a member of that group
// cannot hand it on, and the file then keeps the hub's own group, which is what a fresh install has anyway.
func keepGroup(old, fresh string) {
	fi, err := os.Stat(old)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(fresh, -1, int(st.Gid))
	}
}
