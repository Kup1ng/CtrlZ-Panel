//go:build unix

package hubtrust

import (
	"os"
	"syscall"
)

// groupOf is the group id of a file; false where it cannot be read.
func groupOf(path string) (int, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}

// keepGroup gives the new file the group of the one it replaces. It is best effort: a hub that is not a member of that group
// cannot hand it on, and the file then keeps the hub's own group, which is what a fresh install has anyway.
func keepGroup(old, fresh string) {
	if gid, ok := groupOf(old); ok {
		_ = os.Chown(fresh, -1, gid)
	}
}
