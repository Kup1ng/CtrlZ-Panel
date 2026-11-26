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

// keepGroup gives the new file the group of the one it replaces and says whether it could. A process may hand a file only to a
// group it belongs to, and the hub in its container (USER 65532, no group_add) belongs to none but its own, so a group an operator
// gave chrony is lost at the first renewal; the caller says so in the log, because the next thing that happens is chrony failing
// to read the key after its restart. The default ACL of the directory is what survives (deploy/chrony/panel.conf).
func keepGroup(chown func(string, int, int) error, old, fresh string) (kept bool) {
	gid, ok := groupOf(old)
	if !ok {
		return true // a first write: there is no group to keep
	}
	return chown(fresh, -1, gid) == nil
}
