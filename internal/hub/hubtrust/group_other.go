//go:build !unix

package hubtrust

// groupOf and keepGroup do nothing where files have no group; the panel host runs Linux.
func groupOf(string) (int, bool) { return 0, false }

func keepGroup(func(string, int, int) error, string, string) bool { return true }
