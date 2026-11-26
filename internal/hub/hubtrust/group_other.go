//go:build !unix

package hubtrust

// keepGroup does nothing where files have no group; the panel host runs Linux.
func keepGroup(string, string) {}
