package main

import "testing"

// TestAdminName: the binary is the admin command line when it was started under
// the name ctrlz-admin, the symlink the image carries (spec 17.1).
func TestAdminName(t *testing.T) {
	for argv0, want := range map[string]bool{
		"ctrlz-admin":                true,
		"/usr/local/bin/ctrlz-admin": true,
		"ctrlz-admin.exe":            true,
		"ctrlz":                      false,
		"/usr/local/bin/ctrlz":       false,
		"ctrlz-admin-not":            false,
		"":                           false,
	} {
		if got := adminName(argv0); got != want {
			t.Errorf("adminName(%q) = %v, want %v", argv0, got, want)
		}
	}
}
