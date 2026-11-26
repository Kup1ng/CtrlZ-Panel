//go:build unix

package hubtrust_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
)

func gidOf(t *testing.T, path string) int {
	t.Helper()
	gid, ok := hubtrust.GroupOf(path)
	if !ok {
		t.Fatal("the group of the file cannot be read")
	}
	return gid
}

// GP-r1-8: the key is replaced by a rename, a new inode, so the group an operator gave chrony must be carried over or chrony
// cannot read the renewed key and the nodes lose their time source.
func TestNTSKeyKeepsItsGroupWhenRewritten(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	n := newNTS(t, now, &alerts{})
	if _, err := n.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(n.Dir, hubtrust.NTSKeyFile)
	// A group the process may hand on: any supplementary group other than the current one, or any id when running as root.
	want := -1
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != gidOf(t, key) {
			want = g
			break
		}
	}
	if want < 0 && os.Geteuid() == 0 {
		want = 4242
	}
	if want < 0 {
		t.Skip("no second group to give the key")
	}
	if err := os.Chown(key, -1, want); err != nil {
		t.Skipf("cannot change the group: %v", err)
	}
	// A new node CA orphans the leaf: it is renewed.
	n.CA = newCA(t, now)
	if wrote, err := n.Ensure(t.Context()); err != nil || !wrote {
		t.Fatalf("renewal: wrote %v, err %v", wrote, err)
	}
	if got := gidOf(t, key); got != want {
		t.Errorf("the renewed key has group %d, want %d", got, want)
	}
}
