package deploy

import (
	"strings"
	"testing"
)

// TestAnOverrideMustBePinned holds admin-r16-19: the environment may replace a reference, but only by one that is
// pinned by digest, so no run can judge a tag that moved.
func TestAnOverrideMustBePinned(t *testing.T) {
	want := Image("POSTGRES_IMAGE")
	if !pinned.MatchString(want) {
		t.Fatalf("the Compose default %q is not pinned", want)
	}
	good := "example/img:1@sha256:" + strings.Repeat("a", 64)
	t.Setenv("POSTGRES_IMAGE", good)
	if got := Image("POSTGRES_IMAGE"); got != good {
		t.Errorf("a pinned override was not honoured: %q", got)
	}
	for _, bad := range []string{"example/img:1", "example/img", "example/img@sha256:" + strings.Repeat("a", 64), "example/img:1@sha256:abc", "docker.io/example/img:1"} {
		t.Setenv("POSTGRES_IMAGE", bad)
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("an override of %q was accepted", bad)
				}
			}()
			_ = Image("POSTGRES_IMAGE")
		}()
	}
}

// TestEveryImageNameResolvesToAPinnedLiteral holds admin-r17-6: each name reads the literal reference of its
// service, so a Compose file that wrapped one in `${VAR:-...}` again (which an .env would override) fails here
// before it fails anywhere else.
func TestEveryImageNameResolvesToAPinnedLiteral(t *testing.T) {
	for _, name := range imageNames() {
		if got := Image(name); !pinned.MatchString(got) || strings.Contains(got, "$") {
			t.Errorf("%s resolves to %q, not a pinned literal reference", name, got)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a name that is not in the table was accepted")
			}
		}()
		_ = Image("NOT_AN_IMAGE")
	}()
}
