package store_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestAProfileValueHoldsNoLockHash: the profile a store method returns has no field for the lock hash, so no format verb, no
// log line and no JSON encoding of it can print the hash, whatever verb is used (spec 7, 10.5 lock secrets). The hash is read
// by one method, into a secret.String, and nowhere else.
func TestAProfileValueHoldsNoLockHash(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(store.Profile{}), reflect.TypeOf(store.ProfileCounts{})} {
		for i := 0; i < typ.NumField(); i++ {
			n := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(n, "hash") || strings.Contains(n, "password") || strings.Contains(n, "secret") {
				t.Errorf("%s has the field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	msg := "back soon"
	p := store.Profile{Name: "x", Locked: true, LockMessage: &msg}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, p); strings.Contains(strings.ToLower(out), "hash") {
			t.Errorf("%s of a profile prints %q", verb, out)
		}
	}
}
