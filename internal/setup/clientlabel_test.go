package setup

import (
	"errors"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
)

func TestClientLabel(t *testing.T) {
	cases := []struct {
		name         string
		label, alias string
		want         string
		err          error
	}{
		{"label as given", "kid-phone", "", "kid-phone", nil},
		{"label wins over alias", "a", "Something Else", "a", nil},
		{"digits", "0", "", "0", nil},
		{"longest", strings.Repeat("a", 36), "", strings.Repeat("a", 36), nil},
		{"slug of an alias", "", "Kid's Phone 2", "kid-s-phone-2", nil},
		{"slug trims and joins runs", "", "  --Living   Room!! ", "living-room", nil},
		{"slug cuts to 36", "", strings.Repeat("a", 40), strings.Repeat("a", 36), nil},
		{"slug cut that ends in a hyphen", "", strings.Repeat("a", 35) + " b", strings.Repeat("a", 35), nil},
		{"mixed Persian and Latin", "", "گوشی Ali", "ali", nil},
		{"fullwidth is folded by NFKC", "", "ＡＢＣ", "abc", nil},

		{"nothing at all", "", "", "", ErrLabelRequired},
		{"Persian only alias", "", "گوشی علی", "", ErrLabelRequired},
		{"punctuation only alias", "", "!!! ---", "", ErrLabelRequired},
		{"upper label is not normalized", "Kid", "", "", ErrLabelInvalid},
		{"label with a space", "my phone", "", "", ErrLabelInvalid},
		{"label with an edge hyphen", "kid-", "", "", ErrLabelInvalid},
		{"label too long", strings.Repeat("a", 37), "", "", ErrLabelInvalid},
		{"label with a dot", "a.b", "", "", ErrLabelInvalid},
		{"invalid label is not rescued by the alias", "Kid", "kid", "", ErrLabelInvalid},
		{"default", "default", "", "", ErrLabelReserved},
		{"default through the alias", "", "Default", "", ErrLabelReserved},
		{"default through the alias with noise", "", " DEFAULT! ", "", ErrLabelReserved},
		{"a name that only starts with default", "default2", "", "default2", nil},
	}
	for _, c := range cases {
		got, err := ClientLabel(c.label, c.alias)
		if !errors.Is(err, c.err) || got != c.want {
			t.Errorf("%s: got %q, %v; want %q, %v", c.name, got, err, c.want, c.err)
		}
		// Whatever is accepted is a label the hostname grammar reads.
		if err == nil && !identity.ValidClient(got) {
			t.Errorf("%s: %q is accepted but is not a client label", c.name, got)
		}
	}
}

// Every accepted label makes a host the node reads back as the same client.
func TestClientLabelMakesAHost(t *testing.T) {
	label, err := ClientLabel("", "My Laptop")
	if err != nil {
		t.Fatal(err)
	}
	v, err := View(Input{
		ResolverID: tRID, DoHToken: tToken, Client: label, Zone: "dns.example.com",
		Primary: readyView(t).Legacy.DNS1, Fallback: readyView(t).Legacy.DNS2,
	})
	if err != nil || v.Host != tRID+"-my-laptop.dns.example.com" {
		t.Fatalf("%q, %v", v.Host, err)
	}
}
