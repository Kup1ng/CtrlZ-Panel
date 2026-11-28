package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bodyOf(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
}

// bodyField gives the same value as the map decoder it replaced for every body the document allows and for the odd ones around
// them, and gives up on a body of more than maxProofMembers members (p3-D4-r2-4).
func TestBodyFieldReadsTheNamedMemberOnly(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"plain":                 {`{"link":"abc"}`, "abc"},
		"first of two":          {`{"link":"abc","params":{"protocol":"doh","n":[1,{"a":"b"}]}}`, "abc"},
		"second of two":         {`{"params":{"protocol":"doh"},"link":"abc"}`, "abc"},
		"white space":           {" \n{ \"link\" : \"abc\" }\n", "abc"},
		"a later one wins":      {`{"link":"abc","link":"def"}`, "def"},
		"absent":                {`{"params":{}}`, ""},
		"not a string":          {`{"link":5}`, ""},
		"a later non-string":    {`{"link":"abc","link":5}`, ""},
		"null":                  {`{"link":null}`, ""},
		"not an object":         {`["link"]`, ""},
		"truncated":             {`{"link":"abc"`, ""},
		"trailing data":         {`{"link":"abc"} x`, ""},
		"another case":          {`{"LINK":"abc"}`, ""},
		"empty":                 {``, ""},
		"eight members":         {`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"link":"abc"}`, "abc"},
		"nine members":          {`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"link":"abc"}`, ""},
		"a member of the first": {`{"link":"abc","a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8}`, ""},
	} {
		if got := bodyField(bodyOf(c.body), "link"); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	// The body is still there for the schema check.
	r := bodyOf(`{"link":"abc"}`)
	_ = bodyField(r, "link")
	if left, err := io.ReadAll(r.Body); err != nil || string(left) != `{"link":"abc"}` {
		t.Errorf("the body after the peek: %q %v", left, err)
	}
}

// Junk of the largest size a public route takes costs next to nothing and no allocation per member: a body of 64 KiB of tiny
// members, which the map decoder turned into a map of ten thousand entries on every request that charged nobody (p3-D4-r2-4).
func TestBodyFieldOfJunkAllocatesNothingPerMember(t *testing.T) {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; b.Len() < 64<<10; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + strings.Repeat("k", 1+i%7) + `":0`)
	}
	b.WriteByte('}')
	junk := b.String()
	if got := bodyField(bodyOf(junk), "link"); got != "" {
		t.Fatalf("junk gave %q", got)
	}
	allocs := testing.AllocsPerRun(20, func() { _ = bodyField(bodyOf(junk), "link") })
	// The request, its reader and the few values of the first members: far below one allocation per member (more than ten thousand).
	if allocs > 200 {
		t.Errorf("%.0f allocations for a body of junk members", allocs)
	}
}
