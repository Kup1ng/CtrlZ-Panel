package xrayschema

import (
	"strings"
	"testing"
	"time"
)

// A fragment built to cost the most the limits allow must still be judged in well under
// a second: an accepted subtree is scanned to the depth limit with many keys at each
// level, and one object may hold many unknown keys.
func TestWorstCaseFragmentIsJudgedQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"outbounds":[{"protocol":"vless","streamSettings":{"newThing":`)
	depth := 22
	for i := 0; i < depth; i++ {
		b.WriteString(`{"host":"h","path":"/p","mode":"auto","headers":{"a":"b"},"n":[1,2,3,null,false],"sub":`)
	}
	b.WriteString(`{}`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	b.WriteString(`}}]}`)
	if b.Len() > MaxFragmentBytes {
		t.Fatalf("fragment of %d bytes", b.Len())
	}
	start := time.Now()
	r := Newest().Check([]byte(b.String()), []string{"outbounds[0].streamSettings.newThing"})
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("took %v", d)
	}
	if len(r.Rejected) != 0 || len(r.Warnings) != 0 {
		t.Errorf("rejected: %v %v", r.Rejected, r.Warnings)
	}
	// Many unknown keys in one object.
	var m strings.Builder
	m.WriteString(`{"outbounds":[{"protocol":"vless"`)
	for i := 0; i < 250; i++ {
		m.WriteString(`,"k` + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":1`)
	}
	m.WriteString(`}]}`)
	start = time.Now()
	_ = Newest().Check([]byte(m.String()), nil)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("many keys took %v", d)
	}
}
