package vectors

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // the panel compiles transitions from real zones; the vectors must not depend on the host's zoneinfo

	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// zoneTransitions implements the build_transitions op: input is an IANA zone,
// args are the window start and end (RFC 3339). The output is the base offset
// and every change inside the window, so the real rules of a zone are pinned
// and the synthetic transitions of the schedule group are not the only DST
// coverage (review F10).
func zoneTransitions(c *TextCase) (string, error) {
	loc, err := time.LoadLocation(c.Input)
	if err != nil {
		return "", err
	}
	from, err := parseTime(c.Args[0])
	if err != nil {
		return "", err
	}
	to, err := parseTime(c.Args[1])
	if err != nil {
		return "", err
	}
	base, trs := schedule.BuildTransitions(loc, from, to)
	var b strings.Builder
	fmt.Fprintf(&b, "base=%d", base)
	for _, t := range trs {
		fmt.Fprintf(&b, ";%s=%d", time.Unix(t.At, 0).UTC().Format(time.RFC3339), t.Offset)
	}
	return b.String(), nil
}
