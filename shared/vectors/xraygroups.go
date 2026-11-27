package vectors

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/sharelink"
	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// The xray and sharelink groups (contract 14 and 15) are text groups with these ops:
//
//	xray_check       input: a fragment, args: the accept_unknown paths. Expect is the
//	                 normal form, or an error naming each rejection and warning.
//	sharelink_check  input: one share link. The link is converted and the fragment is
//	                 checked against the newest table; Expect is the normal form.
//	sharelink_json   input: a pasted configuration. Expect lists the candidates (their
//	                 note, protocol and number of outbounds) and the left-out keys.
//
// They pin the same code the panel runs, so a node that checks a fragment again with
// the release it has installed reaches the same text.

func xrayOps(c *TextCase) (string, bool, error) {
	switch c.Op {
	case "loc_publish":
		last, err1 := strconv.ParseUint(c.Args[0], 10, 32)
		now, err2 := strconv.ParseUint(c.Args[1], 10, 32)
		if err1 != nil || err2 != nil {
			return "", true, fmt.Errorf("loc_publish: numbers")
		}
		return strconv.FormatBool(locations.ShouldPublish(uint32(last), uint32(now))), true, nil
	case "xray_check":
		out, err := xrayCheck(xrayschema.Newest(), []byte(c.Input), c.Args)
		return out, true, err
	case "sharelink_check":
		frag, _, _, err := sharelink.Convert(c.Input)
		if err != nil {
			return "", true, fmt.Errorf("convert: %w", err)
		}
		out, err := xrayCheck(xrayschema.Newest(), frag, nil)
		return out, true, err
	case "sharelink_json":
		res, err := sharelink.FromJSON([]byte(c.Input))
		if err != nil {
			return "", true, fmt.Errorf("import: %w", err)
		}
		var parts []string
		for _, cand := range res.Candidates {
			n := strings.Count(string(cand.Fragment), `"protocol"`)
			parts = append(parts, fmt.Sprintf("%s/%s/%d", cand.Note, cand.Protocol, n))
		}
		return "candidates=" + strings.Join(parts, ",") + " left_out=" + strings.Join(res.LeftOut, ","), true, nil
	}
	return "", false, nil
}

func xrayCheck(t xrayschema.Table, frag []byte, accept []string) (string, error) {
	r := t.Check(frag, accept)
	if len(r.Rejected) != 0 || len(r.Warnings) != 0 {
		var parts []string
		for _, i := range r.Rejected {
			parts = append(parts, "rejected "+i.Path+": "+i.Msg)
		}
		for _, i := range r.Warnings {
			parts = append(parts, "warning "+i.Path+": "+i.Msg)
		}
		return "", fmt.Errorf("%s", strings.Join(parts, "; "))
	}
	return string(r.Normalized), nil
}
