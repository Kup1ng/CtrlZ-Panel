package vectors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
)

// appleOp runs the ops of the appleprofile group (contract 14 and 15). Inputs
// are JSON text so a vector reads like the API request it stands for.
//
//	apple_expand    input: request JSON, args[0]: JSON array of common domains
//	                (optional). Output: the canonical params JSON. An error
//	                reads "<pointer>: <code>: <reason>".
//	apple_hash      same inputs. Output: the SHA-256 of the canonical params,
//	                the params_hash of the download link.
//	apple_params    input: stored params JSON, as a download reads it. Output:
//	                the canonical JSON it round-trips to.
//	apple_identity  args: endpoint id, client. Output: the six identifiers.
func appleOp(op string, input string, a []string) (string, bool, error) {
	switch op {
	case "apple_expand", "apple_hash":
		var req appleprofile.Request
		if err := decodeStrict([]byte(input), &req); err != nil {
			return "", true, err
		}
		var common []string
		if len(a) > 0 && a[0] != "" {
			if err := json.Unmarshal([]byte(a[0]), &common); err != nil {
				return "", true, err
			}
		}
		p, err := appleprofile.Expand(req, common)
		if err != nil {
			return "", true, err
		}
		if op == "apple_hash" {
			h, err := p.Hash()
			if err != nil {
				return "", true, err
			}
			return hex.EncodeToString(h[:]), true, nil
		}
		b, err := p.Canonical()
		return string(b), true, err
	case "apple_params":
		p, err := appleprofile.ParseParams([]byte(input))
		if err != nil {
			return "", true, err
		}
		b, err := p.Canonical()
		return string(b), true, err
	case "apple_identity":
		if len(a) != 2 {
			return "", true, fmt.Errorf("apple_identity wants an endpoint id and a client")
		}
		id, err := appleprofile.Identify(a[0], a[1])
		if err != nil {
			return "", true, err
		}
		return fmt.Sprintf("id=%s uuid=%s content=%s content_uuid=%s root=%s root_uuid=%s",
			id.PayloadIdentifier, id.PayloadUUID, id.ContentIdentifier, id.ContentUUID, id.RootIdentifier, id.RootUUID), true, nil
	}
	return "", false, nil
}
