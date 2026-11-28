package rules

import "sort"

// UploadMode is how Upload Folder treats keys that already exist.
type UploadMode uint8

const (
	// UploadNewOnly adds keys that do not exist and leaves the rest alone.
	UploadNewOnly UploadMode = 1
	// UploadUpsert also rewrites a key in the same folder whose payload differs.
	UploadUpsert UploadMode = 2
)

// Item is one rule as the merge sees it. Payload is an opaque canonical
// encoding of everything except the key and folder (action, target, flags,
// expiry); two items are "the same" when their payloads are equal.
type Item struct {
	Key     string
	Folder  string
	Payload string
}

// UploadResult counts what MergeUpload did. Merged is the full resulting list,
// sorted by Key.
type UploadResult struct {
	Created   int
	Updated   int
	Skipped   int
	Conflicts int
	Merged    []Item
}

// MergeUpload applies an Upload Folder file to a profile's existing rules.
//
// It never deletes: a user who uploads a partial list must not lose the rest.
// A key is unique per profile (rule_key), so a key that already lives in a
// different folder is a conflict in both modes and is left where it is;
// moving a rule between folders is a deliberate edit, not an upload side
// effect. Incoming items are applied in order against the evolving state, so
// a repeated key inside one file behaves like two uploads in a row.
func MergeUpload(existing, incoming []Item, mode UploadMode) UploadResult {
	state := make(map[string]Item, len(existing)+len(incoming))
	for _, it := range existing {
		state[it.Key] = it
	}
	var res UploadResult
	for _, in := range incoming {
		cur, ok := state[in.Key]
		switch {
		case !ok:
			state[in.Key] = in
			res.Created++
		case cur.Folder != in.Folder:
			res.Conflicts++
		case mode == UploadUpsert && cur.Payload != in.Payload:
			state[in.Key] = in
			res.Updated++
		default:
			res.Skipped++
		}
	}
	res.Merged = make([]Item, 0, len(state))
	for _, it := range state {
		res.Merged = append(res.Merged, it)
	}
	sort.Slice(res.Merged, func(i, j int) bool { return res.Merged[i].Key < res.Merged[j].Key })
	return res
}
