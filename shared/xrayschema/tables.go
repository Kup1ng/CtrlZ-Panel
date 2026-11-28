package xrayschema

import "errors"

// ErrUnknownRelease is returned by For for a tag that has no table in this build.
var ErrUnknownRelease = errors.New("xrayschema: no allow-list for this Xray release")

// releases lists every release a table exists for, oldest first. A table is never
// removed: a node may stay on any release that was ever shipped as a bundle (7.2).
func releases() []Table {
	return []Table{
		{tag: "v26.11.9", build: outbound, rules: statefulRules},
	}
}

// For returns the table of the release with this tag, or ErrUnknownRelease.
func For(tag string) (Table, error) {
	for _, t := range releases() {
		if t.tag == tag {
			return t, nil
		}
	}
	return Table{}, ErrUnknownRelease
}

// Newest returns the table of the newest release, which a config is checked with
// while its node reports no release yet.
func Newest() Table {
	rs := releases()
	return rs[len(rs)-1]
}

// Releases lists the tags that have a table, oldest first.
func Releases() []string {
	rs := releases()
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.tag
	}
	return out
}
