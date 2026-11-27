//go:build ctrlz_lab

package netclass

// AllowPrivatePairAddrs is true only in a binary built with the ctrlz_lab tag.
// The P4 fault tests run lab builds on a private network, where the nodes of a
// pair have private addresses; a release build refuses them (contract 8a.7).
// It is a constant in a leaf package so that wire and zone read one value and
// the two validators cannot disagree about the lab rule.
const AllowPrivatePairAddrs = true
