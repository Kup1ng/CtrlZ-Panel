package names

import "encoding/binary"

// ProfileKey returns the fixed SipHash key for profile blobs: the 16 ASCII bytes
// "ctrlz-profile-v1". A fixed key keeps a blob's bytes independent of the
// catalog, so identical profiles share one content hash.
func ProfileKey() [16]byte {
	return [16]byte{'c', 't', 'r', 'l', 'z', '-', 'p', 'r', 'o', 'f', 'i', 'l', 'e', '-', 'v', '1'}
}

// Hash64 is SipHash-2-4 with a 128-bit key.
//
// SipHash and not FNV or xxhash because names are attacker-chosen: with a
// keyed hash nobody can pre-compute colliding names against a table whose key
// they have not seen. It is in-tree so the same function can be ported to Rust
// (D1) and checked against the published vectors without a dependency.
func Hash64(key [16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	round := func() {
		v0 += v1
		v1 = v1<<13 | v1>>(64-13)
		v1 ^= v0
		v0 = v0<<32 | v0>>32
		v2 += v3
		v3 = v3<<16 | v3>>(64-16)
		v3 ^= v2
		v0 += v3
		v3 = v3<<21 | v3>>(64-21)
		v3 ^= v0
		v2 += v1
		v1 = v1<<17 | v1>>(64-17)
		v1 ^= v2
		v2 = v2<<32 | v2>>32
	}

	n := len(msg)
	i := 0
	for ; i+8 <= n; i += 8 {
		m := binary.LittleEndian.Uint64(msg[i:])
		v3 ^= m
		round()
		round()
		v0 ^= m
	}
	// The final block holds the length in its top byte, which is what makes
	// messages of different lengths with trailing zeros hash differently.
	b := uint64(n) << 56
	for j := 0; i+j < n; j++ {
		b |= uint64(msg[i+j]) << (8 * uint(j))
	}
	v3 ^= b
	round()
	round()
	v0 ^= b
	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}

// SuffixKey turns a Hash64 value into a CZGT table key for a suffix entry
// (lowest bit 1). ExactKey is the same hash for an exact entry (lowest bit 0).
// One hash per suffix therefore serves both probes of the full name.
func SuffixKey(h uint64) uint64 { return h | 1 }

// ExactKey: see SuffixKey.
func ExactKey(h uint64) uint64 { return h &^ 1 }
