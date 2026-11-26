//go:build !ctrlz_lab

package netclass

// AllowPrivatePairAddrs is false in every build without the ctrlz_lab tag.
// A release-job test runs the built validator on a table with a Private
// dns_ip and expects a refusal, so a hub bug or a wrong node row cannot send
// hostname clients' handshakes, with the rid in SNI, to a device on their own
// LAN (contract 8a.7).
const AllowPrivatePairAddrs = false
