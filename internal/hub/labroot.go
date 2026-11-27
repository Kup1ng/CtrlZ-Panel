package hub

// LabRootKeyIDs are the key ids (hex) of the lab test root that the node repository's lab builds sign
// bundles with (internal/labroot/denylist.go there). A production hub refuses a root.json that holds
// one: a bundle signed by a key that is in a public repository is a bundle anyone could have signed.
func LabRootKeyIDs() []string {
	return []string{
		"cf82bcd033514fc6c7b980d3ab6128a7",
		"04c2182bdebeca0f396bdbdb6ee007fc",
		"d8ce6f14114d1bb4a7a5412076ced473",
		"e60873949b8b28485209f37b9c93713d",
		"2eb7d8a7d0326cd2511aa67a0dcb2e22",
	}
}
