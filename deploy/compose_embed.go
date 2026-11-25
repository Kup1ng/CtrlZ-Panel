package deploy

import "embed"

// composeFS holds the Compose file as it was at build time, read-only.
//
//go:embed compose/docker-compose.yml
var composeFS embed.FS

func composeFile() []byte {
	b, err := composeFS.ReadFile("compose/docker-compose.yml")
	if err != nil {
		panic("deploy: " + err.Error())
	}
	return b
}
