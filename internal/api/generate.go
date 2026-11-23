// Package api is the tenant HTTP API: the router and its pipeline (spec 2.3),
// and the handlers. The server interface is generated from api/openapi.yaml.
package api

//go:generate go tool oapi-codegen -config oapi.yaml -o gen/api.gen.go ../../api/openapi.yaml
