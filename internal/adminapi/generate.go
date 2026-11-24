// Package adminapi is the admin HTTP API: the same pipeline as the tenant API on
// its own host, with its own sessions. The server interface is generated from
// api/admin-openapi.yaml.
package adminapi

//go:generate go tool oapi-codegen -config oapi.yaml -o gen/api.gen.go ../../api/admin-openapi.yaml
