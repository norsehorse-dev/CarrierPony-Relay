// Package relay carries the MySQL schema and migrations inside the relay
// binary, so "carrierpony-relay migrate" needs nothing but the binary.
package relay

import "embed"

// SQL holds schema.sql and migrations/*.sql as they are in the repository.
//
//go:embed schema.sql migrations/*.sql
var SQL embed.FS
