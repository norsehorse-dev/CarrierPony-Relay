module github.com/norsehorse-dev/CarrierPony-Relay

go 1.24.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/go-sql-driver/mysql v1.10.2
	github.com/ncruces/go-sqlite3 v0.32.0
	github.com/norsehorse-dev/CarrierPony-Relay/verifier v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

// The login verifier is its own module so the PHP relay's cp-verify can still
// be built from verifier/ alone. The relay uses the copy in this repository.
replace github.com/norsehorse-dev/CarrierPony-Relay/verifier => ./verifier
