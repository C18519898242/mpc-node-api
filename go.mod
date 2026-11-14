module github.com/C18519898242/mpc-node-api

go 1.24.0

require (
	github.com/taurusgroup/frost-ed25519 v0.0.0-20261113144211-2c927d52326c
	github.com/taurusgroup/multi-party-sig v0.0.0-20261110150323-163e25a3a0a8
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/cronokirby/saferith v0.33.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	golang.org/x/sys v0.9.0 // indirect
)

replace github.com/taurusgroup/frost-ed25519 => github.com/C18519898242/frost-ed25519 v0.0.0-20261113144211-2c927d52326c

replace github.com/taurusgroup/multi-party-sig => github.com/C18519898242/multi-party-sig v0.0.0-20261110150323-163e25a3a0a8
