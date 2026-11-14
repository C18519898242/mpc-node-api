package main

import (
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	frostparty "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	cmpparty "github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func TestMPCDependencies(t *testing.T) {
	if start := cmp.Keygen(curve.Secp256k1{}, "1", []cmpparty.ID{"1", "2", "3"}, 2, nil); start == nil {
		t.Fatal("CMP did not return a keygen start function")
	}
	if _, _, err := frost.NewKeygenState(1, frostparty.IDSlice{1, 2, 3}, 2, 0); err != nil {
		t.Fatalf("initialize FROST keygen: %v", err)
	}
}
