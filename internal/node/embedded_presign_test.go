package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

func TestMobilePresignGenerationCancelsWithWorker(t *testing.T) {
	n := newNode(config.Config{PartyID: "1"})
	store, err := keystore.OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	worker, cancel := context.WithCancel(t.Context())
	defer cancel()
	n.workerContext = worker
	ctx := context.WithValue(t.Context(), applicationContextKey{}, "mobile-test")
	started, release := make(chan struct{}), make(chan struct{})
	generate := func(ctx context.Context, _ string, _ [32]byte, _ <-chan *protocol.Message) (keystore.Presignature, error) {
		close(started)
		select {
		case <-ctx.Done():
			return keystore.Presignature{}, ctx.Err()
		case <-release:
			return keystore.Presignature{}, context.Canceled
		}
	}
	session, err := n.beginPresign(ctx, "frost-presign.cancel", "key", [32]byte{}, 1, "frost", generate, store.ReserveFROSTPresign, store.SaveFROSTPresign)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); <-session.done }()
	<-started
	cancel()
	select {
	case <-session.done:
	case <-time.After(3 * time.Second):
		t.Fatal("mobile presign worker ignored cancellation")
	}
}

func TestMobilePresignCombinationRejectsInvalidPartials(t *testing.T) {
	message := []byte("mobile partial signature validation")
	id := strings.Repeat("A", 43)
	for _, algorithm := range []string{"ecdsa", "frost"} {
		t.Run(algorithm, func(t *testing.T) {
			var public, r, s []byte
			if algorithm == "frost" {
				key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				public = key.Public().(ed25519.PublicKey)
				signature := ed25519.Sign(key, message)
				r, s = signature[:32], bytes.Clone(signature[32:])
				slices.Reverse(s)
			} else {
				group := curve.Secp256k1{}
				one := group.NewScalar()
				data := make([]byte, 32)
				data[31] = 1
				if err := one.UnmarshalBinary(data); err != nil {
					t.Fatal(err)
				}
				// Deterministic fixture with private scalar and nonce both equal to one.
				point := one.ActOnBase()
				var err error
				r, err = uncompressedECDSAPoint(point)
				if err != nil {
					t.Fatal(err)
				}
				public = r
				digest := sha256.Sum256(message)
				s, err = point.XScalar().Add(curve.FromHash(group, digest[:])).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			}
			curveName, _ := mobileCurve(algorithm)
			parts := make([]mobilePresignPartial, 2)
			for i := range parts {
				parts[i] = mobilePresignPartial{
					ecdsaPresignPartial: ecdsaPresignPartial{PresignatureID: id, Curve: curveName, PlayerIndex: i, Threshold: 1, Sharing: "additive", PublicKey: public, R: r, SShare: make([]byte, 32)},
					SchnorrVariant:      "Ed25519", Challenge: make([]byte, 32),
				}
			}
			parts[0].SShare = s
			indices := []int{0, 1}
			signature, err := combineMobilePresign(algorithm, id, public, message, parts, indices)
			if err != nil {
				t.Fatal(err)
			}
			verifyMobileSignature(t, algorithm, public, message, signature)
			for name, mutate := range map[string]func(*mobilePresignPartial){
				"id":               func(p *mobilePresignPartial) { p.PresignatureID = "other" },
				"curve":            func(p *mobilePresignPartial) { p.Curve = "other" },
				"public":           func(p *mobilePresignPartial) { p.PublicKey = []byte("other") },
				"nonce":            func(p *mobilePresignPartial) { p.R = []byte("other") },
				"duplicate player": func(p *mobilePresignPartial) { p.PlayerIndex = 0 },
				"threshold":        func(p *mobilePresignPartial) { p.Threshold++ },
				"sharing":          func(p *mobilePresignPartial) { p.Sharing = "shamir" },
				"scalar encoding":  func(p *mobilePresignPartial) { p.SShare = bytes.Repeat([]byte{255}, 32) },
				"signature":        func(p *mobilePresignPartial) { p.SShare = bytes.Repeat([]byte{1}, 32) },
			} {
				t.Run(name, func(t *testing.T) {
					changed := slices.Clone(parts)
					mutate(&changed[1])
					if sig, err := combineMobilePresign(algorithm, id, public, message, changed, indices); err == nil || sig != nil {
						t.Fatal("accepted an invalid partial signature")
					}
				})
			}
			if _, err := combineMobilePresign(algorithm, id, public, []byte("other message"), parts, indices); err == nil {
				t.Fatal("signature accepted for another message")
			}
			if _, err := combineMobilePresign(algorithm, id, public, message, parts[:1], indices[:1]); err == nil {
				t.Fatal("accepted missing participant")
			}
		})
	}
}
