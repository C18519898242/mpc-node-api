package node

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type shareStore interface {
	Reserve(context.Context, string, keystore.Key) (keystore.Reservation, error)
	Save(context.Context, string, keystore.Key, []byte) error
	Load(context.Context, string, string, string) ([]byte, error)
	DeleteKeyShare(context.Context, string, string) error
	ReserveECDSAPresign(context.Context, string, string, string, [32]byte) (keystore.Reservation, []string, error)
	SaveECDSAPresign(context.Context, string, string, []keystore.Presignature) ([]string, error)
	ReserveFROSTPresign(context.Context, string, string, string, [32]byte) (keystore.Reservation, []string, error)
	SaveFROSTPresign(context.Context, string, string, []keystore.Presignature) ([]string, error)
	ConsumeECDSAPresign(context.Context, string, string, string) (keystore.Presignature, error)
	ConsumeFROSTPresign(context.Context, string, string, string) (keystore.Presignature, error)
	CountPresign(context.Context, string, string) (int, error)
	DeletePresign(context.Context, string, string) error
	ReserveReshare(context.Context, string, keystore.Reshare) (keystore.Reservation, keystore.ReshareState, error)
	LoadReshare(context.Context, string, keystore.Reshare) (keystore.ReshareState, error)
	PendingReshare(context.Context, string, string, string) (bool, error)
	StageReshare(context.Context, string, keystore.Reshare, [32]byte, []byte) error
	CommitReshare(context.Context, string, keystore.Reshare) error
}

type node struct {
	config        config.Config
	logger        *slog.Logger
	client        *http.Client
	peerClients   map[party.ID]*http.Client
	peerNames     map[string]party.ID
	applications  map[string]struct{}
	credentials   []apiKeyCredential
	mu            sync.Mutex
	sessions      map[sessionKey]*keygenSession
	keyOperations map[keyOperation]int
	keys          shareStore
	shareCipher   *keystore.ShareCipher
	wrappingKey   *rsa.PrivateKey
}

func newNode(cfg config.Config) *node {
	return &node{
		config:        cfg,
		logger:        slog.Default(),
		client:        &http.Client{Timeout: 2 * time.Second},
		sessions:      make(map[sessionKey]*keygenSession),
		keyOperations: make(map[keyOperation]int),
	}
}
