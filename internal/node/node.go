package node

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

type shareStore interface {
	Reserve(context.Context, keystore.Key) (keystore.Reservation, error)
	Save(context.Context, keystore.Key, []byte) error
	Load(context.Context, string, string) ([]byte, error)
	ReserveECDSAPresign(context.Context, string, string, [32]byte) (keystore.Reservation, []string, error)
	SaveECDSAPresign(context.Context, string, []keystore.Presignature) ([]string, error)
	ReserveFROSTPresign(context.Context, string, string, [32]byte) (keystore.Reservation, []string, error)
	SaveFROSTPresign(context.Context, string, []keystore.Presignature) ([]string, error)
	ConsumeECDSAPresign(context.Context, string, string) (keystore.Presignature, error)
	ConsumeFROSTPresign(context.Context, string, string) (keystore.Presignature, error)
	CountPresign(context.Context, string) (int, error)
}

type node struct {
	config   config.Config
	logger   *slog.Logger
	client   *http.Client
	mu       sync.Mutex
	sessions map[string]*keygenSession
	keys     shareStore
}

func newNode(cfg config.Config) *node {
	return &node{
		config:   cfg,
		logger:   slog.Default(),
		client:   &http.Client{Timeout: 2 * time.Second},
		sessions: make(map[string]*keygenSession),
	}
}
