package node

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

type shareStore interface {
	Reserve(context.Context, keystore.Key) (keystore.Reservation, error)
	Save(context.Context, keystore.Key, []byte) error
}

type node struct {
	config   config.Config
	client   *http.Client
	mu       sync.Mutex
	sessions map[string]*keygenSession
	keys     shareStore
}

func newNode(cfg config.Config) *node {
	return &node{
		config:   cfg,
		client:   &http.Client{Timeout: 2 * time.Second},
		sessions: make(map[string]*keygenSession),
	}
}
