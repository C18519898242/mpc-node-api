package node

import (
	"net/http"
	"sync"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

type node struct {
	config   config.Config
	client   *http.Client
	mu       sync.Mutex
	sessions map[string]*keygenSession
}

func newNode(cfg config.Config) *node {
	return &node{
		config:   cfg,
		client:   &http.Client{Timeout: 2 * time.Second},
		sessions: make(map[string]*keygenSession),
	}
}
