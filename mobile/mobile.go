// Package mobile exposes the outbound-only MPC node to desktop simulators and
// future gomobile bindings. It does not open REST or MPC listening ports.
package mobile

import (
	"encoding/json"
	"errors"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/node"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Client struct{ embedded *node.Embedded }

// New accepts resolved configuration JSON, a private data directory and an
// in-memory master password. The caller is responsible for protecting secrets.
func New(configJSON, dataDir, masterPassword string) (*Client, error) {
	var cfg config.Config
	var options struct {
		ApplicationID string            `json:"applicationID"`
		ServerAPIKeys map[string]string `json:"serverAPIKeys"`
	}
	if json.Unmarshal([]byte(configJSON), &cfg) != nil || json.Unmarshal([]byte(configJSON), &options) != nil {
		return nil, errors.New("invalid mobile configuration")
	}
	cfg.DataDir = dataDir
	credentials := make(map[party.ID]string, len(options.ServerAPIKeys))
	for id, key := range options.ServerAPIKeys {
		credentials[party.ID(id)] = key
	}
	embedded, err := node.NewEmbedded(cfg, options.ApplicationID, masterPassword, credentials)
	if err != nil {
		return nil, err
	}
	return &Client{embedded: embedded}, nil
}

func (c *Client) CreateKey(algorithm string, threshold int, keyID string) (string, error) {
	return c.embedded.CreateKey(algorithm, threshold, keyID)
}
func (c *Client) Sign(algorithm, keyID string, message []byte) (string, error) {
	return c.embedded.Sign(algorithm, keyID, message)
}
func (c *Client) GeneratePresignatures(algorithm, keyID string, count int) (string, error) {
	return c.embedded.GeneratePresignatures(algorithm, keyID, count)
}
func (c *Client) SignWithPresignature(algorithm, keyID, presignatureID string, message []byte) (string, error) {
	return c.embedded.SignWithPresignature(algorithm, keyID, presignatureID, message)
}
func (c *Client) Close() error { return c.embedded.Close() }
