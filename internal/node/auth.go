package node

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

const (
	defaultApplication  = keystore.DefaultApplication
	peerApplicationPath = "/applications/"
)

var applicationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type apiKeyCredential struct {
	digest        [sha256.Size]byte
	applicationID string
}

func (n *node) configureApplications(defaultStore *keystore.SQLite) error {
	n.keys = defaultStore
	if n.config.RESTAuth == nil {
		return nil
	}
	keys := n.config.RESTAuth.APIKeys
	if len(keys) == 0 {
		return errors.New("restAuth requires at least one API key")
	}
	credentials := make([]apiKeyCredential, 0, len(keys))
	seen := make(map[[sha256.Size]byte]bool)
	for index, key := range keys {
		raw, err := base64.StdEncoding.Strict().DecodeString(key.SHA256)
		if err != nil || len(raw) != sha256.Size || !applicationIDPattern.MatchString(key.ApplicationID) {
			return fmt.Errorf("invalid restAuth API key entry %d", index+1)
		}
		digest := [sha256.Size]byte(raw)
		if seen[digest] {
			return fmt.Errorf("duplicate restAuth API key entry %d", index+1)
		}
		seen[digest] = true
		credentials = append(credentials, apiKeyCredential{digest: digest, applicationID: key.ApplicationID})
	}

	applications := make(map[string]*node)
	for _, credential := range credentials {
		id := credential.applicationID
		if applications[id] != nil {
			continue
		}
		cfg := n.config
		cfg.RESTAuth = nil
		if id != defaultApplication {
			// Scope legacy /v1 share files on case-insensitive filesystems.
			cfg.DataDir = filepath.Join(cfg.DataDir, "applications", hex.EncodeToString([]byte(id)))
			if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
				return err
			}
		}
		app := newNode(cfg)
		app.applicationID, app.keys = id, defaultStore.ForApplication(id)
		app.logger, app.client = n.logger, n.client
		app.peerClients, app.peerNames = n.peerClients, n.peerNames
		applications[id] = app
	}
	n.credentials, n.applications = credentials, applications
	return nil
}

func (n *node) authenticatedRESTHandler() http.Handler {
	health := healthMux()
	handlers := make(map[string]http.Handler, len(n.applications))
	for id, app := range n.applications {
		handlers[id] = app.restHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			health.ServeHTTP(w, r)
			return
		}
		handler := handlers[n.authenticateAPIKey(r)]
		if handler == nil {
			w.Header().Set("WWW-Authenticate", "APIKEY")
			http.Error(w, "unauthorized API key", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (n *node) authenticateAPIKey(r *http.Request) string {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return ""
	}
	scheme, key, ok := strings.Cut(headers[0], " ")
	if !ok || !strings.EqualFold(scheme, "APIKEY") || key == "" || strings.ContainsAny(key, " \t,") {
		return ""
	}
	digest := sha256.Sum256([]byte(key))
	var applicationID string
	for _, credential := range n.credentials {
		if subtle.ConstantTimeCompare(digest[:], credential.digest[:]) == 1 {
			applicationID = credential.applicationID
		}
	}
	return applicationID
}

// Keep the original protocol binding for the existing database's application.
func (n *node) applicationBinding(seed []byte) []byte {
	if n.applicationID == "" || n.applicationID == defaultApplication {
		return seed
	}
	digest := sha256.Sum256(append([]byte("mpc-node/application/"+n.applicationID+"\x00"), seed...))
	return digest[:]
}
