package node

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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

func (n *node) configureRESTAuth() error {
	if n.config.RESTAuth == nil {
		return nil
	}
	keys := n.config.RESTAuth.APIKeys
	if len(keys) == 0 {
		return errors.New("restAuth requires at least one API key")
	}
	credentials := make([]apiKeyCredential, 0, len(keys))
	applications := make(map[string]struct{})
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
		applications[key.ApplicationID] = struct{}{}
	}
	n.credentials, n.applications = credentials, applications
	return nil
}

type applicationContextKey struct{}

func applicationID(ctx context.Context) string {
	if id, ok := ctx.Value(applicationContextKey{}).(string); ok {
		return id
	}
	return defaultApplication
}

func withApplication(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), applicationContextKey{}, id))
}

func (n *node) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		id := n.authenticateAPIKey(r)
		if id == "" {
			w.Header().Set("WWW-Authenticate", "APIKEY")
			http.Error(w, "unauthorized API key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, withApplication(r, id))
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
func applicationBinding(id string, seed []byte) []byte {
	if id == defaultApplication {
		return seed
	}
	digest := sha256.Sum256(append([]byte("mpc-node/application/"+id+"\x00"), seed...))
	return digest[:]
}
