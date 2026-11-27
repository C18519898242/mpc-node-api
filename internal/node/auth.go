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
	rsaDecryption bool
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
		credentials = append(credentials, apiKeyCredential{digest: digest, applicationID: key.ApplicationID, rsaDecryption: key.RSADecryption})
		applications[key.ApplicationID] = struct{}{}
	}
	n.credentials, n.applications = credentials, applications
	return nil
}

type applicationContextKey struct{}
type rsaDecryptionContextKey struct{}

func applicationID(ctx context.Context) string {
	if id, ok := ctx.Value(applicationContextKey{}).(string); ok {
		return id
	}
	return defaultApplication
}

func withApplication(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), applicationContextKey{}, id))
}

func rsaDecryptionAllowed(r *http.Request) bool {
	allowed, _ := r.Context().Value(rsaDecryptionContextKey{}).(bool)
	return r.TLS != nil && allowed
}

func (n *node) authenticatedRESTTLS(r *http.Request) bool {
	app, ok := r.Context().Value(applicationContextKey{}).(string)
	return n.config.RESTAuth != nil && r.TLS != nil && ok && app != ""
}

func (n *node) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		credential := n.authenticateAPIKey(r)
		if credential == nil {
			w.Header().Set("WWW-Authenticate", "APIKEY")
			http.Error(w, "unauthorized API key", http.StatusUnauthorized)
			return
		}
		if credential.rsaDecryption && r.TLS == nil {
			http.Error(w, "RSA decryption credentials require HTTPS", http.StatusForbidden)
			return
		}
		r = withApplication(r, credential.applicationID)
		r = r.WithContext(context.WithValue(r.Context(), rsaDecryptionContextKey{}, credential.rsaDecryption))
		next.ServeHTTP(w, r)
	})
}

func (n *node) authenticateAPIKey(r *http.Request) *apiKeyCredential {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return nil
	}
	scheme, key, ok := strings.Cut(headers[0], " ")
	if !ok || !strings.EqualFold(scheme, "APIKEY") || key == "" || strings.ContainsAny(key, " \t,") {
		return nil
	}
	digest := sha256.Sum256([]byte(key))
	var matched *apiKeyCredential
	for i := range n.credentials {
		credential := &n.credentials[i]
		if subtle.ConstantTimeCompare(digest[:], credential.digest[:]) == 1 {
			matched = credential
		}
	}
	return matched
}

// Keep the original protocol binding for the existing database's application.
func applicationBinding(id string, seed []byte) []byte {
	if id == defaultApplication {
		return seed
	}
	digest := sha256.Sum256(append([]byte("mpc-node/application/"+id+"\x00"), seed...))
	return digest[:]
}
