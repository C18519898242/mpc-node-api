package node

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
)

func (n *node) deleteKeyShare(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyID")
	if !keyIDPattern.MatchString(keyID) {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}
	var body [1]byte
	if read, err := io.ReadFull(r.Body, body[:]); read != 0 || err != io.EOF {
		http.Error(w, "key delete request body must be empty", http.StatusBadRequest)
		return
	}
	for _, algorithm := range []string{"ecdsa", "frost", "rsa"} {
		release := n.lockKeyOperation(w, applicationID(r.Context()), algorithm, keyID, true)
		if release == nil {
			return
		}
		defer release()
	}
	switch err := n.keys.DeleteKeyShare(r.Context(), applicationID(r.Context()), keyID); {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not delete key share", http.StatusInternalServerError)
	default:
		n.mu.Lock()
		for id, session := range n.sessions {
			if id.applicationID == applicationID(r.Context()) && session.key.KeyID == keyID {
				delete(n.sessions, id)
			}
		}
		n.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}
