package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

var sessionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	return mux
}

func (n *node) restHandler() http.Handler {
	mux := healthMux()
	mux.HandleFunc("POST /ecdsa/keys", n.logRequest("keygen", "ecdsa", n.generateECDSAKey))
	mux.HandleFunc("POST /ecdsa/keys/{keyID}/publickey", n.logRequest("publickey", "ecdsa", n.ecdsaPublicKey))
	mux.HandleFunc("POST /ecdsa/keys/{keyID}/sign", n.logRequest("sign", "ecdsa", n.signECDSA))
	mux.HandleFunc("POST /ecdsa/keys/{keyID}/{count}/presiggen", n.logRequest("presiggen", "ecdsa", n.generateECDSAPresign))
	mux.HandleFunc("POST /ecdsa/keys/{keyID}/signwithpresig", n.logRequest("signwithpresig", "ecdsa", n.signWithECDSAPresign))
	mux.HandleFunc("POST /frost/keys", n.logRequest("keygen", "frost", n.generateFROSTKey))
	mux.HandleFunc("POST /frost/keys/{keyID}/publickey", n.logRequest("publickey", "frost", n.frostPublicKey))
	mux.HandleFunc("POST /frost/keys/{keyID}/sign", n.logRequest("sign", "frost", n.signFROST))
	mux.HandleFunc("POST /frost/keys/{keyID}/{count}/presiggen", n.logRequest("presiggen", "frost", n.generateFROSTPresign))
	mux.HandleFunc("POST /frost/keys/{keyID}/signwithpresig", n.logRequest("signwithpresig", "frost", n.signWithFROSTPresign))
	mux.HandleFunc("POST /key/{keyID}/count/presigs", n.logRequest("countpresigs", "key", n.countPresign))
	mux.HandleFunc("DELETE /key/{keyID}/presigs", n.logRequest("deletepresigs", "key", n.deletePresign))
	mux.HandleFunc("POST /v1/keygen", n.logRequest("keygen", "ecdsa", n.startKeygen))
	mux.HandleFunc("GET /v1/sessions/{sessionId}", n.getKeygen)
	return mux
}

func (n *node) startKeygen(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SessionID string `json:"sessionId"`
	}
	if decodeJSON(w, r, &request, 4096) != nil || !sessionIDPattern.MatchString(request.SessionID) {
		http.Error(w, "invalid keygen request or sessionId", http.StatusBadRequest)
		return
	}

	status, started, err := n.beginKeygen(request.SessionID)
	switch {
	case errors.Is(err, errRecordKeygenAttempt):
		http.Error(w, "could not record keygen attempt", http.StatusInternalServerError)
	case err != nil:
		http.Error(w, "could not read keygen result", http.StatusInternalServerError)
	case started:
		writeStatus(w, http.StatusAccepted, status)
	default:
		writeStatus(w, http.StatusOK, status)
	}
}

func (n *node) getKeygen(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	if !sessionIDPattern.MatchString(id) {
		http.Error(w, "invalid sessionId", http.StatusBadRequest)
		return
	}
	status, err := n.getKeygenStatus(id)
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.NotFound(w, r)
	case err != nil:
		http.Error(w, "could not read keygen result", http.StatusInternalServerError)
	default:
		writeStatus(w, http.StatusOK, status)
	}
}

func writeStatus(w http.ResponseWriter, code int, status keygenStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(status)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any, limit int64) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return fmt.Errorf("expected a single JSON value")
	}
	return nil
}
