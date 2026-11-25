package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type walletReceipt struct {
	WalletID   string `json:"walletID"`
	ECDSAKeyID string `json:"ecdsaKeyID"`
	FROSTKeyID string `json:"frostKeyID"`
}

func walletIDs(app, session string) walletReceipt {
	id := func(kind string) string {
		hash := sha256.Sum256([]byte("wallet/v1\x00" + kind + "\x00" + app + "\x00" + session))
		return base64.RawURLEncoding.EncodeToString(hash[:21])
	}
	return walletReceipt{id("wallet"), id("ecdsa"), id("frost")}
}

// Wallet messages share one admission slot but have independent inboxes for
// coordination, CMP and FROST. Control uses slot -1 (the ordinary inbox).
func splitWalletRoute(route string) (string, int, bool) {
	name, ok := strings.CutPrefix(route, "wallet.")
	if !ok {
		return "", 0, false
	}
	sid, phase, hasPhase := strings.Cut(name, ".")
	if !memorySessionPattern.MatchString(sid) {
		return "", 0, false
	}
	base := "wallet." + sid
	switch {
	case !hasPhase:
		return base, -1, true
	case phase == "cmp":
		return base, 0, true
	case phase == "frost":
		return base, 1, true
	default:
		return "", 0, false
	}
}

func (n *node) createWallet(w http.ResponseWriter, r *http.Request) {
	cfg := n.config.WalletBackup
	if cfg == nil || (n.walletBackup == nil && !cfg.AllowRequestPublicKeys) {
		http.Error(w, "wallet backup is not configured", http.StatusForbidden)
		return
	}
	sid := r.Header.Get("MPC-SessionID")
	var request *struct {
		BackupPublicKeys json.RawMessage `json:"backupPublicKeys"`
	}
	if !memorySessionPattern.MatchString(sid) || decodeJSON(w, r, &request, 16384) != nil || request == nil {
		http.Error(w, "invalid wallet session or request body", http.StatusBadRequest)
		return
	}
	if request.BackupPublicKeys != nil && !cfg.AllowRequestPublicKeys {
		http.Error(w, "wallet backup public keys in requests are disabled", http.StatusForbidden)
		return
	}
	if request.BackupPublicKeys == nil && n.walletBackup == nil {
		http.Error(w, "wallet backup requires a configured public key or backupPublicKeys", http.StatusBadRequest)
		return
	}
	players := n.signingPlayers(w, r, sid)
	if players == nil {
		return
	}
	if len(players) != 3 || !slices.Equal(players, n.configuredPlayers()) {
		http.Error(w, "wallet creation requires all three configured nodes", http.StatusBadRequest)
		return
	}
	backupPlan, err := n.prepareWalletBackup(players, request.BackupPublicKeys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	receipt := walletIDs(applicationID(r.Context()), sid)
	session, err := n.beginWallet(r.Context(), sid, receipt, players, backupPlan)
	switch {
	case errors.Is(err, errTooManySessions):
		http.Error(w, "too many concurrent MPC sessions", http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, "could not reserve wallet", http.StatusInternalServerError)
		return
	case session == nil:
		http.Error(w, "wallet session already used", http.StatusConflict)
		return
	}
	select {
	case <-r.Context().Done():
		return
	case <-session.done:
		if session.status.State != "succeeded" {
			http.Error(w, "wallet creation failed", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

func (n *node) beginWallet(ctx context.Context, sid string, receipt walletReceipt, players party.IDSlice, plan walletBackupPlan) (*keygenSession, error) {
	app := applicationID(ctx)
	lookup := sessionKey{app, "wallet." + sid}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pruneSessionsLocked(time.Now())
	var binding [32]byte
	var requestDigest []byte
	if plan.keyIDs[0] != "" {
		binding = sha256.Sum256([]byte(strings.Join(plan.keyIDs[:], "")))
		requestDigest = binding[:]
	}
	if session := n.sessions[lookup]; session != nil {
		if session.signBinding != binding {
			return nil, nil
		}
		return session, nil
	}
	status, err := n.keys.WalletStatus(ctx, app, sid, requestDigest)
	if err != nil || status == keystore.Conflict {
		return nil, err
	}
	session := &keygenSession{done: make(chan struct{}), players: players, signBinding: binding}
	if status == keystore.Completed {
		session.status.State = "succeeded"
		close(session.done)
		return session, nil
	}
	if err := n.checkSessionCapacityLocked(app); err != nil {
		return nil, err
	}
	reserved, err := n.keys.ReserveWallet(ctx, app, sid, receipt.WalletID, requestDigest)
	if err != nil || !reserved {
		return nil, err
	}
	session.status.State = "running"
	session.incoming = make(chan *protocol.Message, 32)
	for i := range session.walletInboxes {
		session.walletInboxes[i] = make(chan *protocol.Message, 32)
	}
	n.sessions[lookup] = session
	go n.runWallet(n.operationContext(ctx), sid, receipt, session, plan)
	return session, nil
}

func (n *node) runWallet(ctx context.Context, sid string, receipt walletReceipt, session *keygenSession, plan walletBackupPlan) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, keygenTimeout)
	defer cancel()
	stage, err := n.generateWallet(ctx, sid, receipt, session, plan)
	n.logMPCResult("createwallet", "wallet", stage, start, err)
	n.mu.Lock()
	session.status.State = "succeeded"
	if err != nil {
		session.status.State = "failed"
	}
	n.finishSessionLocked(session)
	close(session.done)
	n.mu.Unlock()
}
