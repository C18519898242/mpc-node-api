package node

import (
	"encoding/json"
	"net/http"
)

const serviceMajorVersion = "1"

type protocolInfo struct {
	ID      string `json:"-"`
	Name    string `json:"name"`
	Curve   string `json:"curve"`
	Version int    `json:"version"`
}

type nodeProtocol interface {
	Info() protocolInfo
	handlers() protocolHandlers
}

type protocolHandlers struct {
	generateKey     http.HandlerFunc
	publicKey       http.HandlerFunc
	sign            http.HandlerFunc
	generatePresign http.HandlerFunc
	signWithPresign http.HandlerFunc
}

type cmpProtocol struct{ node *node }

func (cmpProtocol) Info() protocolInfo {
	return protocolInfo{ID: "ecdsa", Name: "cmp", Curve: "secp256k1", Version: 1}
}

func (p cmpProtocol) handlers() protocolHandlers {
	return protocolHandlers{
		generateKey:     p.node.generateECDSAKey,
		publicKey:       p.node.ecdsaPublicKey,
		sign:            p.node.signECDSA,
		generatePresign: p.node.generateECDSAPresign,
		signWithPresign: p.node.signWithECDSAPresign,
	}
}

type frostProtocol struct{ node *node }

func (frostProtocol) Info() protocolInfo {
	return protocolInfo{ID: "frost", Name: "frost", Curve: "ed25519", Version: 1}
}

func (p frostProtocol) handlers() protocolHandlers {
	return protocolHandlers{
		generateKey:     p.node.generateFROSTKey,
		publicKey:       p.node.frostPublicKey,
		sign:            p.node.signFROST,
		generatePresign: p.node.generateFROSTPresign,
		signWithPresign: p.node.signWithFROSTPresign,
	}
}

func (n *node) registerProtocols(mux *http.ServeMux) {
	protocols := []nodeProtocol{cmpProtocol{n}, frostProtocol{n}}
	info := make(map[string]protocolInfo, len(protocols))
	for _, p := range protocols {
		meta := p.Info()
		id := meta.ID
		info[id] = meta
		base := "POST /" + id + "/keys"
		api := p.handlers()
		mux.HandleFunc(base, n.logRequest("keygen", id, api.generateKey))
		mux.HandleFunc(base+"/{keyID}/publickey", n.logRequest("publickey", id, api.publicKey))
		mux.HandleFunc(base+"/{keyID}/sign", n.logRequest("sign", id, api.sign))
		mux.HandleFunc(base+"/{keyID}/{count}/presiggen", n.logRequest("presiggen", id, api.generatePresign))
		mux.HandleFunc(base+"/{keyID}/signwithpresig", n.logRequest("signwithpresig", id, api.signWithPresign))
		mux.HandleFunc(base+"/{keyID}/reshare", n.logRequest("reshare", id, n.reshareKey(id)))
		mux.HandleFunc(base+"/{sourceKeyID}/keycopy", n.logRequest("keycopy", id, n.keyCopy(id)))
		mux.HandleFunc(base+"/{keyID}/exportkey", n.logRequest("exportkey", id, n.exportKey(id)))
		mux.HandleFunc(base+"/importkey", n.logRequest("importkey", id, n.importKey(id)))
		mux.HandleFunc(base+"/{keyID}/exportkeyshare", n.logRequest("exportkeyshare", id, n.exportLocalKeyShare(id)))
		mux.HandleFunc(base+"/importkeyshare", n.logRequest("importkeyshare", id, n.importLocalKeyShare(id)))
	}
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": serviceMajorVersion})
	})
	mux.HandleFunc("GET /info/protocols", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})
}
