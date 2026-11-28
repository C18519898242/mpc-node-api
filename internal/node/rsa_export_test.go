package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestRSAExportAndClusterMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	srcPlayers, srcNodes := rsaTestNodes(t, rsaPSSTestRESTAuth())
	dstPlayers, dstNodes := rsaTestNodes(t, rsaPSSTestRESTAuth())

	var dstWrappingDER [3][]byte
	var srcRest, dstRest [3]*httptest.Server
	for i := range 3 {
		wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		dstWrappingDER[i] = der
		dstNodes[i].wrappingKey = wrappingKey
		srcNodes[i].config.KeyTransfer = &config.KeyTransferConfig{
			ExportEnabled:      true,
			ExportWrappingKeys: [][]byte{der},
		}
		srcRest[i] = httptest.NewTLSServer(srcNodes[i].restHandler())
		dstRest[i] = httptest.NewTLSServer(dstNodes[i].restHandler())
		t.Cleanup(srcRest[i].Close)
		t.Cleanup(dstRest[i].Close)
	}

	type reply struct {
		code int
		body []byte
		err  error
	}
	call := func(servers [3]*httptest.Server, i int, token, method, path, session string, selected party.IDSlice, body []byte) reply {
		if session != "" {
			path += "?mpc_routing_id=" + mpcRoutingID(session)
		}
		req, err := http.NewRequestWithContext(ctx, method, servers[i].URL+path, bytes.NewReader(body))
		if err != nil {
			return reply{err: err}
		}
		if token != "" {
			req.Header.Set("Authorization", "APIKEY "+token)
		}
		if session != "" {
			req.Header.Set("MPC-SessionID", session)
			req.Header.Set("MPC-RoutingID", mpcRoutingID(session))
			for _, player := range selected {
				req.Header.Add("MPC-Players", string(player))
			}
		}
		res, err := servers[i].Client().Do(req)
		if err != nil {
			return reply{err: err}
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return reply{res.StatusCode, data, err}
	}
	mustJSON := func(r reply, want int, out any) {
		t.Helper()
		if r.err != nil || r.code != want {
			t.Fatalf("HTTP %d, want %d (err=%v, body=%s)", r.code, want, r.err, r.body)
		}
		if out != nil {
			if err := json.Unmarshal(r.body, out); err != nil {
				t.Fatalf("decode response %s: %v", r.body, err)
			}
		}
	}

	// 1. Create a 2-of-3 RSA signing key on the source cluster.
	const srcKeyID = "src-rsa-sign"
	keygenReq, _ := json.Marshal(map[string]any{"threshold": 1, "bits": 2048, "keyID": srcKeyID})
	keygenCh := make(chan reply, 3)
	for i := range 3 {
		go func() {
			keygenCh <- call(srcRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys", "src-rsa-keygen", srcPlayers, keygenReq)
		}()
	}
	for range 3 {
		var kg generateKeyResponse
		mustJSON(<-keygenCh, http.StatusOK, &kg)
		if kg.KeyID != srcKeyID {
			t.Fatalf("unexpected source keyID %q", kg.KeyID)
		}
	}

	var srcPubResp struct {
		PublicKey []byte `json:"publicKey"`
	}
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodGet, "/rsa/keys/"+srcKeyID+"/publickey", "", nil, nil), http.StatusOK, &srcPubResp)
	parsedPub, err := x509.ParsePKIXPublicKey(srcPubResp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	srcPublicKey := parsedPub.(*rsa.PublicKey)

	// Install deterministic fixture keys for decryption-usage rejection and keyID "_" export regression
	// without running extra slow safe-prime key generations.
	fixtureKey := rsaImportTestKey(t)
	fixtureDER, err := x509.MarshalPKIXPublicKey(&fixtureKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fixtureShares, err := thresholdrsa.Deal(rand.Reader, 3, 2, fixtureKey, false)
	if err != nil {
		t.Fatal(err)
	}
	const decKeyID = "src-rsa-decrypt"
	decSecret, err := fixtureShares[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decRecord, err := json.Marshal(storedRSAKeyShare{
		Players: srcPlayers, PublicKey: fixtureDER, Usage: rsaUsageDecrypt, DecryptionKeyShare: decSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	clear(decSecret)
	decKey := keystore.Key{Algorithm: "rsa", SessionID: "fixture-dec", KeyID: decKeyID, Threshold: 1}
	if res, err := srcNodes[0].keys.Reserve(ctx, defaultApplication, decKey); err != nil || res != keystore.Reserved {
		t.Fatalf("reserve fixture decryption key: (%v, %v)", res, err)
	}
	if err := srcNodes[0].keys.Save(ctx, defaultApplication, decKey, decRecord); err != nil {
		t.Fatal(err)
	}
	clear(decRecord)

	underscoreKey := keystore.Key{Algorithm: "rsa", SessionID: "fixture-underscore", KeyID: "_", Threshold: 1}
	for i := range 3 {
		sec, err := fixtureShares[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		rec, err := json.Marshal(storedRSAKeyShare{
			Players: srcPlayers, PublicKey: fixtureDER, Usage: rsaUsageSign, Share: sec,
		})
		clear(sec)
		if err != nil {
			t.Fatal(err)
		}
		if res, err := srcNodes[i].keys.Reserve(ctx, defaultApplication, underscoreKey); err != nil || res != keystore.Reserved {
			t.Fatalf("reserve fixture underscore key on node %d: (%v, %v)", i+1, res, err)
		}
		if err := srcNodes[i].keys.Save(ctx, defaultApplication, underscoreKey, rec); err != nil {
			t.Fatal(err)
		}
		clear(rec)
	}

	// 2. Export all 3 shares from the source cluster, each wrapped for its target node.
	type exportResp struct {
		WrappedKeyShare []byte `json:"wrappedKeyShare"`
		PublicKey       []byte `json:"publicKey"`
	}
	runExport := func(session string) [3]exportResp {
		t.Helper()
		type indexed struct {
			i   int
			res reply
		}
		ch := make(chan indexed, 3)
		for i := range 3 {
			body, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[i]})
			go func() {
				ch <- indexed{i, call(srcRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", session, srcPlayers, body)}
			}()
		}
		var out [3]exportResp
		for range 3 {
			item := <-ch
			mustJSON(item.res, http.StatusOK, &out[item.i])
			if !bytes.Equal(out[item.i].PublicKey, srcPubResp.PublicKey) {
				t.Fatalf("source node %d exported unexpected publicKey", item.i+1)
			}
		}
		return out
	}

	exported1 := runExport("rsa-export-1")
	exported2 := runExport("rsa-export-2")

	// Identical export retry succeeds; changing wrappingKey on the same session returns 409.
	retryBody, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[0]})
	var retryResp exportResp
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "rsa-export-1", srcPlayers, retryBody), http.StatusOK, &retryResp)
	if !bytes.Equal(retryResp.WrappedKeyShare, exported1[0].WrappedKeyShare) {
		t.Fatal("identical export retry changed wrappedKeyShare")
	}
	srcNodes[0].config.KeyTransfer.ExportWrappingKeys = append(srcNodes[0].config.KeyTransfer.ExportWrappingKeys, dstWrappingDER[1])
	conflictBody, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[1]})
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "rsa-export-1", srcPlayers, conflictBody), http.StatusConflict, nil)
	srcNodes[0].config.KeyTransfer.ExportWrappingKeys = [][]byte{dstWrappingDER[0]}

	// 3. Import exported shares into the target cluster.
	const dstKeyID = "dst-rsa-sign"
	importCh := make(chan reply, 3)
	for i := range 3 {
		body, _ := json.Marshal(map[string]any{"keyID": dstKeyID, "wrappedKeyShare": exported1[i].WrappedKeyShare})
		go func() {
			importCh <- call(dstRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/importkey", "dst-rsa-import", dstPlayers, body)
		}()
	}
	for range 3 {
		var imp generateKeyResponse
		mustJSON(<-importCh, http.StatusOK, &imp)
		if imp.KeyID != dstKeyID {
			t.Fatalf("unexpected imported keyID %q", imp.KeyID)
		}
	}

	// All 3 target nodes must return the exact same SPKI DER public key bytes as source.
	for i := range 3 {
		var pub struct {
			PublicKey []byte `json:"publicKey"`
		}
		mustJSON(call(dstRest, i, rsaOtherToken, http.MethodGet, "/rsa/keys/"+dstKeyID+"/publickey", "", nil, nil), http.StatusOK, &pub)
		if !bytes.Equal(pub.PublicKey, srcPubResp.PublicKey) {
			t.Fatalf("target node %d publicKey differs from source", i+1)
		}
		var info struct {
			PublicKey       []byte `json:"publicKey"`
			Players         uint   `json:"players"`
			RequiredSigners uint   `json:"requiredSigners"`
		}
		mustJSON(call(dstRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/"+dstKeyID+"/publickey", "", nil, []byte(`{}`)), http.StatusOK, &info)
		if !bytes.Equal(info.PublicKey, srcPubResp.PublicKey) || info.Players != 3 || info.RequiredSigners != 2 {
			t.Fatalf("target node %d PublicKeyInfo mismatch", i+1)
		}
	}

	// 4. Sign with RSA-PSS on target nodes 1 and 3 and verify using the source public key.
	digest := sha256.Sum256([]byte("migrated RSA-PSS message"))
	pssReq, _ := json.Marshal(map[string]any{"hash": 5, "messageHash": digest[:], "players": nil})
	pssPlayers := party.IDSlice{"0", "2"}
	pssCh := make(chan reply, 2)
	for _, idx := range []int{0, 2} {
		go func() {
			pssCh <- call(dstRest, idx, rsaOtherToken, http.MethodPost, "/rsa/keys/"+dstKeyID+"/signpss", "dst-pss-1", pssPlayers, pssReq)
		}()
	}
	var salt []byte
	shares := make([]thresholdrsa.SignShare, 2)
	for i := range 2 {
		var body struct {
			PartialSignature []byte `json:"partialSignature"`
		}
		mustJSON(<-pssCh, http.StatusOK, &body)
		var env rsaPSSEnvelope
		if err := json.Unmarshal(body.PartialSignature, &env); err != nil {
			t.Fatal(err)
		}
		if err := shares[i].UnmarshalBinary(env.Share); err != nil {
			t.Fatal(err)
		}
		if salt == nil {
			salt = env.Salt
		} else if !bytes.Equal(salt, env.Salt) {
			t.Fatal("target nodes produced mismatched PSS salts")
		}
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	padded, err := (&thresholdrsa.PSSPadder{Rand: bytes.NewReader(salt), Opts: opts}).Pad(srcPublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := thresholdrsa.CombineSignShares(srcPublicKey, 3, 2, shares, padded)
	if err != nil || rsa.VerifyPSS(srcPublicKey, crypto.SHA256, digest[:], sig, opts) != nil {
		t.Fatalf("migrated key PSS verification against source public key failed: %v", err)
	}

	// 5. Negative export checks: disabled export, non-whitelisted wrapping key, cross-app, decrypt key, bad players, plaintext HTTP.
	validBody, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[0]})
	nonAllowedBody, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[1]})
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "neg-not-allowed", srcPlayers, nonAllowedBody), http.StatusForbidden, nil)
	mustJSON(call(srcRest, 0, "other-app-pss-token", http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "neg-cross-app", srcPlayers, validBody), http.StatusNotFound, nil)
	mustJSON(call(srcRest, 0, rsaDecryptToken, http.MethodPost, "/rsa/keys/"+decKeyID+"/exportkey", "neg-decrypt-key", srcPlayers, validBody), http.StatusForbidden, nil)
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "neg-subset", party.IDSlice{srcPlayers[0], srcPlayers[1]}, validBody), http.StatusBadRequest, nil)
	mustJSON(call(srcRest, 0, "", http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "neg-unauth", srcPlayers, validBody), http.StatusUnauthorized, nil)

	// Regression: valid keyID "_" must export and import normally.
	type underscoreIdx struct {
		i   int
		res reply
	}
	underscoreCh := make(chan underscoreIdx, 3)
	for i := range 3 {
		body, _ := json.Marshal(map[string][]byte{"wrappingKey": dstWrappingDER[i]})
		go func() {
			underscoreCh <- underscoreIdx{i, call(srcRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/_/exportkey", "export-underscore", srcPlayers, body)}
		}()
	}
	var exportedUnderscore [3]exportResp
	for range 3 {
		item := <-underscoreCh
		mustJSON(item.res, http.StatusOK, &exportedUnderscore[item.i])
		if !bytes.Equal(exportedUnderscore[item.i].PublicKey, fixtureDER) {
			t.Fatalf("source node %d exported unexpected publicKey for keyID _", item.i+1)
		}
	}
	for i := range 3 {
		body, _ := json.Marshal(map[string]any{"keyID": "_", "wrappedKeyShare": exportedUnderscore[i].WrappedKeyShare})
		go func() {
			importCh <- call(dstRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/importkey", "import-underscore", dstPlayers, body)
		}()
	}
	for range 3 {
		var imp generateKeyResponse
		mustJSON(<-importCh, http.StatusOK, &imp)
		if imp.KeyID != "_" {
			t.Fatalf("unexpected imported keyID %q, want _", imp.KeyID)
		}
	}
	var importedUnderscorePub struct {
		PublicKey []byte `json:"publicKey"`
	}
	mustJSON(call(dstRest, 0, rsaOtherToken, http.MethodGet, "/rsa/keys/_/publickey", "", nil, nil), http.StatusOK, &importedUnderscorePub)
	if !bytes.Equal(importedUnderscorePub.PublicKey, fixtureDER) {
		t.Fatal("migrated keyID _ publicKey differs from source")
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey?mpc_routing_id="+mpcRoutingID("neg-http"), bytes.NewReader(validBody))
	httpReq.Header.Set("Authorization", "APIKEY "+rsaOtherToken)
	httpReq.Header.Set("MPC-SessionID", "neg-http")
	httpReq.Header.Set("MPC-RoutingID", mpcRoutingID("neg-http"))
	for _, p := range srcPlayers {
		httpReq.Header.Add("MPC-Players", string(p))
	}
	httpW := httptest.NewRecorder()
	srcNodes[0].restHandler().ServeHTTP(httpW, httpReq)
	if httpW.Code != http.StatusForbidden {
		t.Fatalf("plaintext HTTP export returned HTTP %d, want 403", httpW.Code)
	}

	srcNodes[0].config.KeyTransfer.ExportEnabled = false
	mustJSON(call(srcRest, 0, rsaOtherToken, http.MethodPost, "/rsa/keys/"+srcKeyID+"/exportkey", "neg-disabled", srcPlayers, validBody), http.StatusForbidden, nil)
	srcNodes[0].config.KeyTransfer.ExportEnabled = true

	// 6. Wrong node share and cross-session share mixing must fail target import.
	wrongNodeBody, _ := json.Marshal(map[string]any{"keyID": "wrong-node-import", "wrappedKeyShare": exported1[0].WrappedKeyShare})
	mustJSON(call(dstRest, 1, rsaOtherToken, http.MethodPost, "/rsa/keys/importkey", "dst-wrong-node", dstPlayers, wrongNodeBody), http.StatusBadRequest, nil)

	// Even if all target nodes share the same wrapping key, node 1's share cannot be imported by node 2.
	sharedWrap := dstNodes[0].wrappingKey
	savedWrap1 := dstNodes[1].wrappingKey
	dstNodes[1].wrappingKey = sharedWrap
	mustJSON(call(dstRest, 1, rsaOtherToken, http.MethodPost, "/rsa/keys/importkey", "dst-wrong-index", dstPlayers, wrongNodeBody), http.StatusBadRequest, nil)
	dstNodes[1].wrappingKey = savedWrap1

	mixedImports := [3][]byte{exported1[0].WrappedKeyShare, exported2[1].WrappedKeyShare, exported1[2].WrappedKeyShare}
	for i := range 3 {
		body, _ := json.Marshal(map[string]any{"keyID": "mixed-sessions", "wrappedKeyShare": mixedImports[i]})
		go func() {
			importCh <- call(dstRest, i, rsaOtherToken, http.MethodPost, "/rsa/keys/importkey", "dst-mixed-export", dstPlayers, body)
		}()
	}
	for range 3 {
		r := <-importCh
		if r.err != nil || r.code == http.StatusOK {
			t.Fatalf("mixed export sessions import unexpectedly succeeded (HTTP %d)", r.code)
		}
	}
	for i := range 3 {
		mustJSON(call(dstRest, i, rsaOtherToken, http.MethodGet, "/rsa/keys/mixed-sessions/publickey", "", nil, nil), http.StatusNotFound, nil)
	}
}
