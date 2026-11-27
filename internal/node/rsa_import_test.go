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
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestRSAImportRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	players, nodes := rsaTestNodes(t, rsaTestRESTAuth())
	var rest [3]*httptest.Server
	for i, node := range nodes {
		wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		node.wrappingKey = wrappingKey
		rest[i] = httptest.NewTLSServer(node.restHandler())
		t.Cleanup(rest[i].Close)
	}
	original := rsaImportTestKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(&original.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := thresholdrsa.Deal(rand.Reader, 3, 2, original, false)
	if err != nil {
		t.Fatal(err)
	}
	split := sha256.Sum256([]byte("RSA import test split"))
	var raw [3][]byte
	var bundles [3][]byte
	wrap := func(i int, plaintext []byte) []byte {
		t.Helper()
		bundle, err := wrapKeyShare(&nodes[i].wrappingKey.PublicKey, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for i := range shares {
		secret, err := shares[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raw[i], err = json.Marshal(rsaImportShare{rsaImportFormat, split[:], players, publicDER, secret})
		if err != nil {
			t.Fatal(err)
		}
		bundles[i] = wrap(i, raw[i])
	}
	type reply struct {
		code int
		body []byte
		err  error
	}
	call := func(i int, method, path, session string, selected party.IDSlice, body []byte) reply {
		if session != "" {
			path += "?mpc_routing_id=" + mpcRoutingID(session)
		}
		request, err := http.NewRequestWithContext(ctx, method, rest[i].URL+path, bytes.NewReader(body))
		if err != nil {
			return reply{err: err}
		}
		request.Header.Set("Authorization", "APIKEY "+rsaDecryptToken)
		if session != "" {
			request.Header.Set("MPC-SessionID", session)
			request.Header.Set("MPC-RoutingID", mpcRoutingID(session))
			for _, player := range selected {
				request.Header.Add("MPC-Players", string(player))
			}
		}
		response, err := rest[i].Client().Do(request)
		if err != nil {
			return reply{err: err}
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		return reply{response.StatusCode, data, err}
	}
	parse := func(result reply, status int, value any) {
		t.Helper()
		if result.err != nil || result.code != status {
			t.Fatalf("request returned HTTP %d, want %d (%v, %s)", result.code, status, result.err, result.body)
		}
		if value != nil {
			if err := json.Unmarshal(result.body, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	postImport := func(i int, session, keyID string, bundle []byte) reply {
		request, _ := json.Marshal(map[string]any{"keyID": keyID, "wrappedKeyShare": bundle})
		return call(i, http.MethodPost, "/rsa/keys/importkey", session, players, request)
	}
	runImport := func(session, keyID string, inputs [3][]byte, expected int) string {
		t.Helper()
		results := make(chan reply, len(nodes))
		for i := range nodes {
			go func() { results <- postImport(i, session, keyID, inputs[i]) }()
		}
		var agreed string
		for range nodes {
			result := <-results
			if expected != http.StatusOK {
				parse(result, expected, nil)
				continue
			}
			var body generateKeyResponse
			parse(result, expected, &body)
			if body.KeyID == "" || (agreed != "" && body.KeyID != agreed) {
				t.Fatal("nodes returned different key IDs")
			}
			agreed = body.KeyID
		}
		return agreed
	}
	withUnknownField := func(data []byte) []byte {
		return append(bytes.Clone(data[:len(data)-1]), []byte(`,"unknown":true}`)...)
	}
	parse(postImport(0, "wrong-wrap", "wrong-wrap", bundles[1]), http.StatusBadRequest, nil)
	const session = "rsa-import-roundtrip"
	id := runImport(session, "", bundles, http.StatusOK)
	parse(postImport(0, session, "", withUnknownField(bundles[0])), http.StatusBadRequest, nil)
	parse(postImport(0, session, "", wrap(0, withUnknownField(raw[0]))), http.StatusBadRequest, nil)
	var corrupted wrappedKeyShare
	if err := json.Unmarshal(bundles[0], &corrupted); err != nil {
		t.Fatal(err)
	}
	corrupted.Ciphertext[len(corrupted.Ciphertext)-1] ^= 1
	corruptedBundle, _ := json.Marshal(corrupted)
	parse(postImport(0, session, "", corruptedBundle), http.StatusBadRequest, nil)
	base := "/rsa/keys/" + id
	for i := range nodes {
		var info struct {
			PublicKey       []byte
			Players         uint
			RequiredSigners uint
		}
		parse(call(i, http.MethodPost, base+"/publickey", "", nil, nil), http.StatusOK, &info)
		if !bytes.Equal(info.PublicKey, publicDER) || info.Players != 3 || info.RequiredSigners != 2 {
			t.Fatalf("node %d stored a different public key or threshold", i+1)
		}
	}
	digest := sha256.Sum256([]byte("imported RSA signing test"))
	body, _ := json.Marshal(map[string][]byte{"messageHash": digest[:]})
	parts := make([]thresholdrsa.SignShare, 2)
	for j, i := range []int{0, 2} {
		var result struct{ PartialSignature []byte }
		parse(call(i, http.MethodPost, base+"/sign", "", nil, body), http.StatusOK, &result)
		if err := parts[j].UnmarshalBinary(result.PartialSignature); err != nil {
			t.Fatal(err)
		}
	}
	padded, err := (thresholdrsa.PKCS1v15Padder{}).Pad(&original.PublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := thresholdrsa.CombineSignShares(&original.PublicKey, 3, 2, parts, padded)
	if err != nil || rsa.VerifyPKCS1v15(&original.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatalf("imported key could not sign: %v", err)
	}
	pssBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": digest[:]})
	pssResults := make(chan reply, len(parts))
	for _, i := range []int{0, 2} {
		go func() {
			pssResults <- call(i, http.MethodPost, base+"/signpss", "imported-pss",
				party.IDSlice{players[0], players[2]}, pssBody)
		}()
	}
	var salt []byte
	for i := range parts {
		var response struct{ PartialSignature []byte }
		parse(<-pssResults, http.StatusOK, &response)
		var envelope rsaPSSEnvelope
		if err := json.Unmarshal(response.PartialSignature, &envelope); err != nil {
			t.Fatal(err)
		}
		if err := parts[i].UnmarshalBinary(envelope.Share); err != nil {
			t.Fatal(err)
		}
		if salt != nil && !bytes.Equal(salt, envelope.Salt) {
			t.Fatal("nodes disagreed on PSS salt")
		}
		salt = envelope.Salt
	}
	options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	padder := &thresholdrsa.PSSPadder{Rand: bytes.NewReader(salt), Opts: options}
	padded, err = padder.Pad(&original.PublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature, err = thresholdrsa.CombineSignShares(&original.PublicKey, 3, 2, parts, padded)
	if err != nil || rsa.VerifyPSS(&original.PublicKey, crypto.SHA256, digest[:], signature, options) != nil {
		t.Fatalf("imported key could not sign with PSS: %v", err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &original.PublicKey, []byte("usage check"), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string][]byte{"ciphertext": ciphertext})
	parse(call(0, http.MethodPost, base+"/decrypt", "", nil, body), http.StatusForbidden, nil)

	nodes[0].mu.Lock()
	delete(nodes[0].sessions, sessionKey{defaultApplication, "rsa-import." + session})
	nodes[0].mu.Unlock()
	var replay generateKeyResponse
	parse(postImport(0, session, "", wrap(0, raw[0])), http.StatusOK, &replay)
	if replay.KeyID != id {
		t.Fatal("completed import did not return the same key ID")
	}
	var altered rsaImportShare
	if err := json.Unmarshal(raw[0], &altered); err != nil {
		t.Fatal(err)
	}
	altered.SplitID[0] ^= 1
	modified, _ := json.Marshal(altered)
	parse(postImport(0, session, "", wrap(0, modified)), http.StatusConflict, nil)
	parse(call(0, http.MethodDelete, "/key/"+id, "", nil, nil), http.StatusNoContent, nil)
	parse(postImport(0, session, "", bundles[0]), http.StatusConflict, nil)

	if err := json.Unmarshal(raw[2], &altered); err != nil {
		t.Fatal(err)
	}
	altered.Share[len(altered.Share)-4] ^= 1
	modified, _ = json.Marshal(altered)
	bundles[2] = wrap(2, modified)
	runImport("bad-import-proof", "bad-import-proof", bundles, http.StatusInternalServerError)
	for i := range nodes {
		parse(call(i, http.MethodPost, "/rsa/keys/bad-import-proof/publickey", "", nil, nil), http.StatusNotFound, nil)
	}
}

// The fixture uses public 1024-bit primes from RFC 2409 §6.2 and RFC 5054 Appendix A.
func rsaImportTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	p, okP := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	q, okQ := new(big.Int).SetString("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"+
		"D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"+
		"5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"+
		"68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", 16)
	if !okP || !okQ {
		t.Fatal("invalid public prime fixture")
	}
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
		D:         new(big.Int).ModInverse(big.NewInt(65537), phi), Primes: []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRSAImportSecretEncoding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := thresholdrsa.Deal(rand.Reader, 3, 2, key, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range shares {
		raw, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !validRSAImportSecret(raw, key.Size()) {
			t.Fatal("rejected canonical uncached CIRCL share")
		}
		raw[len(raw)-3] = 1
		if validRSAImportSecret(raw, key.Size()) {
			t.Fatal("accepted cached exponent flag in an imported share")
		}
		clear(raw)
	}
}

func TestRSAImportRequiresProtectedREST(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/rsa/keys/importkey", nil)
	w := httptest.NewRecorder()
	newNode(config.Config{}).restHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unprotected RSA import returned HTTP %d", w.Code)
	}
	for _, fixture := range []struct {
		name       string
		url        string
		configure  bool
		credential string
		status     int
	}{
		{"authenticated HTTP", "http://node.example", true, rsaOtherToken, http.StatusForbidden},
		{"HTTPS with auth disabled", "https://node.example", false, "", http.StatusForbidden},
		{"HTTPS without credentials", "https://node.example", true, "", http.StatusUnauthorized},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			cfg := config.Config{PartyID: "1", MPCTLS: &config.MPCTLSConfig{}}
			if fixture.configure {
				cfg.RESTAuth = rsaTestRESTAuth()
			}
			n := newNode(cfg)
			n.shareCipher = keystore.NewShareCipher(make([]byte, 32), "1")
			n.wrappingKey = &rsa.PrivateKey{}
			if err := n.configureRESTAuth(); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, fixture.url+"/rsa/keys/importkey", nil)
			if fixture.credential != "" {
				r.Header.Set("Authorization", "APIKEY "+fixture.credential)
			}
			w := httptest.NewRecorder()
			n.restHandler().ServeHTTP(w, r)
			if w.Code != fixture.status {
				t.Fatalf("RSA import returned HTTP %d, want %d", w.Code, fixture.status)
			}
		})
	}
}
