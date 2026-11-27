package node

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	thresholdrsa "github.com/C18519898242/circl/tss/rsa"
	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func rsaPSSTestRESTAuth() *config.RESTAuthConfig {
	auth := rsaTestRESTAuth()
	sum := sha256.Sum256([]byte("other-app-pss-token"))
	auth.APIKeys = append(auth.APIKeys, config.APIKey{
		ApplicationID: "other-app",
		SHA256:        base64.StdEncoding.EncodeToString(sum[:]),
	})
	return auth
}

func TestRSAPSSSigning(t *testing.T) {
	players, nodes := rsaTestNodes(t, rsaPSSTestRESTAuth())
	var rest [3]*httptest.Server
	for i, n := range nodes {
		rest[i] = httptest.NewTLSServer(n.restHandler())
		t.Cleanup(rest[i].Close)
	}
	doREST := func(nodeIdx int, token, path string, body []byte, session string, selected []party.ID) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rest[nodeIdx].URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "APIKEY "+token)
		}
		if session != "" {
			routingID := mpcRoutingID(session)
			req.Header.Set("MPC-SessionID", session)
			req.Header.Set("MPC-RoutingID", routingID)
			for _, player := range selected {
				req.Header.Add("MPC-Players", string(player))
			}
		}
		res, err := rest[nodeIdx].Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, res.Header, data
	}

	const keygenSession, keyID = "rsa-pss-keygen", "pss-key"
	keygenReq := func(i int) int {
		body, _ := json.Marshal(map[string]any{"threshold": 1, "bits": 2048, "keyID": keyID})
		routingID := mpcRoutingID(keygenSession)
		code, _, respBody := doREST(i, rsaOtherToken, "/rsa/keys?mpc_routing_id="+routingID, body, keygenSession, players)
		if code != http.StatusOK {
			t.Errorf("RSA keygen node %d returned HTTP %d: %s", i+1, code, respBody)
		}
		return code
	}
	replies := make(chan int, len(nodes))
	for i := range nodes {
		go func() { replies <- keygenReq(i) }()
	}
	for range nodes {
		if code := <-replies; code != http.StatusOK {
			t.Fatalf("RSA keygen failed with HTTP %d", code)
		}
	}

	pubCode, _, pubBody := doREST(0, rsaOtherToken, "/rsa/keys/"+keyID+"/publickey", []byte(`{}`), "", nil)
	var pubResp struct {
		PublicKey       []byte
		Players         uint
		RequiredSigners uint
	}
	if pubCode != http.StatusOK || json.Unmarshal(pubBody, &pubResp) != nil {
		t.Fatalf("public key request returned HTTP %d", pubCode)
	}
	parsed, err := x509.ParsePKIXPublicKey(pubResp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := parsed.(*rsa.PublicKey)

	digest := sha256.Sum256([]byte("threshold RSA-PSS message"))
	signOnce := func(session string, selected []int, hash string, msgDigest []byte) ([]byte, [][]byte) {
		t.Helper()
		routingID := mpcRoutingID(session)
		selectedIDs := make([]party.ID, len(selected))
		for i, idx := range selected {
			selectedIDs[i] = players[idx]
		}
		reqBody, _ := json.Marshal(map[string]any{"hash": hash, "messageHash": msgDigest})
		type res struct {
			idx    int
			code   int
			header http.Header
			body   []byte
		}
		ch := make(chan res, len(selected))
		for _, idx := range selected {
			go func() {
				code, hdr, data := doREST(idx, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, reqBody, session, selectedIDs)
				ch <- res{idx, code, hdr, data}
			}()
		}
		envelopes := make([][]byte, 0, len(selected))
		var salt []byte
		shares := make([]thresholdrsa.SignShare, 0, len(selected))
		for range selected {
			got := <-ch
			if got.code != http.StatusOK || got.header.Get("Cache-Control") != "no-store" {
				t.Fatalf("signpss node %d returned HTTP %d: %s", got.idx+1, got.code, got.body)
			}
			var body struct {
				PartialSignature []byte `json:"partialSignature"`
			}
			var env rsaPSSEnvelope
			var share thresholdrsa.SignShare
			if json.Unmarshal(got.body, &body) != nil || json.Unmarshal(body.PartialSignature, &env) != nil ||
				env.Format != rsaPSSFormat || env.SessionID != session || env.KeyID != keyID || env.HashFunction != "SHA256" ||
				!bytes.Equal(env.PublicKey, pubResp.PublicKey) || env.Players != 3 || env.Threshold != 2 ||
				!bytes.Equal(env.Digest, msgDigest) || len(env.Salt) != sha256.Size ||
				share.UnmarshalBinary(env.Share) != nil || env.PlayerIndex != share.Index {
				t.Fatalf("invalid RSA-PSS envelope from node %d", got.idx+1)
			}
			if salt == nil {
				salt = env.Salt
			} else if !bytes.Equal(salt, env.Salt) {
				t.Fatalf("nodes produced mismatched salts")
			}
			envelopes = append(envelopes, body.PartialSignature)
			shares = append(shares, share)
		}
		padder := &thresholdrsa.PSSPadder{
			Rand: bytes.NewReader(salt),
			Opts: &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		}
		padded, err := padder.Pad(pubKey, crypto.SHA256, msgDigest)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := thresholdrsa.CombineSignShares(pubKey, pubResp.Players, pubResp.RequiredSigners, shares, padded)
		if err != nil {
			t.Fatal(err)
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		if err := rsa.VerifyPSS(pubKey, crypto.SHA256, msgDigest, sig, opts); err != nil {
			t.Fatalf("rsa.VerifyPSS failed: %v", err)
		}
		return sig, envelopes
	}

	// Two sessions for the same digest using nodes 1 and 3 must produce distinct valid signatures.
	sig1, _ := signOnce("pss-sess-1", []int{0, 2}, "SHA256", digest[:])
	sig2, _ := signOnce("pss-sess-2", []int{0, 2}, "SHA256", digest[:])
	if bytes.Equal(sig1, sig2) {
		t.Fatal("two RSA-PSS sessions produced identical signatures")
	}

	// Replaying the same session with changed parameters must return 409 Conflict.
	otherDigest := sha256.Sum256([]byte("different digest"))
	conflictReq, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": otherDigest[:]})
	cCode, _, _ := doREST(0, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID("pss-sess-1"), conflictReq, "pss-sess-1", []party.ID{players[0], players[2]})
	if cCode != http.StatusConflict {
		t.Fatalf("conflicting replay returned HTTP %d, want 409", cCode)
	}

	// Missing credentials over HTTPS must return 401; valid credentials over plain HTTP must return 403.
	unauthCode, _, _ := doREST(0, "", "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID("unauth-pss"), conflictReq, "unauth-pss", []party.ID{players[0], players[2]})
	if unauthCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated signpss returned HTTP %d, want 401", unauthCode)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID("plain-http-pss"), bytes.NewReader(conflictReq))
	httpReq.Header.Set("Authorization", "APIKEY "+rsaOtherToken)
	httpReq.Header.Set("MPC-SessionID", "plain-http-pss")
	httpReq.Header.Set("MPC-RoutingID", mpcRoutingID("plain-http-pss"))
	httpReq.Header.Add("MPC-Players", string(players[0]))
	httpReq.Header.Add("MPC-Players", string(players[2]))
	httpW := httptest.NewRecorder()
	nodes[0].restHandler().ServeHTTP(httpW, httpReq)
	if httpW.Code != http.StatusForbidden {
		t.Fatalf("plaintext HTTP signpss returned HTTP %d, want 403", httpW.Code)
	}

	// Invalid hash, digest length, or insufficient signers return 400.
	for name, tc := range map[string]struct {
		body    string
		signers []party.ID
	}{
		"unsupported hash": {`{"hash":"SHA512","messageHash":"` + string(bytes.Repeat([]byte("A"), 44)) + `"}`, []party.ID{players[0], players[2]}},
		"short digest":     {`{"hash":"SHA256","messageHash":"AA=="}`, []party.ID{players[0], players[2]}},
		"single signer":    {`{"hash":"SHA256","messageHash":"` + string(bytes.Repeat([]byte("A"), 44)) + `"}`, []party.ID{players[0]}},
	} {
		t.Run(name, func(t *testing.T) {
			sid := "invalid-" + name
			sid = string(bytes.Map(func(r rune) rune {
				if r == ' ' {
					return '-'
				}
				return r
			}, []byte(sid)))
			code, _, body := doREST(0, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID(sid), []byte(tc.body), sid, tc.signers)
			if code != http.StatusBadRequest {
				t.Fatalf("%s returned HTTP %d, want 400 (%s)", name, code, body)
			}
		})
	}

	// Cross-application isolation returns 404.
	appBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": digest[:]})
	appCode, _, _ := doREST(0, "other-app-pss-token", "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID("other-app-pss"), appBody, "other-app-pss", []party.ID{players[0], players[2]})
	if appCode != http.StatusNotFound {
		t.Fatalf("cross-application signpss returned HTTP %d, want 404", appCode)
	}

	postPeerMessage := func(senderIdx, targetIdx int, session string, msg protocol.Message) int {
		t.Helper()
		payload, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		targetID := players[targetIdx]
		endpoint := "https://" + nodes[senderIdx].config.Peers[targetID] + peerApplicationPath + defaultApplication + "/internal/mpc/" + rsaPSSSignPrefix + session
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := nodes[senderIdx].peerClients[targetID].Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}

	waitRunning := func(nodeIdx int, session string) {
		t.Helper()
		key := sessionKey{defaultApplication, rsaPSSSignPrefix + session}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			nodes[nodeIdx].mu.Lock()
			s := nodes[nodeIdx].sessions[key]
			nodes[nodeIdx].mu.Unlock()
			if s != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for node %d session %s", nodeIdx+1, session)
	}

	// An unselected peer knowing the session ID must be rejected without aborting an active 2-of-3 session.
	t.Run("unselected peer cannot abort active session", func(t *testing.T) {
		const sid = "pss-unselected-peer"
		routingID := mpcRoutingID(sid)
		reqBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": digest[:]})
		selectedIDs := []party.ID{players[0], players[2]}

		node1Done := make(chan int, 1)
		go func() {
			code, _, _ := doREST(0, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, reqBody, sid, selectedIDs)
			node1Done <- code
		}()
		waitRunning(0, sid)

		bogusSSID := bytes.Repeat([]byte{0x11}, sha256.Size)
		if code := postPeerMessage(1, 0, sid, protocol.Message{
			SSID: bogusSSID, From: players[1], To: players[0], Protocol: rsaPSSReadyMessage,
		}); code != http.StatusBadRequest {
			t.Fatalf("unselected peer message to coordinator returned HTTP %d, want 400", code)
		}
		// A selected follower sending a forged coordinator salt/abort message must also be rejected with 400.
		if code := postPeerMessage(2, 0, sid, protocol.Message{
			SSID: bogusSSID, From: players[2], To: players[0], Protocol: rsaPSSAbortMessage,
		}); code != http.StatusBadRequest {
			t.Fatalf("follower abort spoof to coordinator returned HTTP %d, want 400", code)
		}

		node3Code, _, _ := doREST(2, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, reqBody, sid, selectedIDs)
		if node3Code != http.StatusOK {
			t.Fatalf("node 3 returned HTTP %d after unselected peer interference, want 200", node3Code)
		}
		if node1Code := <-node1Done; node1Code != http.StatusOK {
			t.Fatalf("node 1 returned HTTP %d after unselected peer interference, want 200", node1Code)
		}
	})

	// Duplicate identical ready retry from an already-ready follower in a 3-party session must remain idempotent.
	t.Run("3-party idempotent ready retry", func(t *testing.T) {
		const sid = "pss-ready-retry"
		routingID := mpcRoutingID(sid)
		reqBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": digest[:]})
		resCh := make(chan int, 3)
		for _, idx := range []int{0, 1} {
			go func() {
				code, _, _ := doREST(idx, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, reqBody, sid, players)
				resCh <- code
			}()
		}
		waitRunning(0, sid)
		waitRunning(1, sid)

		transcript, err := json.Marshal(struct {
			SessionID    string
			KeyID        string
			Hash         string
			Digest       []byte
			Signers      party.IDSlice
			PublicKeyDER []byte
		}{sid, keyID, "SHA256", digest[:], players, pubResp.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		ssid := sha256.Sum256(applicationBinding(defaultApplication, transcript))
		// Wait briefly so node 2's initial ready has reached node 1, then send an identical duplicate ready.
		time.Sleep(30 * time.Millisecond)
		if code := postPeerMessage(1, 0, sid, protocol.Message{
			SSID: ssid[:], From: players[1], To: players[0], Protocol: rsaPSSReadyMessage,
		}); code != http.StatusNoContent {
			t.Fatalf("duplicate identical ready returned HTTP %d, want 204", code)
		}

		go func() {
			code, _, _ := doREST(2, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, reqBody, sid, players)
			resCh <- code
		}()
		for range 3 {
			if code := <-resCh; code != http.StatusOK {
				t.Fatalf("3-party retry session participant returned HTTP %d, want 200", code)
			}
		}
	})

	// In a 3-party conflict, already-ready followers must fail promptly instead of hanging for 3 minutes.
	for _, tc := range []struct {
		name    string
		session string
		digests [3][32]byte
		delay3  bool
	}{
		{
			name:    "3-party third node conflicts after second is ready",
			session: "pss-3party-conflict-third",
			digests: [3][32]byte{
				sha256.Sum256([]byte("msg-a")),
				sha256.Sum256([]byte("msg-a")),
				sha256.Sum256([]byte("msg-b")),
			},
			delay3: true,
		},
		{
			name:    "3-party coordinator disagrees with both followers",
			session: "pss-3party-conflict-coord",
			digests: [3][32]byte{
				sha256.Sum256([]byte("msg-coord")),
				sha256.Sum256([]byte("msg-followers")),
				sha256.Sum256([]byte("msg-followers")),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routingID := mpcRoutingID(tc.session)
			ch := make(chan int, 3)
			startNode := func(idx int) {
				b, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": tc.digests[idx][:]})
				go func() {
					code, _, _ := doREST(idx, rsaOtherToken, "/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+routingID, b, tc.session, players)
					ch <- code
				}()
			}
			if tc.delay3 {
				startNode(0)
				startNode(1)
				waitRunning(0, tc.session)
				waitRunning(1, tc.session)
				time.Sleep(30 * time.Millisecond)
				startNode(2)
			} else {
				startNode(1)
				startNode(2)
				waitRunning(1, tc.session)
				waitRunning(2, tc.session)
				time.Sleep(30 * time.Millisecond)
				startNode(0)
			}
			deadline := time.After(5 * time.Second)
			for range 3 {
				select {
				case code := <-ch:
					if code != http.StatusInternalServerError {
						t.Fatalf("conflicting 3-party participant returned HTTP %d, want 500", code)
					}
				case <-deadline:
					t.Fatal("3-party conflict did not abort all participants promptly")
				}
			}
		})
	}
}

func TestRSAPSSRejectsUnprotectedAndDecryptionKey(t *testing.T) {
	w := httptest.NewRecorder()
	newNode(config.Config{}).restHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/rsa/keys/test/signpss", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("unprotected RSA-PSS returned HTTP %d", w.Code)
	}

	// Nodes configured with mTLS and encrypted storage but without RESTAuth must also reject signpss.
	noAuthPlayers, noAuthNodes := rsaTestNodes(t, nil)
	noAuthBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": bytes.Repeat([]byte{1}, sha256.Size)})
	noAuthServer := httptest.NewTLSServer(noAuthNodes[0].restHandler())
	t.Cleanup(noAuthServer.Close)
	noAuthReq, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, noAuthServer.URL+"/rsa/keys/test/signpss?mpc_routing_id="+mpcRoutingID("no-auth"), bytes.NewReader(noAuthBody))
	noAuthReq.Header.Set("MPC-SessionID", "no-auth")
	noAuthReq.Header.Set("MPC-RoutingID", mpcRoutingID("no-auth"))
	noAuthReq.Header.Add("MPC-Players", string(noAuthPlayers[0]))
	noAuthReq.Header.Add("MPC-Players", string(noAuthPlayers[2]))
	noAuthRes, err := noAuthServer.Client().Do(noAuthReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = noAuthRes.Body.Close()
	if noAuthRes.StatusCode != http.StatusForbidden {
		t.Fatalf("signpss without RESTAuth returned HTTP %d, want 403", noAuthRes.StatusCode)
	}

	players, nodes := rsaTestNodes(t, rsaTestRESTAuth())
	var rest [3]*httptest.Server
	for i, n := range nodes {
		rest[i] = httptest.NewTLSServer(n.restHandler())
		t.Cleanup(rest[i].Close)
	}
	const session, keyID = "pss-decrypt-key-reject", "decrypt-only-pss"
	routingID := mpcRoutingID(session)
	body, _ := json.Marshal(map[string]any{"keyID": keyID, "bits": 2048, "threshold": 1, "usage": "decrypt"})
	ch := make(chan int, 3)
	for i := range rest {
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, rest[i].URL+"/rsa/keys?mpc_routing_id="+routingID, bytes.NewReader(body))
			req.Header.Set("Authorization", "APIKEY "+rsaDecryptToken)
			req.Header.Set("MPC-SessionID", session)
			req.Header.Set("MPC-RoutingID", routingID)
			for _, p := range players {
				req.Header.Add("MPC-Players", string(p))
			}
			res, err := rest[i].Client().Do(req)
			if err != nil {
				ch <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			ch <- res.StatusCode
		}()
	}
	for range rest {
		if code := <-ch; code != http.StatusOK {
			t.Fatalf("decryption keygen returned HTTP %d", code)
		}
	}

	digest := sha256.Sum256([]byte("forbidden signpss"))
	signBody, _ := json.Marshal(map[string]any{"hash": "SHA256", "messageHash": digest[:]})
	signSession := "pss-on-decrypt-key"
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, rest[0].URL+"/rsa/keys/"+keyID+"/signpss?mpc_routing_id="+mpcRoutingID(signSession), bytes.NewReader(signBody))
	req.Header.Set("Authorization", "APIKEY "+rsaOtherToken)
	req.Header.Set("MPC-SessionID", signSession)
	req.Header.Set("MPC-RoutingID", mpcRoutingID(signSession))
	req.Header.Add("MPC-Players", string(players[0]))
	req.Header.Add("MPC-Players", string(players[2]))
	res, err := rest[0].Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("signpss on decryption key returned HTTP %d, want 403", res.StatusCode)
	}
}
