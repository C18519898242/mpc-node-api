package node

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// This decoder is deliberately independent of the export implementation.
type mobileBackupHeaderFixture struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"salt"`
}

type mobileBackupFixture struct {
	mobileBackupHeaderFixture
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func decryptMobileBackupFixture(data, password string) (localKeySharePayload, error) {
	var envelope mobileBackupFixture
	var payload localKeySharePayload
	if json.Unmarshal([]byte(data), &envelope) != nil || envelope.Version != 1 || envelope.Kind != "mpc-node-api/mobile-key-share-backup" || envelope.KDF != "PBKDF2-HMAC-SHA256" || envelope.Iterations != 600000 || envelope.Cipher != "AES-256-GCM" || len(envelope.Salt) != 16 || len(envelope.Nonce) != 12 {
		return payload, errors.New("invalid backup format")
	}
	key, err := pbkdf2.Key(sha256.New, password, envelope.Salt, envelope.Iterations, 32)
	if err != nil {
		return payload, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return payload, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return payload, err
	}
	aad, _ := json.Marshal(envelope.mobileBackupHeaderFixture)
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return payload, err
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&payload)
	return payload, err
}

func testMobilePasswordShareBackup(t *testing.T, client *Embedded, cfg config.Config, app string, credentials map[party.ID]string, algorithm, keyID string) {
	t.Helper()
	exporter, ok := any(client).(interface {
		ExportKeyShare(string, string, string) (string, error)
	})
	if !ok {
		t.Fatal("mobile password-encrypted share export is not implemented")
	}
	const password = "independent offline backup fixture password"
	var logs bytes.Buffer
	logger := client.node.logger
	client.node.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	defer func() { client.node.logger = logger }()
	// Export must work without contacting either backend.
	transports := make(map[party.ID]http.RoundTripper)
	for id, peer := range client.node.peerClients {
		transports[id], peer.Transport = peer.Transport, noBackupPeerTransport{}
	}
	defer func() {
		for id, transport := range transports {
			client.node.peerClients[id].Transport = transport
		}
	}()
	for _, weak := range []string{"", "short", "                "} {
		if _, err := exporter.ExportKeyShare(algorithm, keyID, weak); err == nil {
			t.Fatal("accepted weak backup password")
		}
	}
	for _, bad := range []struct{ algorithm, key string }{{"rsa", keyID}, {algorithm, "missing-key"}} {
		if _, err := exporter.ExportKeyShare(bad.algorithm, bad.key, password); err == nil {
			t.Fatal("exported an invalid or missing key")
		}
	}
	client.application = "foreign-app"
	_, foreignErr := exporter.ExportKeyShare(algorithm, keyID, password)
	client.application = app
	if foreignErr == nil {
		t.Fatal("another application exported a mobile share")
	}
	encoded, err := exporter.ExportKeyShare(algorithm, keyID, password)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decryptMobileBackupFixture(encoded, password)
	if err != nil {
		t.Fatal("cannot decrypt portable backup", err)
	}
	defer clear(payload.Backup.Share)
	expected, err := client.store.ExportKeyShare(client.ctx, app, algorithm, keyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expected.Share)
	if payload.PartyID != string(cfg.PartyID) || payload.ApplicationID != app || payload.Kind != localKeyShareKind || payload.Version != 1 || !reflect.DeepEqual(payload.Backup, expected) {
		t.Fatal("backup changed the original share or identity")
	}
	if bytes.Contains([]byte(encoded), expected.Share) || bytes.Contains([]byte(encoded), []byte(password)) || bytes.Contains(logs.Bytes(), []byte(password)) || bytes.Contains(logs.Bytes(), expected.Share) || bytes.Contains(logs.Bytes(), []byte(base64.StdEncoding.EncodeToString(expected.Share))) {
		t.Fatal("export exposed sensitive material")
	}
	if opened, err := decryptMobileBackupFixture(encoded, "incorrect backup password"); err == nil || len(opened.Backup.Share) != 0 {
		t.Fatal("wrong password decrypted the share")
	}
	var first mobileBackupFixture
	if err := json.Unmarshal([]byte(encoded), &first); err != nil {
		t.Fatal(err)
	}
	again, err := exporter.ExportKeyShare(algorithm, keyID, password)
	if err != nil {
		t.Fatal(err)
	}
	var second mobileBackupFixture
	if err := json.Unmarshal([]byte(again), &second); err != nil || bytes.Equal(first.Salt, second.Salt) || bytes.Equal(first.Nonce, second.Nonce) || bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("repeated backup reused encryption randomness")
	}
	for _, mutate := range []func(*mobileBackupFixture){
		func(b *mobileBackupFixture) { b.Ciphertext = bytes.Clone(b.Ciphertext); b.Ciphertext[0] ^= 1 },
		func(b *mobileBackupFixture) { b.Nonce = bytes.Clone(b.Nonce); b.Nonce[0] ^= 1 },
		func(b *mobileBackupFixture) { b.Salt = bytes.Clone(b.Salt); b.Salt[0] ^= 1 },
		func(b *mobileBackupFixture) { b.Version++ },
	} {
		changed := first
		mutate(&changed)
		data, _ := json.Marshal(changed)
		if opened, err := decryptMobileBackupFixture(string(data), password); err == nil || len(opened.Backup.Share) != 0 {
			t.Fatal("accepted tampered backup")
		}
	}
	// Restore with a different MK and master password, then sign using a child key.
	restoredConfig := cfg
	restoredConfig.DataDir = t.TempDir()
	store, err := keystore.OpenNodeSQLite(restoredConfig.DataDir, string(cfg.PartyID))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const newPassword = "new phone independent master password"
	mk, err := store.LoadOrCreateMasterKey(t.Context(), newPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mk)
	if bytes.Equal(mk, client.masterKey) {
		t.Fatal("restore reused original MK")
	}
	if err := store.EnableShareEncryption(t.Context(), keystore.NewShareCipher(mk, string(cfg.PartyID))); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreKeyShare(t.Context(), app, payload.Backup); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := NewEmbedded(restoredConfig, app, newPassword, credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	message, path := []byte("restored mobile backup signing"), []uint32{0, 1}
	signed, err := restored.SignWithPath(algorithm, keyID, message, path)
	if err != nil {
		t.Fatal("restored share could not sign", err)
	}
	var signature struct{ PublicKey, Signature []byte }
	if json.Unmarshal([]byte(signed), &signature) != nil {
		t.Fatal("invalid restored signature")
	}
	ctx := context.WithValue(t.Context(), applicationContextKey{}, app)
	var public []byte
	if algorithm == "frost" {
		public, err = client.node.loadFROSTPublicKey(ctx, keyID, path)
	} else {
		public, err = client.node.loadECDSAPublicKey(ctx, keyID, path)
	}
	if err != nil || !bytes.Equal(public, signature.PublicKey) {
		t.Fatal("backup changed the derived public key", err)
	}
	verifyMobileSignature(t, algorithm, public, message, signature.Signature)
}

func TestMobileBackupRejectsPendingRefresh(t *testing.T) {
	store, err := keystore.OpenNodeSQLite(t.TempDir(), "1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	key := keystore.Key{Algorithm: "frost", KeyID: "key", SessionID: "keygen", Threshold: 1}
	if _, err := store.Reserve(ctx, "app", key); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "app", key, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	refresh := keystore.Reshare{Algorithm: "frost", KeyID: "key", SessionID: "refresh"}
	if _, _, err := store.ReserveReshare(ctx, "app", refresh); err != nil {
		t.Fatal(err)
	}
	if err := store.StageReshare(ctx, "app", refresh, [32]byte{1}, []byte("candidate")); err != nil {
		t.Fatal(err)
	}
	client := &Embedded{node: newNode(config.Config{PartyID: "1"}), store: store, application: "app", ctx: ctx}
	if _, err := client.ExportKeyShare("frost", "key", "independent backup password"); err == nil || !strings.Contains(err.Error(), "pending refresh") {
		t.Fatal("exported a key during pending refresh", err)
	}
}
