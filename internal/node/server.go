package node

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/C18519898242/mpc-node-api/internal/config"
	"github.com/C18519898242/mpc-node-api/internal/keystore"
)

// ServeHealth runs the health-only HTTP server.
func ServeHealth(addr string) error {
	slog.Info("health server starting")
	return httpServer(addr, healthMux()).ListenAndServe()
}

func httpServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(httpErrorLog{}, "", 0),
	}
}

// Serve runs the REST and peer listeners for a single node.
func Serve(cfg config.Config) error {
	n := newNode(cfg)
	if err := n.configureEmergencyRecovery(); err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "emergency_recovery")
		return err
	}
	if err := n.configureKeyTransfer(); err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "key_transfer")
		return err
	}
	if err := n.configureWalletBackup(); err != nil {
		return err
	}
	tlsConfig, err := n.configurePeerTLS()
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "mpc_tls")
		return err
	}
	for _, client := range n.peerClients {
		defer client.CloseIdleConnections()
	}
	keys, err := keystore.OpenNodeSQLite(cfg.DataDir, string(cfg.PartyID))
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "storage")
		return err
	}
	defer keys.Close()
	n.keys = keys
	if err := n.cleanupLegacyArtifacts(); err != nil {
		n.logger.Warn("legacy artifact cleanup failed", "node_id", string(cfg.PartyID), "result", "failed")
	}
	if err := n.configureRESTAuth(); err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "rest_auth")
		return err
	}
	masterKey, err := loadMasterKey(keys, cfg.EncryptorMasterPasswordEnv)
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "master_key")
		return err
	}
	defer clear(masterKey)
	if len(masterKey) != 0 {
		n.shareCipher = keystore.NewShareCipher(masterKey, string(cfg.PartyID))
		if err := keys.EnableShareEncryption(context.Background(), n.shareCipher); err != nil {
			n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "share_encryption")
			return err
		}
		if err := n.encryptLegacyShares(); err != nil {
			n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "legacy_share_encryption")
			return err
		}
	}
	rest, err := net.Listen("tcp", n.config.RESTAddr)
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "rest_listener")
		return err
	}
	defer rest.Close()
	mpc, err := net.Listen("tcp", n.config.MPCAddr)
	if err != nil {
		n.logger.Error("startup failed", "node_id", string(cfg.PartyID), "stage", "mpc_listener")
		return err
	}
	defer mpc.Close()

	serveErrors := make(chan error, 2)
	restServer := httpServer(n.config.RESTAddr, n.restHandler())
	restServer.WriteTimeout = keygenTimeout + restServer.ReadTimeout + 5*time.Second
	go func() { serveErrors <- restServer.Serve(rest) }()
	peerServer := httpServer(n.config.MPCAddr, n.peerHandler())
	go func() {
		if tlsConfig == nil {
			serveErrors <- peerServer.Serve(mpc)
			return
		}
		peerServer.TLSConfig = tlsConfig
		serveErrors <- peerServer.ServeTLS(mpc, "", "")
	}()
	n.logger.Info("node listening", "node_id", string(cfg.PartyID), "rest_port", rest.Addr().(*net.TCPAddr).Port,
		"mpc_port", mpc.Addr().(*net.TCPAddr).Port)
	return <-serveErrors
}

func loadMasterKey(store *keystore.SQLite, passwordEnv string) ([]byte, error) {
	var password string
	if passwordEnv != "" {
		password = os.Getenv(passwordEnv)
		if password == "" {
			return nil, errors.New("configured master password environment variable is empty")
		}
	}
	return store.LoadOrCreateMasterKey(context.Background(), password)
}
