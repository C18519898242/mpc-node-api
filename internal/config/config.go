package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Config struct {
	PartyID                    party.ID                 `json:"partyId"`
	RESTAddr                   string                   `json:"restAddr"`
	MPCAddr                    string                   `json:"mpcAddr"`
	DataDir                    string                   `json:"dataDir"`
	Peers                      map[party.ID]string      `json:"peers"`
	MobilePeers                map[party.ID]string      `json:"mobilePeers,omitempty"`
	LegacyFROSTPlayers         []party.ID               `json:"legacyFrostPlayers,omitempty"`
	MPCTLS                     *MPCTLSConfig            `json:"mpcTLS,omitempty"`
	RESTAuth                   *RESTAuthConfig          `json:"restAuth,omitempty"`
	EncryptorMasterPasswordEnv string                   `json:"encryptorMasterPasswordEnv,omitempty"`
	KeyTransfer                *KeyTransferConfig       `json:"keyTransfer,omitempty"`
	EmergencyRecovery          *EmergencyRecoveryConfig `json:"emergencyRecovery,omitempty"`
}

type EmergencyRecoveryConfig struct {
	Enabled    bool     `json:"enabled"`
	PublicKeys [][]byte `json:"publicKeys,omitempty"`
}

type KeyTransferConfig struct {
	ExportEnabled          bool     `json:"exportEnabled,omitempty"`
	WrappingPrivateKeyFile string   `json:"wrappingPrivateKeyFile,omitempty"`
	ExportWrappingKeys     [][]byte `json:"exportWrappingKeys,omitempty"`
}

type RESTAuthConfig struct {
	APIKeys []APIKey `json:"apiKeys"`
}

type APIKey struct {
	ApplicationID string `json:"applicationID"`
	SHA256        string `json:"sha256"`
}

type MPCTLSConfig struct {
	CAFile   string `json:"caFile"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Load reads and validates a local node configuration.
func Load(path string) (Config, error) {
	return load(path, false)
}

// LoadEmbedded resolves an outbound-only node's files without listener addresses.
func LoadEmbedded(path string) (Config, error) { return load(path, true) }

func load(path string, embedded bool) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decode %s: %w", path, err)
	}
	if !validPartyID(cfg.PartyID) || cfg.DataDir == "" || len(cfg.Peers)+len(cfg.MobilePeers) == 0 {
		return cfg, fmt.Errorf("%s: expected partyId, dataDir and at least one peer", path)
	}

	addrs := []string{}
	if !embedded {
		addrs = append(addrs, cfg.RESTAddr, cfg.MPCAddr)
	}
	if err := validateMobilePeers(cfg); err != nil {
		return cfg, err
	}
	for id, addr := range cfg.Peers {
		if !validPartyID(id) || id == cfg.PartyID {
			return cfg, fmt.Errorf("%s: invalid peer ID %q", path, id)
		}
		addrs = append(addrs, addr)
	}
	if cfg.LegacyFROSTPlayers != nil {
		seenPlayers := make(map[party.ID]bool)
		for _, id := range cfg.LegacyFROSTPlayers {
			if !validPartyID(id) || seenPlayers[id] {
				return cfg, fmt.Errorf("%s: invalid legacyFrostPlayers", path)
			}
			seenPlayers[id] = true
		}
		if len(seenPlayers) < 2 || !seenPlayers[cfg.PartyID] {
			return cfg, fmt.Errorf("%s: legacyFrostPlayers must include this node and another player", path)
		}
	}
	seen := make(map[netip.AddrPort]bool, len(addrs))
	for i, raw := range addrs {
		addr, err := netip.ParseAddrPort(raw)
		if err != nil || addr.Port() == 0 || seen[addr] || ((embedded || i >= 2) && addr.Addr().IsUnspecified()) {
			return cfg, fmt.Errorf("%s: invalid or duplicate address %q", path, raw)
		}
		if ((!embedded && i == 0) || cfg.MPCTLS == nil) && !addr.Addr().IsLoopback() {
			return cfg, fmt.Errorf("%s: plaintext listeners and peers must use loopback addresses, got %q", path, raw)
		}
		seen[addr] = true
	}
	if cfg.MPCTLS != nil {
		for _, file := range []*string{&cfg.MPCTLS.CAFile, &cfg.MPCTLS.CertFile, &cfg.MPCTLS.KeyFile} {
			if *file == "" {
				return cfg, fmt.Errorf("%s: mpcTLS requires caFile, certFile and keyFile", path)
			}
			if !filepath.IsAbs(*file) {
				*file = filepath.Join(filepath.Dir(path), *file)
			}
		}
	}
	if !filepath.IsAbs(cfg.DataDir) {
		cfg.DataDir = filepath.Join(filepath.Dir(path), cfg.DataDir)
	}
	if cfg.KeyTransfer != nil && cfg.KeyTransfer.WrappingPrivateKeyFile != "" &&
		!filepath.IsAbs(cfg.KeyTransfer.WrappingPrivateKeyFile) {
		cfg.KeyTransfer.WrappingPrivateKeyFile = filepath.Join(filepath.Dir(path), cfg.KeyTransfer.WrappingPrivateKeyFile)
	}
	return cfg, os.MkdirAll(cfg.DataDir, 0700)
}

// ValidateEmbedded checks JSON supplied directly by an embedding application.
func ValidateEmbedded(cfg Config) error {
	if !validPartyID(cfg.PartyID) || cfg.DataDir == "" || len(cfg.Peers) < 1 || len(cfg.MobilePeers) > 0 || cfg.MPCTLS == nil || cfg.RESTAddr != "" || cfg.MPCAddr != "" || cfg.RESTAuth != nil {
		return fmt.Errorf("embedded node requires TLS, outbound peers, dataDir and no listeners or REST auth")
	}
	seen := map[netip.AddrPort]bool{}
	for id, raw := range cfg.Peers {
		addr, err := netip.ParseAddrPort(raw)
		if !validPartyID(id) || id == cfg.PartyID || err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || seen[addr] {
			return fmt.Errorf("invalid embedded peer")
		}
		seen[addr] = true
	}
	return nil
}

func validateMobilePeers(cfg Config) error {
	for id, app := range cfg.MobilePeers {
		if !validPartyID(id) || id == cfg.PartyID || cfg.Peers[id] != "" || cfg.MPCTLS == nil || cfg.RESTAuth == nil || app == "" {
			return fmt.Errorf("mobilePeers requires distinct peer IDs, mTLS and application authentication")
		}
		found := false
		for _, key := range cfg.RESTAuth.APIKeys {
			found = found || key.ApplicationID == app
		}
		if !found {
			return fmt.Errorf("mobile peer application is not configured")
		}
	}
	return nil
}

func validPartyID(id party.ID) bool {
	// CMP treats an ID as a big-endian number. Reject noncanonical encodings.
	return len(id) > 0 && len(id) <= 32 && id[0] != 0
}
