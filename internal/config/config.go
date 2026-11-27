package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Config struct {
	PartyID                    party.ID                 `json:"partyId"`
	RESTAddr                   string                   `json:"restAddr"`
	AllowNonLoopbackREST       bool                     `json:"allowNonLoopbackREST,omitempty"`
	MPCAddr                    string                   `json:"mpcAddr"`
	DataDir                    string                   `json:"dataDir"`
	Peers                      map[party.ID]string      `json:"peers"`
	MobilePeers                map[party.ID]string      `json:"mobilePeers,omitempty"`
	LegacyFROSTPlayers         []party.ID               `json:"legacyFrostPlayers,omitempty"`
	MPCTLS                     *MPCTLSConfig            `json:"mpcTLS,omitempty"`
	RESTTLS                    *RESTTLSConfig           `json:"restTLS,omitempty"`
	RESTAuth                   *RESTAuthConfig          `json:"restAuth,omitempty"`
	EncryptorMasterPasswordEnv string                   `json:"encryptorMasterPasswordEnv,omitempty"`
	KeyTransfer                *KeyTransferConfig       `json:"keyTransfer,omitempty"`
	EmergencyRecovery          *EmergencyRecoveryConfig `json:"emergencyRecovery,omitempty"`
	WalletBackup               *WalletBackupConfig      `json:"walletBackup,omitempty"`
}

type WalletBackupConfig struct {
	PublicKey              []byte `json:"publicKey,omitempty"` // Base64-encoded PKIX DER RSA public key.
	AllowRequestPublicKeys bool   `json:"allowRequestPublicKeys,omitempty"`
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
	RSADecryption bool   `json:"rsaDecryption,omitempty"`
}

type MPCTLSConfig struct {
	CAFile   string `json:"caFile"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type RESTTLSConfig struct {
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
	seen := make(map[string]bool, len(addrs))
	for i, raw := range addrs {
		isPeer := embedded || i >= 2
		allowNonLoopback := cfg.MPCTLS != nil
		if !embedded && i == 0 {
			allowNonLoopback = cfg.AllowNonLoopbackREST && cfg.RESTAuth != nil && len(cfg.RESTAuth.APIKeys) != 0
		}
		addr, ok := nodeAddress(raw, isPeer, allowNonLoopback)
		if !ok || seen[addr] {
			return cfg, fmt.Errorf("%s: invalid or duplicate address %q", path, raw)
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
	if cfg.RESTTLS != nil {
		for _, file := range []*string{&cfg.RESTTLS.CertFile, &cfg.RESTTLS.KeyFile} {
			if *file == "" {
				return cfg, fmt.Errorf("%s: restTLS requires certFile and keyFile", path)
			}
			if !filepath.IsAbs(*file) {
				*file = filepath.Join(filepath.Dir(path), *file)
			}
		}
	} else if cfg.RESTAuth != nil {
		for _, key := range cfg.RESTAuth.APIKeys {
			if key.RSADecryption {
				return cfg, fmt.Errorf("%s: rsaDecryption API keys require restTLS", path)
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
	if !validPartyID(cfg.PartyID) || cfg.DataDir == "" || len(cfg.Peers) < 1 || len(cfg.MobilePeers) > 0 || cfg.MPCTLS == nil || cfg.RESTAddr != "" || cfg.MPCAddr != "" || cfg.RESTAuth != nil || cfg.RESTTLS != nil || cfg.AllowNonLoopbackREST {
		return fmt.Errorf("embedded node requires TLS, outbound peers, dataDir and no listeners or REST auth")
	}
	seen := map[string]bool{}
	for id, raw := range cfg.Peers {
		addr, ok := nodeAddress(raw, true, true)
		if !validPartyID(id) || id == cfg.PartyID || !ok || seen[addr] {
			return fmt.Errorf("invalid embedded peer")
		}
		seen[addr] = true
	}
	return nil
}

var peerHostname = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

func nodeAddress(raw string, peer, allowNonLoopback bool) (string, bool) {
	if addr, err := netip.ParseAddrPort(raw); err == nil {
		if addr.Port() == 0 || (peer && addr.Addr().IsUnspecified()) || (!allowNonLoopback && !addr.Addr().IsLoopback()) {
			return "", false
		}
		return addr.String(), true
	}
	// Only authenticated MPC peers may use DNS names. Listeners still require IPs.
	if !peer || !allowNonLoopback {
		return "", false
	}
	host, portText, found := strings.Cut(raw, ":")
	port, err := strconv.ParseUint(portText, 10, 16)
	if !found || err != nil || port == 0 || len(host) > 253 || !peerHostname.MatchString(host) {
		return "", false
	}
	return strings.ToLower(host) + ":" + strconv.FormatUint(port, 10), true
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
