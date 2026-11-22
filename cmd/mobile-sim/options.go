package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/C18519898242/mpc-node-api/internal/config"
)

type command struct {
	mode, configPath, algorithm, keyID, message string
	threshold                                   int
	count                                       int
	presignatureID                              string
}

func parseCommand(args []string) (command, error) {
	var cmd command
	if len(args) == 0 || (args[0] != "keygen" && args[0] != "sign" && args[0] != "presiggen" && args[0] != "signwithpresig") {
		return cmd, errors.New("expected keygen, sign, presiggen or signwithpresig")
	}
	cmd.mode = args[0]
	flags := flag.NewFlagSet(cmd.mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cmd.configPath, "config", "configs/mobile/mobile.json", "embedded node JSON config")
	flags.StringVar(&cmd.algorithm, "algorithm", "ecdsa", "ecdsa or frost")
	flags.StringVar(&cmd.keyID, "key-id", "", "key ID; generated if omitted for keygen")
	switch cmd.mode {
	case "keygen":
		flags.IntVar(&cmd.threshold, "threshold", 2, "protocol threshold; positive and less than party count")
	case "presiggen":
		flags.IntVar(&cmd.count, "count", 1, "presignature batch size (1 to 8)")
	case "sign", "signwithpresig":
		flags.StringVar(&cmd.message, "message", "", "UTF-8 message to sign")
		if cmd.mode == "signwithpresig" {
			flags.StringVar(&cmd.presignatureID, "presignature-id", "", "explicit presignature ID from presiggen")
		}
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return cmd, errors.New("invalid command flags; use -config, -algorithm, -key-id with -threshold (keygen), -count (presiggen), or -message and -presignature-id (signwithpresig)")
	}
	if cmd.configPath == "" || (cmd.algorithm != "ecdsa" && cmd.algorithm != "frost") || (cmd.mode != "keygen" && strings.TrimSpace(cmd.keyID) == "") || (cmd.mode == "keygen" && cmd.threshold < 1) || (cmd.mode == "presiggen" && (cmd.count < 1 || cmd.count > 8)) {
		return cmd, errors.New("expected config, ecdsa or frost, key-id, positive threshold for keygen and count from 1 to 8 for presiggen")
	}
	if cmd.mode == "signwithpresig" {
		id, err := base64.RawURLEncoding.Strict().DecodeString(cmd.presignatureID)
		if err != nil || len(id) != 32 {
			return cmd, errors.New("expected an explicit valid presignature-id")
		}
	}
	return cmd, nil
}

type settings struct {
	configJSON, dataDir, password string
}

func loadSettings(path string) (settings, error) {
	var result settings
	path, err := filepath.Abs(path)
	if err != nil {
		return result, errors.New("cannot resolve config path")
	}
	cfg, err := config.LoadEmbedded(path)
	if err != nil {
		return result, errors.New("cannot load embedded node config")
	}
	if err := config.ValidateEmbedded(cfg); err != nil {
		return result, errors.New("invalid embedded node config")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return result, errors.New("cannot read embedded node config")
	}
	var extra struct {
		ApplicationID    string            `json:"applicationID"`
		ServerAPIKeyEnvs map[string]string `json:"serverAPIKeyEnvs"`
	}
	if json.Unmarshal(data, &extra) != nil || strings.TrimSpace(extra.ApplicationID) == "" || len(extra.ServerAPIKeyEnvs) != len(cfg.Peers) {
		return result, errors.New("expected applicationID and serverAPIKeyEnvs for each outbound peer")
	}
	apiKeys := make(map[string]string, len(cfg.Peers))
	for id := range cfg.Peers {
		envName := extra.ServerAPIKeyEnvs[string(id)]
		credential := os.Getenv(envName)
		if envName == "" || strings.TrimSpace(credential) == "" {
			return result, errors.New("missing server API key environment variable")
		}
		apiKeys[string(id)] = credential
	}
	result.password = os.Getenv(cfg.EncryptorMasterPasswordEnv)
	if cfg.EncryptorMasterPasswordEnv == "" || strings.TrimSpace(result.password) == "" {
		return settings{}, errors.New("missing mobile master password environment variable")
	}
	resolved, err := json.Marshal(struct {
		config.Config
		ApplicationID string            `json:"applicationID"`
		ServerAPIKeys map[string]string `json:"serverAPIKeys"`
	}{cfg, extra.ApplicationID, apiKeys})
	if err != nil {
		return settings{}, errors.New("cannot prepare embedded node config")
	}
	result.configJSON, result.dataDir = string(resolved), cfg.DataDir
	return result, nil
}
