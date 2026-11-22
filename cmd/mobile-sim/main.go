package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/C18519898242/mpc-node-api/mobile"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mobile-sim:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	cmd, err := parseCommand(args)
	if err != nil {
		return err
	}
	settings, err := loadSettings(cmd.configPath)
	if err != nil {
		return err
	}
	client, err := mobile.New(settings.configJSON, settings.dataDir, settings.password)
	if err != nil {
		return errors.New("cannot open mobile node; check config, certificates and master password")
	}
	defer client.Close()
	var result string
	switch cmd.mode {
	case "keygen":
		result, err = client.CreateKey(cmd.algorithm, cmd.threshold, cmd.keyID)
	case "sign":
		result, err = client.Sign(cmd.algorithm, cmd.keyID, []byte(cmd.message))
	case "presiggen":
		result, err = client.GeneratePresignatures(cmd.algorithm, cmd.keyID, cmd.count)
	case "signwithpresig":
		result, err = client.SignWithPresignature(cmd.algorithm, cmd.keyID, cmd.presignatureID, []byte(cmd.message))
	}
	if err != nil {
		if cmd.mode == "signwithpresig" {
			return errors.New("presign signing failed; discard this presignature ID and use a new one")
		}
		return errors.New("MPC operation failed; check server availability, credentials and key ID")
	}
	if err := client.Close(); err != nil {
		return errors.New("cannot close mobile node")
	}
	_, err = fmt.Fprintln(out, result)
	return err
}
