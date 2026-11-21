package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/C18519898242/mpc-node-api/internal/recovery"
)

type inputFiles []string

func (f *inputFiles) String() string     { return fmt.Sprint([]string(*f)) }
func (f *inputFiles) Set(s string) error { *f = append(*f, s); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Emergency recovery failed:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected combine, validate or recover")
	}
	mode := args[0]
	if mode != "combine" && mode != "validate" && mode != "recover" {
		return errors.New("expected combine, validate or recover")
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(out)
	var inputs inputFiles
	flags.Var(&inputs, "in", "input JSON file; repeat for each node's partial when combining")
	publicFile := flags.String("public-key", "", "trusted publickey API response JSON file")
	rsaFile := flags.String("rsa-key", "", "RSA public key PEM/DER; private key PEM for recover")
	label := flags.String("label", "", "UTF-8 recovery label; must match the generation request")
	output := flags.String("out", "", "new output JSON file; existing files are never overwritten")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(inputs) == 0 || *publicFile == "" || *rsaFile == "" || (mode != "combine" && len(inputs) != 1) || (mode != "validate" && *output == "") || (mode == "validate" && *output != "") {
		return errors.New("expected -in, -public-key, -rsa-key and -out (except validate)")
	}
	var expected struct {
		Curve     string `json:"curve"`
		PublicKey []byte `json:"publicKey"`
	}
	if err := readJSON(*publicFile, &expected); err != nil {
		return err
	}
	if len(expected.PublicKey) == 0 {
		return errors.New("trusted public key file has no publicKey")
	}
	public, private, err := readRSA(*rsaFile, mode == "recover")
	if err != nil {
		return err
	}
	if mode == "combine" {
		partials := make([]recovery.Partial, len(inputs))
		for i, path := range inputs {
			if err := readJSON(path, &partials[i]); err != nil {
				return err
			}
		}
		backup, err := recovery.Combine(partials, expected.PublicKey, public, []byte(*label))
		if err != nil {
			return err
		}
		if err := writeJSON(*output, backup); err != nil {
			return err
		}
		fmt.Fprintln(out, "Validated and combined recovery data:", *output)
		return nil
	}
	var backup recovery.Backup
	if err := readJSON(inputs[0], &backup); err != nil {
		return err
	}
	if mode == "validate" {
		if err := recovery.Validate(backup, expected.PublicKey, public, []byte(*label)); err != nil {
			return err
		}
		fmt.Fprintln(out, "Recovery data is valid; no private RSA key or MPC node was used.")
		return nil
	}
	key, err := recovery.Recover(backup, expected.PublicKey, private, []byte(*label))
	if err != nil {
		return err
	}
	defer clear(key.PrivateKey)
	if err := writeJSON(*output, key); err != nil {
		return err
	}
	fmt.Fprintln(out, "Recovered private key and chain code into:", *output)
	return nil
}
