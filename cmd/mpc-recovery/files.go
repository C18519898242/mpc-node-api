package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"

	"github.com/C18519898242/mpc-node-api/internal/recovery"
)

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("could not read recovery input within size limit")
	}
	return b, nil
}

func readJSON(path string, target any) error {
	b, err := readFile(path, 32<<20)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return errors.New("invalid recovery JSON input")
	}
	return nil
}

func readRSA(path string, private bool) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	b, err := readFile(path, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	defer clear(b)
	der := b
	if block, _ := pem.Decode(b); block != nil {
		der = block.Bytes
		defer clear(der)
	}
	if !private {
		key, err := recovery.ParsePublicKey(der)
		return key, nil, err
	}
	value, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if k, e := x509.ParsePKCS1PrivateKey(der); e == nil {
			value, err = k, nil
		}
	}
	key, ok := value.(*rsa.PrivateKey)
	if err != nil || !ok || key.Validate() != nil {
		return nil, nil, errors.New("expected a valid PEM RSA private key")
	}
	return &key.PublicKey, key, nil
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	defer clear(b)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	err = errors.Join(writeErr, f.Close())
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}
