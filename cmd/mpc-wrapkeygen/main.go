package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", "certs/key-transfer-dev-4096", "directory for the local RSA wrapping key pair")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, "RSA wrapping key generation failed:", err)
		os.Exit(1)
	}
	fmt.Println("Created rsa-private.pem, rsa-public.pem and rsa-public.der in", *out)
}

func generate(dir string) error {
	names := []string{"rsa-private.pem", "rsa-public.pem", "rsa-public.der"}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("output file already exists or cannot be inspected: %s", name)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privatePEM)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for i, data := range [][]byte{privatePEM, publicPEM, publicDER} {
		file, err := os.OpenFile(filepath.Join(dir, names[i]), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return err
		}
	}
	return nil
}
