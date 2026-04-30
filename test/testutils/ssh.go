package testutils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateSSHKeys creates an ed25519 key pair and writes them to files.
// Returns the public key in OpenSSH authorized_keys format.
func GenerateSSHKeys(privatePath, publicPath string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	// Write private key (PKCS8 PEM)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privBytes,
	}), 0600); err != nil {
		return "", err
	}

	// Build OpenSSH wire-format public key blob
	// format: string("ssh-ed25519") + string(pub_key_bytes)
	algo := "ssh-ed25519"
	blob := make([]byte, 4+len(algo)+4+ed25519.PublicKeySize)
	binary.BigEndian.PutUint32(blob[0:4], uint32(len(algo)))
	copy(blob[4:], algo)
	binary.BigEndian.PutUint32(blob[4+len(algo):], ed25519.PublicKeySize)
	copy(blob[4+len(algo)+4:], pub)

	// OpenSSH authorized_keys format: "ssh-ed25519 <base64(blob)> <comment>"
	pubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " bdp-test"
	if err := os.WriteFile(publicPath, []byte(pubLine+"\n"), 0644); err != nil {
		return "", err
	}

	return pubLine, nil
}
