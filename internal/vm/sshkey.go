package vm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// EnsureKey creates (once) the profile's SSH key in dir and returns the
// signer and the authorized_keys line.
func EnsureKey(dir string) (ssh.Signer, string, error) {
	path := filepath.Join(dir, "id_ed25519")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		block, err := ssh.MarshalPrivateKey(priv, "hat profile key")
		if err != nil {
			return nil, "", err
		}
		b = pem.EncodeToMemory(block)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, "", err
		}
	} else if err != nil {
		return nil, "", err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}
