package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

type diskIdentity struct {
	Version    int    `json:"version"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type Identity struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func LoadOrCreate(path string) (*Identity, error) {
	var stored diskIdentity
	err := securefile.ReadJSON(path, &stored)
	if errors.Is(err, os.ErrNotExist) {
		publicKey, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			return nil, fmt.Errorf("generate device identity: %w", generateErr)
		}
		stored = diskIdentity{
			Version:    1,
			PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
			PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
		}
		if err := securefile.WriteJSON(path, stored); err != nil {
			return nil, err
		}
		return &Identity{private: privateKey, public: publicKey}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	if stored.Version != 1 {
		return nil, fmt.Errorf("unsupported device identity version %d", stored.Version)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(stored.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("stored Ed25519 private key is invalid")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(stored.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("stored Ed25519 public key is invalid")
	}
	derived := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(publicKey, derived) != 1 {
		return nil, errors.New("stored Ed25519 key pair does not match")
	}
	return &Identity{private: ed25519.PrivateKey(privateKey), public: ed25519.PublicKey(publicKey)}, nil
}

func (i *Identity) PublicKeyString() string {
	return base64.RawURLEncoding.EncodeToString(i.public)
}

func (i *Identity) Sign(message []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(i.private, message))
}
