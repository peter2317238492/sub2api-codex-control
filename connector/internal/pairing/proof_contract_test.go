package pairing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPairingV2ProofMatchesSharedControlAPIVector(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate pairing proof contract test")
	}
	data, err := os.ReadFile(filepath.Join(
		filepath.Dir(filename), "..", "..", "..", "packages", "control-protocol", "fixtures", "pairing-proof-v2.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var payload startPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	var expected struct {
		ProofSHA256 string `json:"proof_sha256"`
		Signature   string `json:"signature"`
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	proof := pairingStartProof(payload)
	digest := sha256.Sum256(proof)
	if hex.EncodeToString(digest[:]) != expected.ProofSHA256 {
		t.Fatalf("pairing proof SHA-256 = %x, want %s", digest, expected.ProofSHA256)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(expected.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, proof, signature) {
		t.Fatal("shared pairing proof signature did not verify")
	}
}
