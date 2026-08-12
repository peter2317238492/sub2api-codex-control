package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/identity"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
)

func TestHTTPTokenSourceSignsProofAndCachesToken(t *testing.T) {
	const deviceID = "11111111-1111-4111-8111-111111111111"
	const accessToken = "short-lived-token-value"
	deviceIdentity, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.Header.Get("Authorization") != "Device refresh" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		var body tokenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		publicKey, _ := base64.RawURLEncoding.DecodeString(body.PublicKey)
		signature, _ := base64.RawURLEncoding.DecodeString(body.Signature)
		proof := body.DeviceID + "\n" + body.Timestamp + "\n" + body.Nonce
		if body.DeviceID != deviceID || !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(proof), signature) {
			t.Error("device proof signature is invalid")
		}
		responseBody, _ := json.Marshal(map[string]any{
			"access_token": accessToken, "expires_at": time.Now().Add(5 * time.Minute).UTC(),
		})
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(string(responseBody))), Request: request,
		}, nil
	})}
	source := &HTTPTokenSource{
		HTTP: httpClient, URL: "https://control.test/v1/device/connect-token",
		Credentials: pairing.Credentials{DeviceID: deviceID, RefreshCredential: "refresh"}, Identity: deviceIdentity,
	}
	first, err := source.Token(t.Context())
	if err != nil || first.Value != accessToken {
		t.Fatalf("first token = %#v, %v", first, err)
	}
	if _, err := source.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("cached token made %d requests", requests.Load())
	}
	source.Invalidate()
	if _, err := source.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("invalidated token made %d requests", requests.Load())
	}
	if strings.Contains(first.Value, "refresh") {
		t.Fatal("refresh credential leaked into access token")
	}
}

func TestHTTPTokenSourceErrorsNeverReflectBodyCredentialOrTransportDetails(t *testing.T) {
	const (
		deviceID   = "11111111-1111-4111-8111-111111111111"
		credential = "refresh-credential-sentinel"
		bodySecret = "REFLECTED-TOKEN-BODY-SENTINEL"
	)
	deviceIdentity, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		transport roundTripFunc
		want      string
	}{
		{
			name: "HTTP response body",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusUnauthorized, Header: make(http.Header), Request: request,
					Body: io.NopCloser(strings.NewReader(bodySecret + " Authorization: " + credential)),
				}, nil
			},
			want: "HTTP status 401",
		},
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New(bodySecret + " Authorization: Device " + credential)
			},
			want: "request failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &HTTPTokenSource{
				HTTP: &http.Client{Transport: test.transport}, URL: "https://control.test/v1/device/connect-token",
				Credentials: pairing.Credentials{DeviceID: deviceID, RefreshCredential: credential}, Identity: deviceIdentity,
			}
			_, err := source.Token(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("token error = %v", err)
			}
			for _, secret := range []string{bodySecret, credential, "Authorization"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("token error leaked %q: %v", secret, err)
				}
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
