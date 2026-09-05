package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/identity"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

type DeviceToken struct {
	Value     string
	ExpiresAt time.Time
}

type TokenSource interface {
	Token(context.Context) (DeviceToken, error)
	Invalidate()
}

type HTTPTokenSource struct {
	HTTP        *http.Client
	URL         string
	Credentials pairing.Credentials
	Identity    *identity.Identity
	Now         func() time.Time

	mu     sync.Mutex
	cached DeviceToken
}

type tokenRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *HTTPTokenSource) Token(ctx context.Context) (DeviceToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Now == nil {
		s.Now = time.Now
	}
	now := s.Now().UTC()
	if s.cached.Value != "" && now.Add(30*time.Second).Before(s.cached.ExpiresAt) {
		return s.cached, nil
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if s.Identity == nil || !protocol.IsUUID(s.Credentials.DeviceID) || s.Credentials.RefreshCredential == "" ||
		len(s.Credentials.RefreshCredential) > 4096 || strings.IndexFunc(s.Credentials.RefreshCredential, func(character rune) bool { return character < 0x21 || character == 0x7f }) >= 0 {
		return DeviceToken{}, errors.New("device token source is not configured")
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return DeviceToken{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := now.Format(time.RFC3339Nano)
	proof := s.Credentials.DeviceID + "\n" + timestamp + "\n" + nonce
	payload := tokenRequest{
		DeviceID:  s.Credentials.DeviceID,
		PublicKey: s.Identity.PublicKeyString(),
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: s.Identity.Sign([]byte(proof)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return DeviceToken{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return DeviceToken{}, errors.New("device token request is invalid")
	}
	request.Header.Set("Authorization", "Device "+s.Credentials.RefreshCredential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := productionCanaryHTTPClient(s.HTTP).Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return DeviceToken{}, fmt.Errorf("device token exchange canceled: %w", ctx.Err())
		}
		return DeviceToken{}, errors.New("device token exchange request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if rejection := productionCanaryRejection(response, s.URL); rejection != nil {
			return DeviceToken{}, rejection
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return DeviceToken{}, fmt.Errorf("device token exchange returned HTTP status %d", response.StatusCode)
	}
	var result tokenResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return DeviceToken{}, errors.New("device token response is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return DeviceToken{}, errors.New("device token response contains trailing JSON")
		}
		return DeviceToken{}, errors.New("device token response is invalid")
	}
	if len(result.AccessToken) < 16 || len(result.AccessToken) > 16<<10 ||
		strings.IndexFunc(result.AccessToken, func(character rune) bool { return character < 0x21 || character == 0x7f }) >= 0 ||
		!result.ExpiresAt.After(now.Add(30*time.Second)) || result.ExpiresAt.After(now.Add(20*time.Minute)) {
		return DeviceToken{}, errors.New("device token response is invalid or outside the allowed lifetime")
	}
	s.cached = DeviceToken{Value: result.AccessToken, ExpiresAt: result.ExpiresAt}
	return s.cached, nil
}

func (s *HTTPTokenSource) Invalidate() {
	s.mu.Lock()
	s.cached = DeviceToken{}
	s.mu.Unlock()
}
