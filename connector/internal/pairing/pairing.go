package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	pairingProtocolVersion = 2
	pairingCodeAlphabet    = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	pairingProofDomain     = "sub2api-codex-control/pairing-start/v2\x00"
)

var (
	ErrPairingExpired     = errors.New("pairing expired")
	ErrPairingStateLocked = errors.New("pairing state is already in use")
)

type Credentials struct {
	Version           int    `json:"version"`
	DeviceID          string `json:"device_id"`
	RefreshCredential string `json:"refresh_credential"`
}

func LoadCredentials(path string) (Credentials, error) {
	var credentials Credentials
	if err := securefile.ReadJSON(path, &credentials); err != nil {
		return Credentials{}, err
	}
	if credentials.Version != 1 || !validCredentials(credentials) {
		return Credentials{}, errors.New("stored device credentials are invalid")
	}
	return credentials, nil
}

func SaveCredentials(path string, credentials Credentials) error {
	if !validCredentials(credentials) {
		return errors.New("refusing to persist incomplete device credentials")
	}
	credentials.Version = 1
	return securefile.WriteJSON(path, credentials)
}

type StartRequest struct {
	PublicKey        string   `json:"public_key"`
	DisplayName      string   `json:"display_name"`
	ConnectorVersion string   `json:"connector_version"`
	CodexVersion     string   `json:"codex_version"`
	WorkspaceRoots   []string `json:"workspace_roots"`
}

type startPayload struct {
	ProtocolVersion             int      `json:"protocol_version"`
	PairingID                   string   `json:"pairing_id"`
	CreatedAt                   string   `json:"created_at"`
	Audience                    string   `json:"audience"`
	PublicKey                   string   `json:"public_key"`
	DisplayName                 string   `json:"display_name"`
	ConnectorVersion            string   `json:"connector_version"`
	CodexVersion                string   `json:"codex_version"`
	WorkspaceRoots              []string `json:"workspace_roots"`
	CodeCommitment              string   `json:"code_commitment"`
	PollTokenCommitment         string   `json:"poll_token_commitment"`
	RefreshCredentialCommitment string   `json:"refresh_credential_commitment"`
	Signature                   string   `json:"signature"`
}

type startResponse struct {
	PairingID string    `json:"pairing_id"`
	ExpiresAt time.Time `json:"expires_at"`
	PollURL   string    `json:"poll_url"`
}

type pollResponse struct {
	Status    string    `json:"status"`
	PairingID string    `json:"pairing_id"`
	ExpiresAt time.Time `json:"expires_at"`
	DeviceID  string    `json:"device_id"`
}

type Client struct {
	HTTP         *http.Client
	StartURL     string
	PollInterval time.Duration
	Now          func() time.Time
	Sign         func([]byte) string
}

type CodePublisher func(code string, expiresAt time.Time) error

func (c *Client) pairPending(
	ctx context.Context,
	request StartRequest,
	pending pendingPairing,
	publishCode CodePublisher,
) (Credentials, error) {
	if err := validatePendingPairing(pending, request, c.StartURL); err != nil {
		return Credentials{}, err
	}
	audience, err := pairingAudience(c.StartURL)
	if err != nil {
		return Credentials{}, err
	}
	payload := startPayload{
		ProtocolVersion:             pairingProtocolVersion,
		PairingID:                   pending.PairingID,
		CreatedAt:                   pending.CreatedAt,
		Audience:                    audience,
		PublicKey:                   request.PublicKey,
		DisplayName:                 request.DisplayName,
		ConnectorVersion:            request.ConnectorVersion,
		CodexVersion:                request.CodexVersion,
		WorkspaceRoots:              append([]string(nil), request.WorkspaceRoots...),
		CodeCommitment:              pairingSecretCommitment(normalizePairingCode(pending.Code)),
		PollTokenCommitment:         pairingSecretCommitment(pending.PollToken),
		RefreshCredentialCommitment: pairingSecretCommitment(pending.RefreshCredential),
	}
	payload.Signature = c.Sign(pairingStartProof(payload))
	if payload.Signature == "" || len(payload.Signature) > 128 {
		return Credentials{}, errors.New("pairing proof signer returned an invalid signature")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Credentials{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.StartURL, bytes.NewReader(body))
	if err != nil {
		return Credentials{}, errors.New("pairing start request is invalid")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.HTTP.Do(httpRequest)
	if err != nil {
		return Credentials{}, sanitizedRequestError(ctx, "start device pairing")
	}
	if response.StatusCode == http.StatusGone {
		discardResponse(response)
		return Credentials{}, fmt.Errorf("%w: pairing start was rejected as stale", ErrPairingExpired)
	}
	var started startResponse
	if err := decodeResponse(response, http.StatusCreated, &started); err != nil {
		return Credentials{}, fmt.Errorf("start device pairing: %w", err)
	}
	if started.PairingID != pending.PairingID || started.PollURL == "" || len(started.PollURL) > 4096 ||
		started.ExpiresAt.IsZero() || started.ExpiresAt.After(c.Now().Add(20*time.Minute)) {
		return Credentials{}, errors.New("pairing server returned an incomplete response")
	}
	pollURL, err := c.validatePollURL(started.PollURL, pending.PairingID)
	if err != nil {
		return Credentials{}, err
	}
	if publishCode != nil {
		if err := publishCode(pending.Code, started.ExpiresAt); err != nil {
			return Credentials{}, fmt.Errorf("publish pairing code: %w", err)
		}
	}
	for {
		credentials, isPending, err := c.poll(
			ctx,
			pollURL,
			pending.PollToken,
			pending.PairingID,
			started.ExpiresAt,
			pending.RefreshCredential,
		)
		if err != nil {
			return Credentials{}, err
		}
		if !isPending {
			return credentials, nil
		}
		if !c.Now().Before(started.ExpiresAt) {
			return Credentials{}, fmt.Errorf("%w: pairing code expired before it was claimed", ErrPairingExpired)
		}
		timer := time.NewTimer(c.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Credentials{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) initialize(request StartRequest) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(request.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != request.PublicKey {
		return errors.New("pairing public key must be canonical raw base64url Ed25519 data")
	}
	if !canonicalSignedText(request.DisplayName, 255) ||
		!canonicalSignedText(request.ConnectorVersion, 64) ||
		!canonicalSignedText(request.CodexVersion, 64) ||
		len(request.WorkspaceRoots) == 0 || len(request.WorkspaceRoots) > 32 {
		return errors.New("pairing request is incomplete")
	}
	for _, root := range request.WorkspaceRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) ||
			len([]byte(root)) > 4096 || strings.IndexFunc(root, func(character rune) bool { return character < 0x20 }) >= 0 {
			return errors.New("pairing workspace roots must be canonical absolute paths")
		}
	}
	if c.Sign == nil {
		return errors.New("pairing proof signer is required")
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	_, err = pairingAudience(c.StartURL)
	return err
}

func canonicalSignedText(value string, maximumRunes int) bool {
	return value != "" && utf8.ValidString(value) && value == strings.TrimSpace(value) &&
		utf8.RuneCountInString(value) <= maximumRunes &&
		strings.IndexFunc(value, func(character rune) bool {
			return character < 0x20 || character == 0x7f
		}) < 0
}

func validCredentials(credentials Credentials) bool {
	return protocol.IsUUID(credentials.DeviceID) && credentials.RefreshCredential != "" &&
		len(credentials.RefreshCredential) <= 4096 &&
		strings.IndexFunc(credentials.RefreshCredential, func(character rune) bool { return character < 0x21 || character == 0x7f }) < 0
}

func (c *Client) poll(
	ctx context.Context,
	pollURL string,
	pollToken string,
	pairingID string,
	expiresAt time.Time,
	refreshCredential string,
) (Credentials, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return Credentials{}, false, errors.New("pairing poll request is invalid")
	}
	request.Header.Set("Authorization", "Pairing "+pollToken)
	request.Header.Set("Accept", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return Credentials{}, false, sanitizedRequestError(ctx, "poll device pairing")
	}
	if response.StatusCode == http.StatusGone {
		discardResponse(response)
		return Credentials{}, false, fmt.Errorf("%w: pairing poll was rejected as stale", ErrPairingExpired)
	}
	var result pollResponse
	if response.StatusCode == http.StatusAccepted {
		if err := decodeResponse(response, http.StatusAccepted, &result); err != nil {
			return Credentials{}, false, err
		}
		if result.Status != "pending" || result.PairingID != pairingID ||
			result.ExpiresAt.IsZero() || !result.ExpiresAt.Equal(expiresAt) ||
			result.DeviceID != "" {
			return Credentials{}, false, errors.New("pending pairing response is invalid")
		}
		return Credentials{}, true, nil
	}
	if err := decodeResponse(response, http.StatusOK, &result); err != nil {
		return Credentials{}, false, fmt.Errorf("poll device pairing: %w", err)
	}
	if result.Status != "claimed" || result.PairingID != "" || !result.ExpiresAt.IsZero() ||
		!protocol.IsUUID(result.DeviceID) {
		return Credentials{}, false, errors.New("pairing claim response is invalid")
	}
	return Credentials{Version: 1, DeviceID: result.DeviceID, RefreshCredential: refreshCredential}, false, nil
}

func discardResponse(response *http.Response) {
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
}

func (c *Client) validatePollURL(raw string, pairingID string) (string, error) {
	start, err := url.Parse(c.StartURL)
	if err != nil || !strings.HasSuffix(start.Path, "/start") || start.RawPath != "" {
		return "", errors.New("pairing start URL is invalid")
	}
	reference, err := url.Parse(raw)
	if err != nil || reference.RawQuery != "" || reference.ForceQuery ||
		reference.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("pairing poll URL is invalid")
	}
	poll := start.ResolveReference(reference)
	expectedPath := strings.TrimSuffix(start.Path, "/start") + "/" + pairingID + "/poll"
	if poll.Scheme != start.Scheme || !strings.EqualFold(poll.Host, start.Host) || poll.User != nil ||
		poll.RawQuery != "" || poll.ForceQuery || poll.Fragment != "" || poll.RawPath != "" ||
		poll.Path != expectedPath || poll.EscapedPath() != expectedPath {
		return "", errors.New("pairing poll_url must use the pairing endpoint origin")
	}
	return poll.String(), nil
}

func decodeResponse(response *http.Response, expected int, destination any) error {
	defer response.Body.Close()
	if response.StatusCode != expected {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("HTTP response JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("response contains trailing JSON")
		}
		return errors.New("HTTP response JSON is invalid")
	}
	return nil
}

func sanitizedRequestError(ctx context.Context, operation string) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s canceled: %w", operation, ctx.Err())
	}
	return errors.New(operation + " request failed")
}

type pendingPairing struct {
	Version           int    `json:"version"`
	PairingID         string `json:"pairing_id"`
	CreatedAt         string `json:"created_at"`
	Code              string `json:"code"`
	PollToken         string `json:"poll_token"`
	RefreshCredential string `json:"refresh_credential"`
	IntentDigest      string `json:"intent_digest"`
}

func newPendingPairing(now time.Time, request StartRequest, startURL string) (pendingPairing, error) {
	pairingID, err := randomUUID()
	if err != nil {
		return pendingPairing{}, err
	}
	code, err := randomPairingCode()
	if err != nil {
		return pendingPairing{}, err
	}
	pollToken, err := randomSecret(32)
	if err != nil {
		return pendingPairing{}, err
	}
	refreshSecret, err := randomSecret(48)
	if err != nil {
		return pendingPairing{}, err
	}
	pending := pendingPairing{
		Version:           pairingProtocolVersion,
		PairingID:         pairingID,
		CreatedAt:         now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Code:              code,
		PollToken:         pollToken,
		RefreshCredential: "dcr_" + refreshSecret,
	}
	digest, err := pairingIntentDigest(pending, request, startURL)
	if err != nil {
		return pendingPairing{}, err
	}
	pending.IntentDigest = digest
	return pending, nil
}

func validatePendingPairing(pending pendingPairing, request StartRequest, startURL string) error {
	if pending.Version != pairingProtocolVersion || !protocol.IsUUID(pending.PairingID) ||
		!validPairingCode(pending.Code) || pending.PollToken == "" || len(pending.PollToken) > 4096 ||
		!strings.HasPrefix(pending.RefreshCredential, "dcr_") || !validCredentials(Credentials{
		Version: 1, DeviceID: "11111111-1111-4111-8111-111111111111", RefreshCredential: pending.RefreshCredential,
	}) {
		return errors.New("stored pending pairing is invalid")
	}
	createdAt, err := time.Parse(time.RFC3339, pending.CreatedAt)
	if err != nil || createdAt.Format(time.RFC3339) != pending.CreatedAt {
		return errors.New("stored pending pairing timestamp is invalid")
	}
	digest, err := pairingIntentDigest(pending, request, startURL)
	if err != nil {
		return err
	}
	if len(pending.IntentDigest) != sha256.Size*2 || pending.IntentDigest != digest {
		return errors.New("stored pending pairing does not match the current connector configuration")
	}
	return nil
}

func pairingIntentDigest(pending pendingPairing, request StartRequest, startURL string) (string, error) {
	audience, err := pairingAudience(startURL)
	if err != nil {
		return "", err
	}
	payload := startPayload{
		ProtocolVersion:             pairingProtocolVersion,
		PairingID:                   pending.PairingID,
		CreatedAt:                   pending.CreatedAt,
		Audience:                    audience,
		PublicKey:                   request.PublicKey,
		DisplayName:                 request.DisplayName,
		ConnectorVersion:            request.ConnectorVersion,
		CodexVersion:                request.CodexVersion,
		WorkspaceRoots:              append([]string(nil), request.WorkspaceRoots...),
		CodeCommitment:              pairingSecretCommitment(normalizePairingCode(pending.Code)),
		PollTokenCommitment:         pairingSecretCommitment(pending.PollToken),
		RefreshCredentialCommitment: pairingSecretCommitment(pending.RefreshCredential),
	}
	digest := sha256.Sum256(pairingStartProof(payload))
	return hex.EncodeToString(digest[:]), nil
}

func pairingStartProof(payload startPayload) []byte {
	proof := bytes.NewBufferString(pairingProofDomain)
	for _, field := range []string{
		payload.PairingID,
		payload.CreatedAt,
		payload.Audience,
		payload.PublicKey,
		payload.CodeCommitment,
		payload.PollTokenCommitment,
		payload.RefreshCredentialCommitment,
		payload.DisplayName,
		payload.ConnectorVersion,
		payload.CodexVersion,
	} {
		digest := sha256.Sum256([]byte(field))
		proof.Write(digest[:])
	}
	_ = binary.Write(proof, binary.BigEndian, uint32(len(payload.WorkspaceRoots)))
	for _, root := range payload.WorkspaceRoots {
		digest := sha256.Sum256([]byte(root))
		proof.Write(digest[:])
	}
	return proof.Bytes()
}

func pairingSecretCommitment(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func pairingAudience(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("pairing start URL is invalid")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate pairing identity")
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func randomSecret(byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate pairing secret")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomPairingCode() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate pairing code")
	}
	for index := range raw {
		raw[index] = pairingCodeAlphabet[int(raw[index])&(len(pairingCodeAlphabet)-1)]
	}
	return string(raw[:4]) + "-" + string(raw[4:8]) + "-" + string(raw[8:12]) + "-" + string(raw[12:]), nil
}

func normalizePairingCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

func validPairingCode(code string) bool {
	if len(code) != 19 || code[4] != '-' || code[9] != '-' || code[14] != '-' {
		return false
	}
	for index := 0; index < len(code); index++ {
		if index == 4 || index == 9 || index == 14 {
			continue
		}
		if code[index] >= utf8.RuneSelf || !strings.ContainsRune(pairingCodeAlphabet, rune(code[index])) {
			return false
		}
	}
	return true
}

func LoadOrPair(
	ctx context.Context,
	path string,
	client *Client,
	request StartRequest,
	publishCode CodePublisher,
) (credentials Credentials, resultErr error) {
	release, err := acquirePairingStateLock(filepath.Dir(path))
	if err != nil {
		return Credentials{}, err
	}
	defer func() {
		if err := release(); err != nil {
			credentials = Credentials{}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	return loadOrPairUnlocked(ctx, path, client, request, publishCode)
}

func loadOrPairUnlocked(ctx context.Context, path string, client *Client, request StartRequest, publishCode CodePublisher) (Credentials, error) {
	credentials, err := LoadCredentials(path)
	if err == nil {
		if removeErr := removePendingPairing(filepath.Join(filepath.Dir(path), "pending-pairing.json")); removeErr != nil {
			return Credentials{}, removeErr
		}
		return credentials, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Credentials{}, err
	}
	if client == nil {
		return Credentials{}, errors.New("pairing client is required")
	}
	if err := client.initialize(request); err != nil {
		return Credentials{}, err
	}
	pendingPath := filepath.Join(filepath.Dir(path), "pending-pairing.json")
	var pending pendingPairing
	err = securefile.ReadJSON(pendingPath, &pending)
	if errors.Is(err, os.ErrNotExist) {
		pending, err = newPendingPairing(client.Now(), request, client.StartURL)
		if err != nil {
			return Credentials{}, err
		}
		if err := securefile.WriteJSON(pendingPath, pending); err != nil {
			return Credentials{}, err
		}
	} else if err != nil {
		return Credentials{}, fmt.Errorf("load pending pairing: %w", err)
	}
	if err := validatePendingPairing(pending, request, client.StartURL); err != nil {
		return Credentials{}, err
	}
	credentials, err = client.pairPending(ctx, request, pending, publishCode)
	if err != nil {
		if errors.Is(err, ErrPairingExpired) {
			if removeErr := removePendingPairing(pendingPath); removeErr != nil {
				return Credentials{}, errors.Join(err, removeErr)
			}
		}
		return Credentials{}, err
	}
	if err := SaveCredentials(path, credentials); err != nil {
		return Credentials{}, err
	}
	if err := removePendingPairing(pendingPath); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func removePendingPairing(path string) error {
	if err := removeStateFile(path); err != nil {
		return fmt.Errorf("remove pending pairing: %w", err)
	}
	return nil
}

type pairingCodeFile struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// LoadOrPairWithCodeFile publishes the one-time code through a private state
// file and removes it whenever the pairing attempt ends.
func LoadOrPairWithCodeFile(
	ctx context.Context,
	credentialsPath string,
	codePath string,
	client *Client,
	request StartRequest,
	codeAvailable func(path string),
) (credentials Credentials, resultErr error) {
	return LoadOrPairWithCodeFilePrepared(
		ctx,
		credentialsPath,
		codePath,
		client,
		func() (StartRequest, error) { return request, nil },
		codeAvailable,
	)
}

// LoadOrPairWithCodeFilePrepared serializes identity preparation with all
// pairing state reads and writes.
func LoadOrPairWithCodeFilePrepared(
	ctx context.Context,
	credentialsPath string,
	codePath string,
	client *Client,
	prepareRequest func() (StartRequest, error),
	codeAvailable func(path string),
) (credentials Credentials, resultErr error) {
	release, err := acquirePairingStateLock(filepath.Dir(credentialsPath))
	if err != nil {
		return Credentials{}, err
	}
	defer func() {
		if err := release(); err != nil {
			credentials = Credentials{}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if prepareRequest == nil {
		return Credentials{}, errors.New("pairing request preparation is required")
	}
	request, err := prepareRequest()
	if err != nil {
		return Credentials{}, err
	}
	return loadOrPairWithCodeFileUnlocked(ctx, credentialsPath, codePath, client, request, codeAvailable)
}

func loadOrPairWithCodeFileUnlocked(
	ctx context.Context,
	credentialsPath string,
	codePath string,
	client *Client,
	request StartRequest,
	codeAvailable func(path string),
) (credentials Credentials, resultErr error) {
	if err := removePairingCodeFile(codePath); err != nil {
		return Credentials{}, fmt.Errorf("remove stale pairing code file: %w", err)
	}
	defer func() {
		if err := removePairingCodeFile(codePath); err != nil {
			credentials = Credentials{}
			resultErr = errors.Join(resultErr, fmt.Errorf("remove pairing code file: %w", err))
		}
	}()

	return loadOrPairUnlocked(ctx, credentialsPath, client, request, func(code string, expiresAt time.Time) error {
		if err := securefile.WriteJSON(codePath, pairingCodeFile{Code: code, ExpiresAt: expiresAt}); err != nil {
			return err
		}
		if codeAvailable != nil {
			codeAvailable(codePath)
		}
		return nil
	})
}

func removePairingCodeFile(path string) error {
	return removeStateFile(path)
}

func removeStateFile(path string) error {
	removed := false
	for _, candidate := range []string{path, path + ".tmp"} {
		err := os.Remove(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
