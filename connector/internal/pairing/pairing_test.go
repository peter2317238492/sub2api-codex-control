package pairing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testDeviceID = "11111111-1111-4111-8111-111111111111"

func TestPairingRecoversLostStartAndCompletionResponsesAcrossRestarts(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	codePath := filepath.Join(stateDir, "pairing-code.json")
	pendingPath := filepath.Join(stateDir, "pending-pairing.json")
	request, signer, publicKey := validStartRequest(t)
	expiresAt := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)

	var firstPayload startPayload
	firstClient := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.URL.Path != "/v1/device-pairings/start" {
			t.Fatalf("unexpected first request path %q", httpRequest.URL.Path)
		}
		firstPayload = decodeStartPayload(t, httpRequest)
		assertStartProof(t, firstPayload, publicKey)
		pending := readPendingPairing(t, pendingPath)
		body, err := json.Marshal(firstPayload)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{pending.Code, pending.PollToken, pending.RefreshCredential} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("pairing request exposed local secret %q", secret)
			}
		}
		return nil, errors.New("server committed start but response was lost")
	})
	_, err := LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, firstClient, request, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "start device pairing request failed") {
		t.Fatalf("first pairing error = %v", err)
	}
	originalPending := readPendingPairing(t, pendingPath)
	assertPrivateFile(t, pendingPath)
	assertPairingCodeRemoved(t, codePath)

	secondClient := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.URL.Path == "/v1/device-pairings/start" {
			payload := decodeStartPayload(t, httpRequest)
			assertSameStartIntent(t, firstPayload, payload)
			return pairingStartedResponse(httpRequest, payload.PairingID, expiresAt), nil
		}
		if httpRequest.Header.Get("Authorization") != "Pairing "+originalPending.PollToken {
			t.Fatalf("poll authorization did not use persisted token")
		}
		return nil, errors.New("server completed pairing but response was lost")
	})
	codePublished := false
	_, err = LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, secondClient, request,
		func(path string) {
			codePublished = true
			assertPrivateFile(t, path)
			var code pairingCodeFile
			if readErr := json.Unmarshal(mustRead(t, path), &code); readErr != nil {
				t.Fatal(readErr)
			}
			if code.Code != originalPending.Code || !code.ExpiresAt.Equal(expiresAt) {
				t.Fatalf("published code = %#v", code)
			}
		},
	)
	if err == nil || !strings.Contains(err.Error(), "poll device pairing request failed") {
		t.Fatalf("second pairing error = %v", err)
	}
	if !codePublished {
		t.Fatal("pairing code was not republished after restart")
	}
	assertPairingCodeRemoved(t, codePath)
	if got := readPendingPairing(t, pendingPath); got != originalPending {
		t.Fatalf("pending state changed across response loss: %#v != %#v", got, originalPending)
	}

	thirdClient := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.URL.Path == "/v1/device-pairings/start" {
			payload := decodeStartPayload(t, httpRequest)
			assertSameStartIntent(t, firstPayload, payload)
			return pairingStartedResponse(httpRequest, payload.PairingID, expiresAt), nil
		}
		body, _ := json.Marshal(map[string]any{"status": "claimed", "device_id": testDeviceID})
		return testResponse(httpRequest, http.StatusOK, body), nil
	})
	credentials, err := LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, thirdClient, request, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.DeviceID != testDeviceID || credentials.RefreshCredential != originalPending.RefreshCredential {
		t.Fatalf("recovered credentials = %#v", credentials)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending pairing remains after credential commit: %v", err)
	}
	assertPairingCodeRemoved(t, codePath)
	credentialData := string(mustRead(t, credentialsPath))
	if !strings.Contains(credentialData, originalPending.RefreshCredential) ||
		strings.Contains(credentialData, originalPending.Code) ||
		strings.Contains(credentialData, originalPending.PollToken) {
		t.Fatal("credential file did not contain exactly the durable device credential")
	}
}

func TestExpiredPairingDeletesPendingSecrets(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	codePath := filepath.Join(stateDir, "pairing-code.json")
	request, signer, _ := validStartRequest(t)
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	client := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.URL.Path == "/v1/device-pairings/start" {
			payload := decodeStartPayload(t, httpRequest)
			return pairingStartedResponse(httpRequest, payload.PairingID, expiresAt), nil
		}
		return testResponse(httpRequest, http.StatusGone, []byte(`{"detail":"pairing_expired"}`)), nil
	})
	_, err := LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, client, request, nil,
	)
	if !errors.Is(err, ErrPairingExpired) {
		t.Fatalf("pairing error = %v, want ErrPairingExpired", err)
	}
	for _, path := range []string{filepath.Join(stateDir, "pending-pairing.json"), codePath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("terminal pairing state %q remains: %v", path, statErr)
		}
	}
}

func TestTransientPollFailureRetainsPendingButRemovesPublishedCode(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	codePath := filepath.Join(stateDir, "pairing-code.json")
	request, signer, _ := validStartRequest(t)
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	client := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.URL.Path == "/v1/device-pairings/start" {
			payload := decodeStartPayload(t, httpRequest)
			return pairingStartedResponse(httpRequest, payload.PairingID, expiresAt), nil
		}
		return nil, errors.New("network unavailable Authorization: Pairing secret")
	})
	_, err := LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, client, request, nil,
	)
	if err == nil || err.Error() != "poll device pairing request failed" {
		t.Fatalf("pairing error = %v", err)
	}
	assertPrivateFile(t, filepath.Join(stateDir, "pending-pairing.json"))
	assertPairingCodeRemoved(t, codePath)
}

func TestPendingPairingRejectsConfigurationDriftBeforeNetwork(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	request, signer, _ := validStartRequest(t)
	var requests atomic.Int32
	client := signedClient(signer, func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("offline")
	})
	_, _ = LoadOrPair(t.Context(), credentialsPath, client, request, nil)
	if requests.Load() != 1 {
		t.Fatalf("initial network requests = %d", requests.Load())
	}
	request.DisplayName = "changed device"
	_, err := LoadOrPair(t.Context(), credentialsPath, client, request, nil)
	if err == nil || !strings.Contains(err.Error(), "does not match the current connector configuration") {
		t.Fatalf("configuration drift error = %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("configuration drift reached network, requests = %d", requests.Load())
	}
}

func TestPairingErrorsNeverReflectResponseBodiesOrSecrets(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "device-credentials.json")
	request, signer, _ := validStartRequest(t)
	const bodySecret = "REFLECTED-PAIRING-BODY-SENTINEL"
	client := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		return testResponse(httpRequest, http.StatusBadRequest, []byte(bodySecret)), nil
	})
	_, err := LoadOrPair(t.Context(), credentialsPath, client, request, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP status 400") || strings.Contains(err.Error(), bodySecret) {
		t.Fatalf("pairing error leaked response: %v", err)
	}
}

func TestPairingCodeUsesCanonicalSixteenCharacterAlphabet(t *testing.T) {
	for range 128 {
		code, err := randomPairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if !validPairingCode(code) {
			t.Fatalf("generated pairing code is invalid: %q", code)
		}
		if normalized := normalizePairingCode(code); len(normalized) != 16 {
			t.Fatalf("normalized code %q has length %d", normalized, len(normalized))
		}
	}

	for _, code := range []string{
		"2345-6789-ABCD-EFGH",
		"2345-6789-abcd-EFGH",
		"2345-6789-ABCD-EFGI",
		"2345-6789-ABCD-EFGO",
		"2345-6789-ABCD-EFG0",
		"2345-6789-ABCD-EFG1",
		"23456789-ABCD-EFGH",
		"2345-6789-ABCD-EFGH-",
		"2345-6789-ABCD-EFG\u00c9",
	} {
		if code == "2345-6789-ABCD-EFGH" {
			if !validPairingCode(code) {
				t.Fatalf("canonical code rejected: %q", code)
			}
			continue
		}
		if validPairingCode(code) {
			t.Fatalf("noncanonical code accepted: %q", code)
		}
	}
}

func TestPairingRejectsNoncanonicalSignedInputsBeforeSigning(t *testing.T) {
	validRequest, _, _ := validStartRequest(t)
	tests := map[string]func(*StartRequest){
		"padded public key": func(request *StartRequest) { request.PublicKey += "=" },
		"short public key":  func(request *StartRequest) { request.PublicKey = request.PublicKey[:42] },
		"leading display whitespace": func(request *StartRequest) {
			request.DisplayName = " device"
		},
		"display control": func(request *StartRequest) { request.DisplayName = "device\nname" },
		"invalid display UTF-8": func(request *StartRequest) {
			request.DisplayName = string([]byte{'d', 0xff})
		},
		"trailing connector version whitespace": func(request *StartRequest) {
			request.ConnectorVersion += " "
		},
		"codex version control": func(request *StartRequest) { request.CodexVersion += "\x7f" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest
			mutate(&request)
			var signatures atomic.Int32
			client := signedClient(func([]byte) string {
				signatures.Add(1)
				return "unexpected"
			}, func(*http.Request) (*http.Response, error) {
				t.Fatal("noncanonical signed input reached the network")
				return nil, nil
			})
			_, err := LoadOrPair(
				t.Context(), filepath.Join(t.TempDir(), "device-credentials.json"), client, request, nil,
			)
			if err == nil {
				t.Fatal("noncanonical signed input was accepted")
			}
			if signatures.Load() != 0 {
				t.Fatalf("noncanonical input was signed %d times", signatures.Load())
			}
		})
	}
}

func TestPairingPollURLMustMatchExpectedPairingPath(t *testing.T) {
	client := &Client{StartURL: "https://control.test/v1/device-pairings/start"}
	valid := []string{
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll",
		"/v1/device-pairings/" + testDeviceID + "/poll",
	}
	for _, raw := range valid {
		if _, err := client.validatePollURL(raw, testDeviceID); err != nil {
			t.Fatalf("valid poll URL %q rejected: %v", raw, err)
		}
	}

	for _, raw := range []string{
		"https://evil.test/v1/device-pairings/" + testDeviceID + "/poll",
		"https://control.test/v1/device-pairings/22222222-2222-4222-8222-222222222222/poll",
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll/extra",
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll?token=secret",
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll?",
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll#fragment",
		"https://control.test/v1/device-pairings/" + testDeviceID + "/poll#",
		"https://user@control.test/v1/device-pairings/" + testDeviceID + "/poll",
		"https://control.test/v1/device-pairings/" + testDeviceID + "%2fpoll",
	} {
		if _, err := client.validatePollURL(raw, testDeviceID); err == nil {
			t.Fatalf("invalid poll URL accepted: %q", raw)
		}
	}
}

func TestPairingStateLockRejectsConcurrentEntryWithoutNetwork(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	codePath := filepath.Join(stateDir, "pairing-code.json")
	request, signer, _ := validStartRequest(t)
	expiresAt := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var firstRequests atomic.Int32
	firstClient := signedClient(signer, func(httpRequest *http.Request) (*http.Response, error) {
		firstRequests.Add(1)
		if httpRequest.URL.Path == "/v1/device-pairings/start" {
			var payload startPayload
			if err := json.NewDecoder(httpRequest.Body).Decode(&payload); err != nil {
				return nil, err
			}
			return pairingStartedResponse(httpRequest, payload.PairingID, expiresAt), nil
		}
		close(firstEntered)
		<-releaseFirst
		return nil, errors.New("offline")
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := LoadOrPairWithCodeFile(
			t.Context(), credentialsPath, codePath, firstClient, request, nil,
		)
		firstDone <- err
	}()
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		close(releaseFirst)
		t.Fatal("first pairing attempt did not reach the network")
	}
	codeBefore := append([]byte(nil), mustRead(t, codePath)...)

	var secondRequests atomic.Int32
	var secondPreparations atomic.Int32
	secondClient := signedClient(signer, func(*http.Request) (*http.Response, error) {
		secondRequests.Add(1)
		return nil, errors.New("must not be called")
	})
	secondDone := make(chan error, 1)
	go func() {
		_, err := LoadOrPairWithCodeFilePrepared(
			t.Context(), credentialsPath, codePath, secondClient,
			func() (StartRequest, error) {
				secondPreparations.Add(1)
				return request, nil
			}, nil,
		)
		secondDone <- err
	}()

	var secondErr error
	timedOut := false
	select {
	case secondErr = <-secondDone:
	case <-time.After(2 * time.Second):
		timedOut = true
	}
	if !timedOut {
		if codeAfter := mustRead(t, codePath); !bytes.Equal(codeAfter, codeBefore) {
			t.Fatal("concurrent pairing altered the active pairing code file")
		}
	}
	close(releaseFirst)
	firstErr := <-firstDone
	if timedOut {
		secondErr = <-secondDone
		t.Fatal("concurrent pairing waited for the state lock instead of failing immediately")
	}
	if !errors.Is(secondErr, ErrPairingStateLocked) {
		t.Fatalf("concurrent pairing error = %v, want ErrPairingStateLocked", secondErr)
	}
	if secondRequests.Load() != 0 {
		t.Fatalf("concurrent pairing made %d network requests", secondRequests.Load())
	}
	if secondPreparations.Load() != 0 {
		t.Fatalf("concurrent pairing prepared identity %d times", secondPreparations.Load())
	}
	if firstRequests.Load() != 2 || firstErr == nil {
		t.Fatalf("first pairing requests = %d, error = %v", firstRequests.Load(), firstErr)
	}
	assertPrivateFile(t, filepath.Join(stateDir, "pairing.lock"))
	assertPairingCodeRemoved(t, codePath)
}

func TestPairingStateLockIsExclusiveAcrossProcesses(t *testing.T) {
	stateDir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestPairingStateLockHelper$")
	command.Env = append(os.Environ(), "SUB2API_PAIRING_LOCK_HELPER=1", "SUB2API_PAIRING_LOCK_DIR="+stateDir)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	locked := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != "locked\n" {
			readErr = errors.New("pairing lock helper returned an invalid readiness message")
		}
		locked <- readErr
	}()
	select {
	case err := <-locked:
		if err != nil {
			_ = stdin.Close()
			_ = command.Wait()
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("pairing lock helper did not acquire the lock")
	}

	if release, err := acquirePairingStateLock(stateDir); !errors.Is(err, ErrPairingStateLocked) {
		if release != nil {
			_ = release()
		}
		_ = stdin.Close()
		_ = command.Wait()
		t.Fatalf("cross-process lock error = %v, want ErrPairingStateLocked", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	release, err := acquirePairingStateLock(stateDir)
	if err != nil {
		t.Fatalf("reacquire pairing state lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestPairingStateLockHelper(t *testing.T) {
	if os.Getenv("SUB2API_PAIRING_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	release, err := acquirePairingStateLock(os.Getenv("SUB2API_PAIRING_LOCK_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		_ = release()
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestExistingCredentialsRemoveStaleTransientPairingState(t *testing.T) {
	stateDir := t.TempDir()
	credentialsPath := filepath.Join(stateDir, "device-credentials.json")
	codePath := filepath.Join(stateDir, "pairing-code.json")
	credentials := Credentials{Version: 1, DeviceID: testDeviceID, RefreshCredential: "dcr_refresh-only"}
	if err := SaveCredentials(credentialsPath, credentials); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "pending-pairing.json"),
		filepath.Join(stateDir, "pending-pairing.json.tmp"),
		codePath,
		codePath + ".tmp",
	} {
		if err := os.WriteFile(path, []byte("stale-one-time-secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadOrPairWithCodeFile(
		t.Context(), credentialsPath, codePath, nil, StartRequest{}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != credentials {
		t.Fatalf("credentials = %#v", got)
	}
	for _, path := range []string{filepath.Join(stateDir, "pending-pairing.json"), codePath} {
		for _, candidate := range []string{path, path + ".tmp"} {
			if _, statErr := os.Stat(candidate); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("stale state %q remains: %v", candidate, statErr)
			}
		}
	}
}

func validStartRequest(t *testing.T) (StartRequest, func([]byte) string, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return StartRequest{
			PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), DisplayName: "device",
			ConnectorVersion: "0.1.0", CodexVersion: "0.147.0", WorkspaceRoots: []string{"/work/project"},
		}, func(message []byte) string {
			return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
		}, publicKey
}

func signedClient(
	signer func([]byte) string,
	transport pairingRoundTripFunc,
) *Client {
	return &Client{
		HTTP:     &http.Client{Transport: transport},
		StartURL: "https://control.test/v1/device-pairings/start", PollInterval: time.Millisecond,
		Sign: signer,
	}
}

func decodeStartPayload(t *testing.T, request *http.Request) startPayload {
	t.Helper()
	var payload startPayload
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProtocolVersion != pairingProtocolVersion || payload.Audience != request.URL.String() {
		t.Fatalf("start payload has invalid version or audience: %#v", payload)
	}
	return payload
}

func assertStartProof(t *testing.T, payload startPayload, publicKey ed25519.PublicKey) {
	t.Helper()
	signature, err := base64.RawURLEncoding.DecodeString(payload.Signature)
	if err != nil || !ed25519.Verify(publicKey, pairingStartProof(payload), signature) {
		t.Fatal("pairing start proof did not verify")
	}
}

func assertSameStartIntent(t *testing.T, first, replay startPayload) {
	t.Helper()
	first.Signature = ""
	replay.Signature = ""
	firstJSON, _ := json.Marshal(first)
	replayJSON, _ := json.Marshal(replay)
	if string(firstJSON) != string(replayJSON) {
		t.Fatalf("start retry changed intent:\nfirst=%s\nreplay=%s", firstJSON, replayJSON)
	}
}

func pairingStartedResponse(request *http.Request, pairingID string, expiresAt time.Time) *http.Response {
	body, _ := json.Marshal(map[string]any{
		"pairing_id": pairingID,
		"expires_at": expiresAt,
		"poll_url":   "https://control.test/v1/device-pairings/" + pairingID + "/poll",
	})
	return testResponse(request, http.StatusCreated, body)
}

func readPendingPairing(t *testing.T, path string) pendingPairing {
	t.Helper()
	var pending pendingPairing
	if err := json.Unmarshal(mustRead(t, path), &pending); err != nil {
		t.Fatal(err)
	}
	return pending
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file %q mode = %v, want regular 0600", path, info.Mode())
	}
}

func assertPairingCodeRemoved(t *testing.T, path string) {
	t.Helper()
	for _, candidate := range []string{path, path + ".tmp"} {
		if _, err := os.Stat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pairing code state %q was not removed: %v", candidate, err)
		}
	}
}

type pairingRoundTripFunc func(*http.Request) (*http.Response, error)

func (f pairingRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testResponse(request *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(string(body))), Request: request,
	}
}

func TestPairingContextCancellationIsSanitized(t *testing.T) {
	credentialsPath := filepath.Join(t.TempDir(), "device-credentials.json")
	request, signer, _ := validStartRequest(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client := signedClient(signer, func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	})
	_, err := LoadOrPair(ctx, credentialsPath, client, request, nil)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("cancellation error = %v", err)
	}
}
