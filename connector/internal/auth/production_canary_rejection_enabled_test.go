//go:build productioncanary

package auth

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
)

func TestCanaryRejectionRequiresExactCredentialFailure(t *testing.T) {
	const endpoint = "https://control.test/codex-api/v1/device/connect-token"
	for _, test := range []struct {
		name, body, challenge, url string
		status                     int
		redirect, rejected         bool
	}{
		{"credential", `{"detail":"invalid_device_credential"}`, "Device", endpoint, 401, false, true},
		{"proof", `{"detail":"invalid_device_proof"}`, "Device", endpoint, 401, false, false},
		{"outage", `{"detail":"invalid_device_credential"}`, "Device", endpoint, 503, false, false},
		{"challenge", `{"detail":"invalid_device_credential"}`, "Bearer", endpoint, 401, false, false},
		{"duplicate", `{"detail":"invalid_device_proof","detail":"invalid_device_credential"}`, "Device", endpoint, 401, false, false},
		{"trailing", `{"detail":"invalid_device_credential"}{}`, "Device", endpoint, 401, false, false},
		{"large", `{"detail":"invalid_device_credential"}` + strings.Repeat(" ", 4096), "Device", endpoint, 401, false, false},
		{"redirect", `{"detail":"invalid_device_credential"}`, "Device", endpoint, 401, true, false},
		{"endpoint", `{"detail":"invalid_device_credential"}`, "Device", endpoint + "/other", 401, false, false},
		{"extra", `{"detail":"invalid_device_credential","other":true}`, "Device", endpoint, 401, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.redirect {
				request.Response = &http.Response{StatusCode: 302}
			}
			response := &http.Response{
				StatusCode: test.status, Request: request,
				Header: http.Header{"Www-Authenticate": []string{test.challenge}},
				Body:   io.NopCloser(strings.NewReader(test.body)),
			}
			err = productionCanaryRejection(response, endpoint)
			if errors.Is(err, ErrInvalidDeviceCredential) != test.rejected {
				t.Fatalf("credential classification differs: %v", err)
			}
		})
	}
}

func TestCanaryTokenRequestStopsBeforeFollowingRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusFound, Request: request,
			Header: http.Header{"Location": []string{"http://control.test/leak"}},
			Body:   io.NopCloser(strings.NewReader("")),
		}, nil
	})}
	source := &HTTPTokenSource{
		HTTP: client, URL: "https://control.test/codex-api/v1/device/connect-token",
		Credentials: pairing.Credentials{DeviceID: "11111111-1111-4111-8111-111111111111", RefreshCredential: "fixture-refresh"},
		Identity:    newTestIdentity(t),
	}
	_, err := source.Token(t.Context())
	if calls != 1 || err == nil || !strings.Contains(err.Error(), "HTTP status 302") {
		t.Fatalf("redirect was not stopped before another request: calls=%d err=%v", calls, err)
	}
	if client.CheckRedirect != nil {
		t.Fatal("instrumented policy mutated the caller's HTTP client")
	}
}
